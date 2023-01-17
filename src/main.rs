mod ras_client;
mod data_type;
mod ssh;

use tokio::select;

use std::time::Duration;

use crate::ras_client::*;
use crate::data_type::*;
use crate::data_type::RacConfig;
use config::Config;

async fn keep_session_loop(config: &RacConfig, client: &RasClient, device: String, session: &SshSession) -> Result<(), anyhow::Error> {
    let current_keys = &session.authorized_pubkeys;

    let mut handle = ssh::start_ssh(&config, &device, session).await?;

    loop {
        select! {
            h = &mut handle => {
                if let Err(err) = h {
                    log::error!("Error with ssh session: {:?}", err);
                }
                log::info!("ssh session ended");
                break;
            },
            _ = tokio::time::sleep(Duration::from_secs(3)) => {
                let session = client.get_session().await?;

                if let Some((s, _)) = session {
                    let new_keys = s.authorized_pubkeys;

                    // TODO: Also check anything else in sessions changed, is it still signed properly?
                    if RasClient::keys_changed(current_keys, &new_keys) {
                        log::warn!("keys changed, disconnecting client");

                        handle.disconnect(russh::Disconnect::ByApplication, "disconnect by client", "en").await?;
                        break;
                    } else {
                        log::debug!("Session still valid");
                    }

                } else {
                    log::info!("session was cancelled by server");
                    handle.disconnect(russh::Disconnect::ByApplication, "disconnect by client", "en").await?;
                    break;
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "rac=info");
    }

    env_logger::init();

    let file = if let Ok(f) = std::env::var("CONFIG_FILE") {
        f
    } else {
        "client.toml".to_owned()
    };

    log::debug!("Config file set to {}", file);

    let config: Config = Config::builder()
        .add_source(config::File::with_name(&file))
        .add_source(config::Environment::with_prefix("RAC").prefix_separator("__").separator("__"))
        .build()
        .expect("Could not load config");

    let rac_cfg: RacConfig = config.try_deserialize().expect("could not deserialize config");

    if let Ok(c) = std::env::var("DEBUG_CONFIG") {
        if c == "true" {
            log::debug!("Config: {:?}", rac_cfg);
        }
    }

    let ras_client = &RasClient::new(rac_cfg.clone()).expect("could not create RasClient");

    ras_client.update_authorized_keys(&vec![]).expect("could not reset authorized keys");

    ras_client.add_device_pubkey().await.expect("could not add this device's public keys to RAS");

    loop {
        log::debug!("checking for new sessions for this device");

        let session = ras_client.get_session().await;

        if let Err(e) = session {
            log::error!("Could not get session data from server: {}. Trying later", e);
            tokio::time::sleep(Duration::from_secs(3)).await;
            continue;
        }

        if let Some((s, device)) = session.unwrap() {
            log::info!("Received new session for {}", device);

            if let Err(e) = ras_client.update_authorized_keys(&s.authorized_pubkeys) {
                log::error!("Could not update authorized_keys on local system: {}", e);
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }

            match keep_session_loop(&rac_cfg, ras_client, device, &s).await {
                Ok(_) => log::info!("ssh session closed"),
                Err(err) => {
                    log::error!("Error in ssh session loop: {:?}", err);
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    continue;
                },
            }
        } else {
            log::debug!("No sessions available for this device");
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }
}
