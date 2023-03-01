#![deny(clippy::unwrap_used)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]

use std::time::Duration;

use config::Config;
use log::*;
use rac::authorized_keys;
use rac::ras_client::*;
use rac::{data_type::RacConfig, device_keys};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "rac=info");
    }

    env_logger::init();
    #[allow(clippy::unwrap_used)]
    color_eyre::install().unwrap();

    let file = if let Ok(f) = std::env::var("CONFIG_FILE") {
        f
    } else {
        "client.toml".to_owned()
    };

    debug!("Config file set to {}", file);

    let config = Config::builder()
        .add_source(config::File::with_name(&file))
        .add_source(
            config::Environment::with_prefix("RAC")
                .prefix_separator("__")
                .separator("__"),
        )
        .build()
        .expect("Could not load config");

    let rac_cfg: RacConfig = config
        .try_deserialize()
        .expect("could not deserialize config");

    if let Ok(debug_config) = std::env::var("DEBUG_CONFIG") {
        if debug_config == "true" {
            debug!("Config: {:#?}", rac_cfg);
        }
    }

    let ras_client = RasClient::with_tls(rac_cfg.clone()).expect("could not create RasClient");

    authorized_keys::update_keys(&rac_cfg.device.authorized_keys_path, &vec![])
        .await
        .expect("could not reset authorized keys");

    let device_pubkey = device_keys::read_or_create(&rac_cfg.device.ssh_private_key_path)
        .await
        .expect("could not read/generate device ssh pubkey");

    debug!("Device public key is {:?}", device_pubkey.to_openssh());

    ras_client
        .add_device_pubkey(&device_pubkey)
        .await
        .expect("could not add this device's public keys to RAS");

    loop {
        debug!("checking for new sessions for this device");

        let session = ras_client.get_session().await;

        if let Err(e) = session {
            error!("Could not get session data from server: {e}. Trying later");
            tokio::time::sleep(Duration::from_secs(3)).await;
            continue;
        }

        #[allow(clippy::unwrap_used)]
        if let Some(device_session) = session.unwrap() {
            debug!("{device_session:?}");
            info!("Received new session");
            let ssh_session = &device_session.ssh;

            if let Err(e) = authorized_keys::update_keys(
                &rac_cfg.device.authorized_keys_path,
                &ssh_session.authorized_pubkeys,
            )
            .await
            {
                error!("Could not update authorized_keys on local system: {}", e);
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }

            match rac::keep_session_loop(&rac_cfg, &ras_client, &device_session).await {
                Ok(_) => info!("ssh session closed"),
                Err(err) => {
                    error!("Error in ssh session loop: {:?}", err);
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    continue;
                }
            }
        } else {
            debug!("No sessions available for this device");
            tokio::time::sleep(rac_cfg.device.poll_timeout).await;
        }
    }
}
