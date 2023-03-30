#![deny(clippy::unwrap_used)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]

use std::sync::Arc;
use std::time::Duration;

use config::Config;
use eyre::Context;
use log::*;
use rac::{data_type::RacConfig, device_keys};
use rac::{drop_privileges, ras_client::*};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "rac=info");
    }

    if env!("VERGEN_CARGO_PROFILE") == "release" {
        env_logger::builder().format_target(false).init();
    } else {
        env_logger::init();
    }

    color_eyre::install().expect("could no initialize color_eyre");

    let file = if let Ok(f) = std::env::var("CONFIG_FILE") {
        f
    } else {
        "client.toml".to_owned()
    };

    info!("Config file set to {}", file);

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

    let device_pubkey = device_keys::read_or_create_pubkey(&rac_cfg.device.ssh_private_key_path)
        .await
        .expect("could not read/generate device ssh pubkey");

    debug!("Device public key is {:?}", device_pubkey.to_openssh());

    ras_client
        .add_device_pubkey(&device_pubkey)
        .await
        .expect("could not add this device's public keys to RAS");

    let ras_client = Arc::new(ras_client);

    drop_privileges(&rac_cfg).expect("Could not drop privileges");

    loop {
        debug!("checking for new sessions for this device");

        tokio::select! {
            r = check_new_sessions(&ras_client, &rac_cfg) => {
                if let Err(err) = r {
                    debug!("{err:#?}");
                    error!("could not get sessions: {err}. Trying later");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                } else {
                    tokio::time::sleep(rac_cfg.device.poll_timeout).await;
                }
            }
        }
    }
}

async fn check_new_sessions(
    ras_client: &RasClient,
    rac_config: &RacConfig,
) -> Result<(), eyre::Report> {
    let session = ras_client
        .get_session()
        .await
        .wrap_err("Could not get session data from server")?;

    if session.is_none() {
        debug!("No sessions available for this device");
        return Ok(());
    }

    #[allow(clippy::unwrap_used)]
    let session = session.unwrap();

    debug!("{session:?}");
    info!("Received new session");

    rac::keep_session_loop(rac_config, ras_client, &session)
        .await
        .wrap_err("Error in ssh session loop")?;

    info!("ssh session closed");

    Ok(())
}
