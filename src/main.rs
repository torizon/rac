// Copyright 2023 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::unwrap_used)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
#![allow(clippy::module_name_repetitions)]
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]

use std::path::Path;

use config::Config;
use log::*;
use rac::dbus::Event;
use rac::event_loop::*;
use rac::{data_type::RacConfig, device_keys};
use rac::{
    drop_privileges,
    torizon::{self, *},
};
use tokio::sync::broadcast::{self};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    #[allow(clippy::print_stdout)]
    if args.get(1).unwrap_or(&String::new()) == "--version" {
        println!("{}", torizon::user_agent());
        return;
    }

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "rac=info");
    }

    if env!("VERGEN_CARGO_PROFILE") == "release" {
        env_logger::builder().format_target(false).init();
    } else {
        env_logger::init();
    }

    color_eyre::install().expect("could no initialize color_eyre");

    info!("{} started", torizon::user_agent());

    let file = if let Ok(f) = std::env::var("CONFIG_FILE") {
        f
    } else if Path::new("/etc/rac/client.toml").exists() {
        "/etc/rac/client.toml".to_owned()
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

    let http_client = torizon::tls_http_client(&rac_cfg).expect("could not start http client");

    let ras_client = TorizonClient::new(rac_cfg.clone(), http_client.clone());

    drop_privileges(&rac_cfg).expect("Could not drop privileges");

    let device_pubkey = device_keys::read_or_create_pubkey(&rac_cfg.device.ssh_private_key_path)
        .await
        .expect("could not read/generate device ssh pubkey");

    ras_client
        .add_device_pubkey(&device_pubkey)
        .await
        .expect("could not add this device's public keys to RAS");

    debug!("Device public key is {:?}", device_pubkey.to_openssh());

    if let Err(err) = tokio::fs::create_dir_all(&rac_cfg.device.local_tuf_repo_path).await {
        warn!(
            "could not create {:?}: {:?}",
            &rac_cfg.device.local_tuf_repo_path, err
        );
    }

    let (tx, rx) = broadcast::channel::<Event>(8);

    let dbus_loop_handle = tokio::spawn(start_dbus_loop(rac_cfg.clone(), tx));

    let ssh_loop_handle = tokio::spawn(start_ssh_event_loop(
        rx.resubscribe(),
        rac_cfg.clone(),
        ras_client.clone(),
    ));

    let remote_commands_handle =
        tokio::spawn(start_remote_commands_event_loop(ras_client, rac_cfg, rx));

    tokio::select! {
        cause = dbus_loop_handle =>
            error!("dbus loop quit unexpectedly: {:?}", cause),
        cause = ssh_loop_handle =>
            error!("ssh loop quit unexpectedly: {:?}", cause),
        cause = remote_commands_handle =>
            error!("remote commands loop quit unexpectedly: {:?}", cause),
    }
}
