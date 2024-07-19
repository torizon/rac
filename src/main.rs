// Copyright 2023 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::unwrap_used)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]

use std::sync::Arc;

use chrono::Utc;
use config::Config;
use eyre::Context;
use futures::stream::StreamExt;
use futures::Stream;
use log::*;
use rac::data_type::DeviceSession;
use rac::dbus::Event;
use rac::{data_type::RacConfig, dbus, device_keys};
use rac::{
    drop_privileges,
    torizon::{self, *},
};
use tokio_stream::wrappers::ReceiverStream;

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

    let mut dbus_events = start_dbus_channel();

    let ras_client = Arc::new(ras_client);

    poll_and_start_session(&ras_client, &rac_cfg, &mut dbus_events).await;

    let poll_timer = tokio::time::sleep(rac_cfg.device.poll_timeout);
    tokio::pin!(poll_timer);

    loop {
        debug!("waiting for new sessions for this device");

        tokio::select! {
            () = &mut poll_timer =>
                poll_and_start_session(&ras_client, &rac_cfg, &mut dbus_events).await,
            event = dbus_events.next() => {
                if let Some(Event::PollRasNow(_)) = event {
                    poll_and_start_session(&ras_client, &rac_cfg, &mut dbus_events).await;
                } else {
                    debug!("event received via dbus, no session active: {:?}", event);
                    continue; // do not reset timer
                }
            },
        }

        poll_timer
            .as_mut()
            .reset(tokio::time::Instant::now() + rac_cfg.device.poll_timeout);
    }
}

async fn poll_and_start_session<S>(
    ras_client: &TorizonClient,
    rac_cfg: &RacConfig,
    dbus_events: &mut S,
) where
    S: Stream<Item = Event> + Unpin,
{
    match poll_for_new_sessions(ras_client).await {
        Ok(Some(session)) => {
            if let Err(err) =
                rac::keep_session_loop(rac_cfg, ras_client, &session, dbus_events).await
            {
                error!("error in ssh session loop: {:?}", err);
            } else {
                info!("ssh session closed");
            }
        }
        Ok(None) => info!("no sessions available in RAS"),
        Err(err) => error!("could not get sessions, trying later {err:?}"),
    }
}

fn start_dbus_channel() -> impl Stream<Item = dbus::Event> {
    let rx = dbus::client::start();
    debug!("subscribed to dbus signals");
    ReceiverStream::new(rx)
}

async fn poll_for_new_sessions(
    ras_client: &TorizonClient,
) -> Result<Option<DeviceSession>, eyre::Report> {
    let session = ras_client
        .get_session()
        .await
        .wrap_err("Could not get session data from server")?;

    let session = match session {
        None => {
            debug!("No sessions available for this device");
            return Ok(None);
        }
        Some(s) => s,
    };

    debug!("{session:?}");
    info!("Received new session");

    if Utc::now() > session.ssh.expires_at {
        warn!("session expired at {}", session.ssh.expires_at);
    }

    Ok(Some(session))
}
