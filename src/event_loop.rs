#![allow(clippy::module_name_repetitions)]

use crate::command::CommandPolling;
use crate::Event;
use crate::{data_type::RacConfig, dbus};
use futures::stream::StreamExt;
use futures::FutureExt;
use futures::{future, Stream};
use log::*;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio_stream::wrappers::ReceiverStream;

use crate::TorizonClient;

use crate::ssh::SshPolling;

pub async fn start_poll_loop(
    ras_client: TorizonClient,
    rac_cfg: RacConfig,
    mut events_ch: Receiver<Event>,
) {
    let mut ssh_polling = SshPolling::new(ras_client.clone(), rac_cfg.clone());

    let mut command_polling = if rac_cfg.device.enable_remote_commands {
        Some(CommandPolling::new(
            ras_client.clone(),
            rac_cfg.clone(),
            ras_client,
        ))
    } else {
        info!("remote commands disabled");
        None
    };

    let mut poll_interval = tokio::time::interval(rac_cfg.device.poll_timeout);

    poll_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = poll_interval.tick() => {
                ssh_polling.poll().await;

                if let Some(cmd_poll) = &mut command_polling {
                    cmd_poll.poll().await;
                }
            },

            event = events_ch.recv() => {
                match event {
                    Ok(ev @ Event::DbusPollRasNow(_)) => {
                        if let Err(err) = ssh_polling.forward(ev).await {
                            warn!("could not forward event to ssh loop: {err:?}");
                        }

                        ssh_polling.poll().await;

                        if let Some(cmd_poll) = &mut command_polling {
                            cmd_poll.poll().await;
                        }
                    },
                    Err(RecvError::Lagged(_)) => {
                        debug!("start_poll_loop lagged");
                    }
                    Err(err) => {
                        error!(
                            "could not process event: {err:?}"
                        );
                    }
                }
            },
        }
    }
}

fn start_dbus_channel(rac_cfg: &RacConfig) -> Box<dyn Stream<Item = Event> + Send + Unpin> {
    if rac_cfg.device.enable_dbus_server {
        let rx = dbus::server::start();
        info!("subscribed to dbus signals");
        Box::new(ReceiverStream::new(rx))
    } else {
        info!("dbus client disabled");
        Box::new(future::pending().into_stream())
    }
}

pub async fn start_dbus_loop(rac_cfg: RacConfig, cmd_tx: Sender<Event>) {
    loop {
        let mut dbus_events = start_dbus_channel(&rac_cfg);

        loop {
            debug!("waiting for new sessions for this device");

            if let Some(event) = dbus_events.next().await {
                if let Err(err) = cmd_tx.send(event) {
                    warn!("could not broadcast dbus event: {err:?}");
                }
            } else {
                warn!("dbus stream closed");
                break;
            }
        }

        info!(
            "waiting for {:?} before retrying to reconnect to dbus",
            rac_cfg.device.poll_timeout
        );
        tokio::time::sleep(rac_cfg.device.poll_timeout).await;
    }
}
