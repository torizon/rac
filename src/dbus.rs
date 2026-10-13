use serde;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "command", content = "args")]
pub enum Event {
    PollRasNow(serde_json::Value),
}

pub mod server {
    use log::*;
    use std::time::Duration;
    use tokio::sync::mpsc::{self, Sender};
    use zbus::conn::Builder;

    use super::Event;

    struct TznRac {
        ch: Sender<Event>,
    }

    #[zbus::interface(name = "io.torizon.Rac1")]
    impl TznRac {
        async fn poll_ras_now(&self, args_json: &str) -> zbus::fdo::Result<()> {
            let json_args: serde_json::Value = serde_json::from_str(args_json).map_err(|err| {
                zbus::fdo::Error::InvalidArgs(format!("invalid args json: {}", err))
            })?;

            debug!("received poll_ras_now in dbus. args={:?}", json_args);

            let event = Event::PollRasNow(json_args);

            if let Err(err) = self.ch.try_send(event) {
                warn!("could not send msg to main event loop: {:?}", err);
            }

            Ok(())
        }
    }

    async fn dbus_start_server(ch: Sender<Event>) -> crate::Result<()> {
        // two step dbus init required because zbus 4 has a bug: if
        // requesting the name fails inside Builder::build() (e.g.
        // AccessDenied by the bus policy), the connection is leaked and
        // retrying eventually exhausts max_connections_per_user. Fixed
        // in zbus 5, but 5 requires a rustc upgrade, which we cannot do
        // because the yocto build pins rustc 1.75.
        //
        // The name is still requested only after build() returns, so the
        // interface is registered and the object server is listening
        // before any client can reach us through the well-known name.

        let conn = Builder::system()?
            .serve_at("/io/torizon/Rac1", TznRac { ch })?
            .build()
            .await?;

        conn.request_name("io.torizon.Rac1").await?;

        Ok(std::future::pending::<()>().await)
    }

    #[must_use]
    pub fn start() -> tokio::sync::mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(10);

        tokio::task::spawn(async move {
            loop {
                match dbus_start_server(tx.clone()).await {
                    Ok(_) => {
                        error!("dbus server finished unexpectedly");
                    }
                    Err(err) => warn!("could not connect to dbus: {:?}", err),
                }

                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        rx
    }
}
