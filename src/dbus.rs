use serde;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "command", content = "args")]
pub enum Event {
    PollRasNow(serde_json::Value),
}

pub mod client {
    use futures::stream::StreamExt;
    use log::*;
    use serde_json::json;
    use std::{fmt::Debug, time::Duration};
    use tokio::sync::mpsc::{self, Sender};
    use zbus::{proxy, Connection};

    use super::Event;

    #[proxy(
        interface = "io.torizon.TznService1",
        default_service = "io.torizon.TznService",
        default_path = "/io/torizon/TznService"
    )]
    trait TznService {
        #[zbus(signal)]
        async fn tzn_message_sig(command: &str, arg_json: &str) -> zbus::Result<()>;
    }

    fn handle_event(msg: &TznMessageSig, ch: &Sender<Event>) -> crate::Result<()> {
        let args: TznMessageSigArgs = msg.args()?;
        let json_args: serde_json::Value = serde_json::from_str(args.arg_json)?;

        debug!(
            "received signal in dbus. command={} args={:?}",
            args.command, json_args
        );

        let full_json = json!({
            "command": args.command,
            "args": json_args,
        });

        let event: Event = serde_json::from_value(full_json)?;

        ch.try_send(event)
            .map_err(|err| eyre::eyre!("could not send msg: {:?}", err))?;

        Ok(())
    }

    async fn dbus_connect() -> crate::Result<TznMessageSigStream<'static>> {
        let connection = Connection::session().await?;

        let dbus_proxy = TznServiceProxy::new(&connection).await?;

        let events = dbus_proxy.receive_tzn_message_sig().await?;

        Ok(events)
    }

    #[must_use]
    pub fn start() -> tokio::sync::mpsc::Receiver<Event> {
        let (tx, rx) = mpsc::channel(10);

        tokio::task::spawn(async move {
            loop {
                match dbus_connect().await {
                    Ok(mut events) => {
                        while let Some(msg) = events.next().await {
                            if let Err(err) = handle_event(&msg, &tx) {
                                info!("could not handle {:?}: {:?}", msg, err);
                            }
                        }

                        error!("event stream/dbus finished unexpectedly");
                    }
                    Err(err) => warn!("could not connect to dbus: {:?}", err),
                }

                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });

        rx
    }
}
