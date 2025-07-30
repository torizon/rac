#![allow(clippy::module_name_repetitions)]

use crate::data_type::{Command, DeviceSession};
use crate::dbus::Event;
use crate::{command::*, CommandResult, UptaneMetadataProvider, ValidCommand};
use crate::{data_type::RacConfig, dbus};
use chrono::Utc;
use eyre::Context;
use futures::stream::StreamExt;
use futures::FutureExt;
use futures::{future, Stream};
use log::*;
use serde_json::json;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio_stream::wrappers::ReceiverStream;

use crate::TorizonClient;

async fn start_poll_loop<T>(rac_cfg: RacConfig, mut dbus_events: Receiver<Event>, mut ras: T)
where
    T: RasPoll,
{
    // Needs to poll before timer fires
    ras.poll(&rac_cfg, &mut dbus_events).await;

    let poll_timer = tokio::time::sleep(rac_cfg.device.poll_timeout);
    tokio::pin!(poll_timer);

    loop {
        debug!("{}: waiting for poll events", std::any::type_name::<T>());

        tokio::select! {
            () = &mut poll_timer =>
                ras.poll(&rac_cfg, &mut dbus_events).await,
            event = dbus_events.recv() => {
                match event {
                    Ok(Event::PollRasNow(_)) =>
                        ras.poll(&rac_cfg, &mut dbus_events).await,
                    Err(err) =>
                        warn!("{}: could not poll and execute: {err:?}", std::any::type_name::<T>()),
                }
            },
        }

        poll_timer
            .as_mut()
            .reset(tokio::time::Instant::now() + rac_cfg.device.poll_timeout);
    }
}

trait RasPoll: std::fmt::Debug {
    async fn poll(&mut self, rac_cfg: &RacConfig, dbus_events: &mut Receiver<dbus::Event>);
}

#[derive(Debug)]
struct CommandPolling<V: UptaneMetadataProvider = TorizonClient> {
    ras_client: TorizonClient,
    metadata_provider: V,
    cmd_store: CommandStore,
}

impl<V: UptaneMetadataProvider> CommandPolling<V> {
    async fn poll_for_new_commands(
        ras_client: &TorizonClient,
        metadata_provider: &V,
    ) -> Result<Option<Command>, eyre::Report> {
        let mut commands = ras_client
            .get_commands()
            .await
            .wrap_err("Could not get session data from server")?
            .values;

        debug!("commands received: {commands:?}");

        let min_key = commands.keys().min().copied();

        // Only return the lowest priority command
        let cmd_opt = min_key.and_then(|k| commands.remove(&k));

        // validate RAS command against uptane metadata
        if let Some(cmd) = cmd_opt {
            let cmd_valid = crate::valid_command_metadata(metadata_provider, &cmd).await?;
            #[allow(clippy::if_not_else)]
            if cmd_valid != ValidCommand::Valid {
                debug!("command from server is invalid: {:#?}", &cmd);
                error!("invalid command received from server: {:#?}", &cmd_valid);

                let error = json!({
                    "message": "invalid command received from server",
                    "validation_result": &cmd_valid
                });

                let result = CommandResult {
                    success: false,
                    stdout: String::new(),
                    stderr: String::new(),
                    error: Some(error),
                    exit_code: None,
                    finished_at: chrono::Utc::now(),
                };

                ras_client.send_command_result(&cmd.id, &result).await?;

                Ok(None)
            } else {
                Ok(Some(cmd))
            }
        } else {
            Ok(None)
        }
    }
}

impl<V: UptaneMetadataProvider> RasPoll for CommandPolling<V> {
    async fn poll(&mut self, rac_cfg: &RacConfig, _dbus: &mut Receiver<Event>) {
        async fn execute<V: UptaneMetadataProvider>(
            ras_client: &TorizonClient,
            rac_cfg: &RacConfig,
            metadata_provider: &V,
            cmd_store: &mut CommandStore,
        ) -> Result<(), eyre::Report> {
            for (cmd_id, res) in cmd_store.find_pending().await? {
                cmd_store.start(&cmd_id).await?;

                if let Err(err) = ras_client.send_command_result(&cmd_id, &res).await {
                    warn!("could not send pending command result: {err:?}");
                    cmd_store.result_pending(&cmd_id, res, err).await?;
                } else {
                    debug!("finished pending cmd {}", &cmd_id);
                    cmd_store.result_sent(&cmd_id).await?;
                }
            }

            if let Some(cmd) =
                CommandPolling::<V>::poll_for_new_commands(ras_client, metadata_provider).await?
            {
                info!("running command {:?}", &cmd);

                if cmd_store.is_pending(&cmd.id).await? {
                    warn!(
                        "command {:?} returned from server still pending, not executing again",
                        &cmd.id
                    );
                    return Ok(());
                }

                cmd_store.start(&cmd.id).await?;

                match crate::run_command(rac_cfg, &cmd).await {
                    Ok(result) => {
                        if let Err(err) = ras_client.send_command_result(&cmd.id, &result).await {
                            warn!("could not send command result: {err:?}");
                            cmd_store.result_pending(&cmd.id, result, err).await?;
                        } else {
                            debug!("command result sent");

                            cmd_store.result_sent(&cmd.id).await?;
                        }

                        info!("command finished");
                    }
                    Err(err) => {
                        cmd_store.result_sent(&cmd.id).await?;
                        error!("could not run command: {err:?}");
                    }
                }
            } else {
                info!("no new commands in RAS");
            };

            Ok(())
        }
        if let Err(err) = execute::<V>(
            &self.ras_client,
            rac_cfg,
            &self.metadata_provider,
            &mut self.cmd_store,
        )
        .await
        {
            error!("error, trying later {err:?}");
        }
    }
}

#[derive(Debug)]
struct SshPolling {
    ras_client: TorizonClient,
    rac_cfg: RacConfig,
}

impl SshPolling {
    async fn poll_for_new_sessions(&self) -> Result<Option<DeviceSession>, eyre::Report> {
        let session = self
            .ras_client
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
}

impl RasPoll for SshPolling {
    async fn poll(&mut self, _rac_cfg: &RacConfig, dbus_events: &mut Receiver<Event>) {
        match self.poll_for_new_sessions().await {
            Ok(Some(session)) => {
                if let Err(err) =
                    crate::keep_session_loop(&self.rac_cfg, &self.ras_client, &session, dbus_events)
                        .await
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
}

pub async fn start_remote_commands_event_loop(
    ras_client: TorizonClient,
    rac_cfg: RacConfig,
    dbus_events: Receiver<Event>,
) {
    let persist = CommandStore::new(rac_cfg.device.commands_dir.clone());

    let poll = CommandPolling {
        ras_client: ras_client.clone(),
        cmd_store: persist,
        metadata_provider: ras_client,
    };

    start_poll_loop(rac_cfg, dbus_events, poll).await;
}

pub async fn start_ssh_event_loop(
    dbus_events: Receiver<Event>,
    rac_cfg: RacConfig,
    ras_client: TorizonClient,
) {
    let poll = SshPolling {
        ras_client,
        rac_cfg: rac_cfg.clone(),
    };

    start_poll_loop(rac_cfg, dbus_events, poll).await;
}

fn start_dbus_channel(rac_cfg: &RacConfig) -> Box<dyn Stream<Item = dbus::Event> + Send + Unpin> {
    if rac_cfg.device.enable_dbus_client {
        let rx = dbus::client::start();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_type::{CommandId, CommandResult, CommandsResponse};
    use serde_json::json;
    use std::collections::HashMap;
    use tempfile::tempdir;
    use tough::schema::RemoteSessions;
    use url::Url;
    use wiremock::{
        matchers::{body_json_schema, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    struct TestContext {
        polling: CommandPolling<MockUptaneProvider>,
        mock_server: MockServer,
        dbus_events: Receiver<Event>,
        rac_cfg: RacConfig,
    }

    pub struct CommandResultMatcher(CommandResult);

    impl wiremock::Match for CommandResultMatcher {
        fn matches(&self, request: &wiremock::Request) -> bool {
            let mut req_body: CommandResult = match request.body_json() {
                Ok(b) => b,
                Err(err) => {
                    debug!("command result body did not match: {err:?}");
                    return false;
                }
            };

            // Set the finished_at time to match the expected result for comparison
            req_body.finished_at = self.0.finished_at;

            // compare only the error message
            let error = req_body.error.and_then(|error_json| {
                error_json
                    .get("message")
                    .and_then(|msg| msg.as_str().map(str::to_owned))
            });

            let expected_error = self.0.error.as_ref().and_then(|error_json| {
                error_json
                    .get("message")
                    .and_then(|msg| msg.as_str().map(str::to_owned))
            });

            if error != expected_error {
                return false;
            }

            req_body.error = self.0.error.clone();

            req_body == self.0
        }
    }

    #[derive(Debug)]
    struct MockUptaneProvider;

    impl UptaneMetadataProvider for MockUptaneProvider {
        async fn fetch_verified_remote_sessions(&self) -> crate::Result<RemoteSessions> {
            Ok(RemoteSessions {
                remote_sessions: json!({}),
                remote_commands: Some(json!({
                    "allowed_commands": {
                        "restart-service": {
                            "args": [
                                "aktualizr"
                            ]
                        },
                        "echo": {
                            "args": ["test"]
                        }
                    },
                    "version": "v1alpha"
                })),
                expires: chrono::Utc::now() + std::time::Duration::from_secs(3600),
                #[allow(clippy::unwrap_used)]
                version: std::num::NonZeroU64::new(1).unwrap(),
                _extra: HashMap::new(),
            })
        }
    }

    impl TestContext {
        async fn new() -> Self {
            let temp_dir = tempdir().expect("Failed to create temp directory");
            let temp_path = temp_dir.path().to_path_buf();
            let cmd_store = CommandStore::new(temp_path);

            let mock_server = MockServer::start().await;
            let base_url = Url::parse(&mock_server.uri()).expect("Failed to parse URL");

            let rac_config = RacConfig {
                torizon: crate::data_type::TorizonConfig {
                    url: base_url.clone(),
                    director_url: Some(base_url),
                    ..Default::default()
                },
                ..Default::default()
            };

            let http_client = reqwest::Client::builder()
                .build()
                .expect("Failed to build HTTP client");
            let ras_client = TorizonClient::new(rac_config.clone(), http_client);

            // 10 = max number of dbus messages in a single burst this
            // client can handle
            let (_tx, dbus_events) = tokio::sync::broadcast::channel(10);

            Self {
                polling: CommandPolling::<MockUptaneProvider> {
                    ras_client,
                    cmd_store,
                    metadata_provider: MockUptaneProvider {},
                },
                mock_server,
                dbus_events,
                rac_cfg: rac_config,
            }
        }

        fn create_command(&self) -> (CommandId, Command) {
            let cmd_id = CommandId::generate();
            let command = Command {
                id: cmd_id,
                name: crate::data_type::CommandName::Echo(EchoAction),
                args: vec!["test".to_string()],
                created_at: chrono::Utc::now(),
            };
            (cmd_id, command)
        }

        async fn mock_get_commands(&self, commands: HashMap<u32, Command>) {
            let response = CommandsResponse { values: commands };

            Mock::given(method("GET"))
                .and(path("/commands"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .expect(1)
                .mount(&self.mock_server)
                .await;
        }

        async fn mock_post_command_result(
            &self,
            cmd_id: &CommandId,
            status: u16,
            result: Option<CommandResult>,
        ) {
            let path_str = format!("/commands/{cmd_id}/result");

            let mut mock = Mock::given(method("POST"))
                .and(path(path_str))
                .and(body_json_schema::<CommandResult>);

            let name =
                format!("command result status={status} cmd_id={cmd_id:?} result={result:?}");

            if let Some(res) = result {
                mock = mock.and(CommandResultMatcher(res));
            }

            mock.respond_with(ResponseTemplate::new(status).set_body_json(json!({})))
                .expect(1)
                .named(name)
                .mount(&self.mock_server)
                .await;
        }

        async fn mock_reset(&self) {
            self.mock_server.verify().await;
            self.mock_server.reset().await;
        }

        async fn create_pending_result(&mut self, cmd_id: &CommandId) -> CommandResult {
            let result = CommandResult {
                success: true,
                stdout: "test output".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
                error: None,
                finished_at: chrono::Utc::now(),
            };

            self.polling
                .cmd_store
                .start(cmd_id)
                .await
                .expect("Failed to start command");

            self.polling
                .cmd_store
                .result_pending(cmd_id, result.clone(), eyre::eyre!("Pending test error"))
                .await
                .expect("Failed to set pending result");

            result
        }
    }

    #[tokio::test]
    async fn test_poll_and_run_command_success() {
        let mut ctx = TestContext::new().await;
        let (cmd_id, command) = ctx.create_command();

        let expect = CommandResult {
            success: true,
            stdout: command.args.join(""),
            stderr: String::new(),
            exit_code: Some(0),
            error: None,
            finished_at: chrono::Utc::now(),
        };

        ctx.mock_get_commands(HashMap::from([(0, command)])).await;

        ctx.mock_post_command_result(&cmd_id, 200, Some(expect))
            .await;

        ctx.polling.poll(&ctx.rac_cfg, &mut ctx.dbus_events).await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .find_pending()
            .await
            .expect("Failed to find pending commands");
        assert!(pending_commands.is_empty(), "Expected no pending commands");
    }

    #[tokio::test]
    async fn test_poll_and_run_command_invalid_uptane_metadata() {
        let mut ctx = TestContext::new().await;

        let cmd_id = CommandId::generate();
        let command = Command {
            id: cmd_id,
            name: crate::data_type::CommandName::Reboot(RebootAction),
            args: Vec::new(),
            created_at: chrono::Utc::now(),
        };

        let expect = CommandResult {
            success: false,
            stdout: String::new(),
            stderr: String::new(),
            error: Some(json!({"message": "invalid command received from server"})), // rest of body will not be matched
            exit_code: None,
            finished_at: chrono::Utc::now(),
        };

        ctx.mock_get_commands(HashMap::from([(0, command)])).await;

        ctx.mock_post_command_result(&cmd_id, 200, Some(expect))
            .await;

        ctx.polling.poll(&ctx.rac_cfg, &mut ctx.dbus_events).await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .find_pending()
            .await
            .expect("Failed to find pending commands");
        assert!(pending_commands.is_empty(), "Expected no pending commands");
    }

    #[tokio::test]
    async fn test_poll_and_run_command_no_commands() {
        let mut ctx = TestContext::new().await;

        ctx.mock_get_commands(HashMap::new()).await;

        ctx.polling.poll(&ctx.rac_cfg, &mut ctx.dbus_events).await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .find_pending()
            .await
            .expect("Failed to find pending commands");
        assert!(pending_commands.is_empty(), "Expected no pending commands");
    }

    #[tokio::test]
    async fn test_poll_and_run_command_send_pending_results() {
        let mut ctx = TestContext::new().await;
        let (cmd_id, _) = ctx.create_command();

        let result = ctx.create_pending_result(&cmd_id).await;

        ctx.mock_get_commands(HashMap::new()).await;

        ctx.mock_post_command_result(&cmd_id, 200, Some(result))
            .await;

        ctx.polling.poll(&ctx.rac_cfg, &mut ctx.dbus_events).await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .find_pending()
            .await
            .expect("Failed to find pending commands");

        assert!(pending_commands.is_empty(), "Expected no pending commands");
    }

    #[tokio::test]
    async fn test_poll_and_run_command_failed_to_send_result() {
        let mut ctx = TestContext::new().await;
        let (cmd_id, command) = ctx.create_command();

        ctx.mock_get_commands(HashMap::from([(0, command)])).await;

        ctx.mock_post_command_result(&cmd_id, 500, None).await;

        ctx.polling.poll(&ctx.rac_cfg, &mut ctx.dbus_events).await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .find_pending()
            .await
            .expect("Failed to find pending commands");
        assert_eq!(pending_commands.len(), 1, "Expected one pending command");
        assert_eq!(
            pending_commands[0].0, cmd_id,
            "Expected pending command to match created command"
        );
    }

    #[tokio::test]
    async fn test_poll_and_run_command_retry_after_server_down() {
        let mut ctx = TestContext::new().await;
        let (cmd_id, command) = ctx.create_command();

        ctx.mock_get_commands(HashMap::from([(0, command)])).await;

        ctx.mock_post_command_result(&cmd_id, 500, None).await;

        ctx.polling.poll(&ctx.rac_cfg, &mut ctx.dbus_events).await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .find_pending()
            .await
            .expect("Failed to find pending commands");
        assert_eq!(pending_commands.len(), 1, "Expected one pending command");
        assert_eq!(
            pending_commands[0].0, cmd_id,
            "Expected pending command to match created command"
        );

        ctx.mock_reset().await;

        ctx.mock_get_commands(HashMap::new()).await;

        let result = pending_commands[0].1.clone();
        ctx.mock_post_command_result(&cmd_id, 200, Some(result.clone()))
            .await;

        // Second poll - should retry sending the pending result
        ctx.polling.poll(&ctx.rac_cfg, &mut ctx.dbus_events).await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .find_pending()
            .await
            .expect("Failed to find pending commands");
        assert!(
            pending_commands.is_empty(),
            "Expected no pending commands after successful retry"
        );
    }

    #[tokio::test]
    async fn test_poll_and_run_command_not_executed_when_pending_result_exists() {
        let mut ctx = TestContext::new().await;
        let (cmd_id, command) = ctx.create_command();

        ctx.mock_get_commands(HashMap::from([(0, command.clone())]))
            .await;
        ctx.mock_post_command_result(&cmd_id, 500, None).await;
        ctx.polling.poll(&ctx.rac_cfg, &mut ctx.dbus_events).await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .find_pending()
            .await
            .expect("Failed to find pending commands");
        assert_eq!(pending_commands.len(), 1, "Expected one pending command");
        let pending_result = pending_commands[0].1.clone();

        ctx.mock_reset().await;

        // Second poll - server returns the same command again
        // But we should only try to send the pending result, not execute the command again
        ctx.mock_get_commands(HashMap::from([(0, command)])).await;

        // should only be called once, for pending result, not for a new execution
        ctx.mock_post_command_result(&cmd_id, 500, Some(pending_result))
            .await;

        ctx.polling.poll(&ctx.rac_cfg, &mut ctx.dbus_events).await;

        // Verify there are no more pending commands
        let pending_commands = ctx
            .polling
            .cmd_store
            .find_pending()
            .await
            .expect("Failed to find pending commands");
        assert!(!pending_commands.is_empty(), "Expected pending commands");
    }
}
