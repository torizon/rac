// Copyright 2025 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Local;
use eyre::Context;
use eyre::OptionExt;
use log::debug;
use log::error;
use log::warn;
use log::*;
use nix::fcntl::Flock;
use serde::Deserialize;
use serde::Serialize;
use tokio::task::JoinHandle;

use crate::data_type::*;
use crate::ValidCommand;

use crate::torizon::TorizonClient;
use crate::torizon::UptaneMetadataProvider;
use crate::Result;
use serde_json::json;

// The goal of persisting command results to disk is to cover the
// following failure modes:
//
// 1. The Command execution starts, and then RAC is killed or
// crashes. On the next RAC run, rac picks up the command from disk
// and reports a failure to the server, before polling for new
// commands.
//
// 2. The Command execution starts and finishes, but RAC cannot send
// the result back to the server. On the next command polling run, RAC
// will try to send the output back to the server, before polling for
// new commands.
//
// 3. A concurrent execution of RAC will try to run the same Command
// at the same time. RAC will write and lock a file to disk and try to
// prevent a double execution of the command.
//
// Every other failure mode related with the execution and persistence
// of command results to disk is undefined behavior.
#[derive(Debug)]
pub struct CommandStore {
    base_dir: PathBuf,
    locks: HashMap<CommandId, nix::fcntl::Flock<std::fs::File>>,
}

impl CommandStore {
    #[must_use]
    pub fn new(base_dir: PathBuf) -> CommandStore {
        Self {
            base_dir,
            locks: HashMap::new(),
        }
    }

    fn file_path(&self, cmd_id: &CommandId) -> PathBuf {
        format!("{}/{cmd_id}.cmd", self.base_dir.display()).into()
    }

    async fn set_file_lock<'a>(
        &'a mut self,
        cmd_id: &CommandId,
    ) -> Result<&'a mut Flock<std::fs::File>> {
        if !self.locks.contains_key(cmd_id) {
            tokio::fs::create_dir_all(&self.base_dir)
                .await
                .context(format!("create_dir_all {}", self.base_dir.display()))?;

            let file_path = self.file_path(cmd_id);

            let file = tokio::task::spawn_blocking(move || {
                let file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(false)
                    .open(&file_path)
                    .context(format!("file_path {}", file_path.display()))?;

                let file = match nix::fcntl::Flock::lock(
                    file,
                    nix::fcntl::FlockArg::LockExclusiveNonblock,
                ) {
                    Ok(l) => l,
                    Err((_, err)) => return Err(err.into()),
                };

                Ok::<Flock<std::fs::File>, eyre::Report>(file)
            })
            .await??;

            self.locks.insert(*cmd_id, file);
        }

        #[allow(clippy::unwrap_used)] // initialized if didn't exist
        let file_lock = self.locks.get_mut(cmd_id).unwrap();

        Ok(file_lock)
    }

    async fn unset_file_lock(&mut self, cmd_id: &CommandId, keep_file_result: bool) -> Result<()> {
        let _file = self.locks.remove(cmd_id).ok_or_eyre("lock was not set")?;

        if !keep_file_result {
            tokio::fs::remove_file(self.file_path(cmd_id)).await?;
        }

        Ok(()) // _file is dropped here, closing the file and releasing the lock
    }

    pub async fn start(&mut self, cmd_id: &CommandId) -> Result<()> {
        self.set_file_lock(cmd_id).await?;
        Ok(())
    }

    pub async fn result_pending(
        &mut self,
        cmd_id: &CommandId,
        result: CommandResult,
        error: eyre::Report,
    ) -> Result<()> {
        let file = self.set_file_lock(cmd_id).await?;

        let payload = RunData {
            cmd_id: *cmd_id,
            output: result,
            error: Some(format!("{error}").to_owned()),
        };

        let json = serde_json::to_string_pretty(&payload)?;

        // blocking IO
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&json.into_bytes())?;
        file.sync_all()?;

        self.unset_file_lock(cmd_id, true).await?;

        Ok(())
    }

    pub async fn find_pending(&mut self) -> Result<Vec<(CommandId, CommandResult)>> {
        let mut pending = Vec::new();

        if !tokio::fs::try_exists(&self.base_dir).await? || !self.base_dir.is_dir() {
            return Ok(pending);
        }

        let mut entries = tokio::fs::read_dir(&self.base_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("cmd") {
                debug!("unexpected file {path:?}");
                continue;
            }

            let Ok(content) = tokio::fs::read_to_string(&path).await else {
                debug!("could read {path:?}");
                continue;
            };

            let run_data = match serde_json::from_str::<RunData>(&content) {
                Ok(run_data) => run_data,
                Err(err) => {
                    warn!("could not parse contents of {path:?}: {err:?} try to finish command");

                    let cmd_id: Result<CommandId> = path
                        .file_name()
                        .and_then(|f| f.to_str())
                        .map(|f| f.trim_end_matches(".cmd").to_owned())
                        .ok_or_eyre("invalid cmd output filename")
                        .and_then(String::try_into);

                    if let Err(err) = cmd_id {
                        error!("could not end command {err:?}");
                        continue;
                    }

                    RunData {
                        cmd_id: cmd_id?,
                        output: CommandResult {
                            success: false,
                            stdout: "unknown".into(),
                            stderr: "unknown".into(),
                            error: Some(
                                "a lock file for the command exists, but no output is available"
                                    .into(),
                            ),
                            exit_code: None,
                            finished_at: chrono::Utc::now(),
                        },
                        error: Some(
                            "a lock file for the command exists, but no output is available".into(),
                        ),
                    }
                }
            };

            if self.locks.contains_key(&run_data.cmd_id) {
                debug!(
                    "there is an existent lock for {}, not reporting this cmd",
                    &run_data.cmd_id
                );
                continue;
            }

            pending.push((run_data.cmd_id, run_data.output));

            // limit to 10 per call so that a single client is not
            // stuck on sending too many results at the same time
            if pending.len() >= 10 {
                break;
            }
        }

        Ok(pending)
    }

    pub async fn result_sent(&mut self, cmd_id: &CommandId) -> Result<()> {
        self.set_file_lock(cmd_id).await?;
        self.unset_file_lock(cmd_id, false).await?;
        Ok(())
    }

    pub async fn is_pending(&mut self, cmd_id: &CommandId) -> Result<bool> {
        if self.find_pending().await?.iter().any(|p| p.0 == *cmd_id) {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[derive(Serialize, Deserialize)]
struct RunData {
    cmd_id: CommandId,
    output: CommandResult,
    error: Option<String>,
}

#[derive(Debug, Clone, Default, Hash, PartialEq, Eq)]
pub struct EchoAction;

impl EchoAction {
    pub async fn execute(self, args: &[String]) -> crate::Result<std::process::Output> {
        use tokio::process::Command;

        let mut output = Command::new("echo").args(args).output().await?;

        let str_output = String::from_utf8_lossy(&output.stdout).to_string();

        output.stdout = str_output
            .trim_end_matches(|c: char| c.is_whitespace())
            .into();

        Ok(output)
    }
}

#[derive(Debug, Clone, Default, Hash, PartialEq, Eq)]
pub struct RebootAction;

impl RebootAction {
    pub async fn execute(self) -> crate::Result<std::process::Output> {
        // Implement reboot action logic here
        use tokio::process::Command;

        let reboot_when = Local::now() + Duration::from_secs(30);
        let when_str = format!("--when={}", reboot_when.format("%Y-%m-%d %H:%M:%S"));

        // requires sudo
        let output = Command::new("sudo")
            .arg("systemctl")
            .arg("reboot")
            .arg(&when_str)
            .output()
            .await?;

        Ok(output)
    }
}

#[derive(Debug, Clone, Default, Hash, PartialEq, Eq)]
pub struct RebootServiceAction {}

impl RebootServiceAction {
    pub async fn execute(self, args: &[String]) -> crate::Result<std::process::Output> {
        use tokio::process::Command;

        let name = args
            .first()
            .ok_or_eyre("restart: no argument for service name")?;

        // requires sudo
        let output = Command::new("sudo")
            .arg("systemctl")
            .arg("restart")
            .arg(name)
            .output()
            .await?;

        Ok(output)
    }
}

#[derive(Debug)]
pub struct CommandPolling<V: UptaneMetadataProvider = TorizonClient> {
    ras_client: TorizonClient,
    rac_config: RacConfig,
    metadata_provider: V,
    cmd_store: Arc<tokio::sync::Mutex<CommandStore>>,
    handler: Option<JoinHandle<crate::Result<()>>>,
}

impl<V: UptaneMetadataProvider + 'static> CommandPolling<V> {
    pub fn new(ras_client: TorizonClient, rac_config: RacConfig, metadata_provider: V) -> Self {
        let persist = CommandStore::new(rac_config.device.commands_dir.clone());

        Self {
            ras_client,
            rac_config,
            cmd_store: Arc::new(tokio::sync::Mutex::new(persist)),
            metadata_provider,
            handler: None,
        }
    }

    async fn poll_for_new_commands(&mut self) -> Result<Option<Command>> {
        let commands = self
            .ras_client
            .get_commands()
            .await
            .wrap_err("Could not get session data from server")?
            .values;

        debug!("commands received: {commands:?}");

        // Only return the lowest priority command
        let cmd_opt = commands.first().cloned();

        // validate RAS command against uptane metadata
        if let Some(cmd) = cmd_opt {
            let cmd_valid = crate::valid_command_metadata(&self.metadata_provider, &cmd).await?;
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

                self.ras_client
                    .send_command_result(&cmd.id, &result)
                    .await?;

                Ok(None)
            } else {
                Ok(Some(cmd))
            }
        } else {
            Ok(None)
        }
    }

    async fn run_command(
        rac_cfg: RacConfig,
        ras_client: TorizonClient,
        cmd: Command,
        cmd_store_ref: Arc<tokio::sync::Mutex<CommandStore>>,
    ) -> crate::Result<()> {
        let mut cmd_store = cmd_store_ref.lock().await;

        cmd_store.start(&cmd.id).await?;

        match crate::run_command(&rac_cfg, &cmd).await {
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

        Ok(())
    }

    async fn poll_safe(&mut self) -> crate::Result<()> {
        {
            let mut cmd_store = self.cmd_store.lock().await;

            for (cmd_id, res) in cmd_store.find_pending().await? {
                cmd_store.start(&cmd_id).await?;

                if let Err(err) = self.ras_client.send_command_result(&cmd_id, &res).await {
                    warn!("could not send pending command result: {err:?}");
                    cmd_store.result_pending(&cmd_id, res, err).await?;
                } else {
                    debug!("finished pending cmd {}", &cmd_id);
                    cmd_store.result_sent(&cmd_id).await?;
                }
            }
        }

        if let Some(cmd) = self.poll_for_new_commands().await? {
            info!("running command {:?}", &cmd);

            {
                let mut cmd_store = self.cmd_store.lock().await;

                if cmd_store.is_pending(&cmd.id).await? {
                    warn!(
                        "command {:?} returned from server still pending, not executing again",
                        &cmd.id
                    );
                    return Ok(());
                }
            }

            let handler = tokio::spawn(Self::run_command(
                self.rac_config.clone(),
                self.ras_client.clone(),
                cmd,
                self.cmd_store.clone(),
            ));

            self.handler = Some(handler);
        } else {
            info!("no new commands in RAS");
        };

        Ok(())
    }

    pub async fn poll(&mut self) {
        if let Some(h) = &mut self.handler {
            if h.is_finished() {
                match h.await {
                    Ok(Ok(_)) => {
                        debug!("command loop finished");
                    }
                    Ok(Err(err)) => {
                        error!("command execution failed: {err:?}");
                    }
                    Err(err) => warn!("command execution loop failed: {err:?}"),
                }
                self.handler = None;
            } else {
                info!("command execution not finished, skipping poll");
                return;
            }
        }

        if let Err(err) = self.poll_safe().await {
            error!("error, trying later {err:?}");
        }
    }

    #[cfg(test)]
    async fn wait_for_command(&mut self) {
        if let Some(h) = self.handler.take() {
            h.await
                .expect("command task panicked")
                .expect("command task failed");
        }
    }
}

#[cfg(test)]
mod polling_tests {
    use super::*;
    use crate::data_type::CommandsResponse;
    use serde_json::json;
    use std::collections::HashMap;
    use tempfile::{tempdir, TempDir};
    use tough::schema::RemoteSessions;
    use url::Url;
    use wiremock::{
        matchers::{body_json_schema, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    struct TestContext {
        polling: CommandPolling<MockUptaneProvider>,
        mock_server: MockServer,
        _commands_dir: TempDir,
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
            let commands_dir = tempdir().expect("Failed to create temp directory");

            let mock_server = MockServer::start().await;
            let base_url = Url::parse(&mock_server.uri()).expect("Failed to parse URL");

            let rac_config = RacConfig {
                torizon: crate::data_type::TorizonConfig {
                    url: base_url.clone(),
                    director_url: Some(base_url),
                    ..Default::default()
                },
                device: crate::data_type::DeviceConfig {
                    commands_dir: commands_dir.path().to_path_buf(),
                    ..Default::default()
                },
            };

            let http_client = reqwest::Client::builder()
                .build()
                .expect("Failed to build HTTP client");
            let ras_client = TorizonClient::new(rac_config.clone(), http_client);

            Self {
                polling: CommandPolling::new(ras_client, rac_config, MockUptaneProvider {}),
                mock_server,
                _commands_dir: commands_dir,
            }
        }

        // polls and waits for the spawned command execution, if any, to finish
        async fn poll(&mut self) {
            self.polling.poll().await;
            self.polling.wait_for_command().await;
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

        async fn mock_get_commands(&self, commands: Vec<Command>) {
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
                .lock()
                .await
                .start(cmd_id)
                .await
                .expect("Failed to start command");

            self.polling
                .cmd_store
                .lock()
                .await
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

        ctx.mock_get_commands(vec![command]).await;

        ctx.mock_post_command_result(&cmd_id, 200, Some(expect))
            .await;

        ctx.poll().await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .lock()
            .await
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

        ctx.mock_get_commands(vec![command]).await;

        ctx.mock_post_command_result(&cmd_id, 200, Some(expect))
            .await;

        ctx.poll().await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .lock()
            .await
            .find_pending()
            .await
            .expect("Failed to find pending commands");
        assert!(pending_commands.is_empty(), "Expected no pending commands");
    }

    #[tokio::test]
    async fn test_poll_and_run_command_no_commands() {
        let mut ctx = TestContext::new().await;

        ctx.mock_get_commands(vec![]).await;

        ctx.poll().await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .lock()
            .await
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

        ctx.mock_get_commands(vec![]).await;

        ctx.mock_post_command_result(&cmd_id, 200, Some(result))
            .await;

        ctx.poll().await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .lock()
            .await
            .find_pending()
            .await
            .expect("Failed to find pending commands");

        assert!(pending_commands.is_empty(), "Expected no pending commands");
    }

    #[tokio::test]
    async fn test_poll_and_run_command_failed_to_send_result() {
        let mut ctx = TestContext::new().await;
        let (cmd_id, command) = ctx.create_command();

        ctx.mock_get_commands(vec![command]).await;

        ctx.mock_post_command_result(&cmd_id, 500, None).await;

        ctx.poll().await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .lock()
            .await
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

        ctx.mock_get_commands(vec![command]).await;

        ctx.mock_post_command_result(&cmd_id, 500, None).await;

        ctx.poll().await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .lock()
            .await
            .find_pending()
            .await
            .expect("Failed to find pending commands");
        assert_eq!(pending_commands.len(), 1, "Expected one pending command");
        assert_eq!(
            pending_commands[0].0, cmd_id,
            "Expected pending command to match created command"
        );

        ctx.mock_reset().await;

        ctx.mock_get_commands(vec![]).await;

        let result = pending_commands[0].1.clone();
        ctx.mock_post_command_result(&cmd_id, 200, Some(result.clone()))
            .await;

        // Second poll - should retry sending the pending result
        ctx.poll().await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .lock()
            .await
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

        ctx.mock_get_commands(vec![command.clone()]).await;
        ctx.mock_post_command_result(&cmd_id, 500, None).await;
        ctx.poll().await;

        let pending_commands = ctx
            .polling
            .cmd_store
            .lock()
            .await
            .find_pending()
            .await
            .expect("Failed to find pending commands");
        assert_eq!(pending_commands.len(), 1, "Expected one pending command");
        let pending_result = pending_commands[0].1.clone();

        ctx.mock_reset().await;

        // Second poll - server returns the same command again
        // But we should only try to send the pending result, not execute the command again
        ctx.mock_get_commands(vec![command]).await;

        // should only be called once, for pending result, not for a new execution
        ctx.mock_post_command_result(&cmd_id, 500, Some(pending_result))
            .await;

        ctx.poll().await;

        // Verify there are no more pending commands
        let pending_commands = ctx
            .polling
            .cmd_store
            .lock()
            .await
            .find_pending()
            .await
            .expect("Failed to find pending commands");
        assert!(!pending_commands.is_empty(), "Expected pending commands");
    }
}
