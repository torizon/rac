// Copyright 2025 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use chrono::Local;
use eyre::Context;
use eyre::OptionExt;
use log::debug;
use log::error;
use log::warn;
use nix::fcntl::Flock;
use serde::Deserialize;
use serde::Serialize;

use crate::data_type::*;

use crate::Result;

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
