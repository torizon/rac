// Copyright 2023 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::unwrap_used)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]

pub mod command;
pub mod data_type;
pub mod dbus;
pub mod device_keys;
pub mod event_loop;
pub mod local_session;
pub mod torizon;

mod authorized_keys;
mod embedded_server;
mod spawned_sshd;
mod ssh;

use std::collections::HashSet;
use std::sync::Arc;

use eyre::bail;
use eyre::eyre;
use eyre::Context;

use futures::FutureExt;
use russh::client::Handle;
use serde::Serialize;
use ssh::Client;
use tokio::select;
use tokio::sync::broadcast::Receiver;

use crate::data_type::RacConfig;
use crate::data_type::*;
use crate::torizon::*;
use log::*;

type Result<T> = color_eyre::Result<T>;

#[allow(clippy::similar_names)]
pub fn drop_privileges(config: &RacConfig) -> Result<()> {
    if !nix::unistd::Uid::current().is_root() {
        info!("No need to drop privileges, current user is not root");
        return Ok(());
    }

    if let Some(ref user_group) = config.device.unprivileged_user_group {
        match user_group.split_once(':') {
            Some((user, group)) => {
                let ugroup = nix::unistd::Group::from_name(group)?
                    .ok_or(eyre!("Could not get group {group}"))?;

                let uuser = nix::unistd::User::from_name(user)?
                    .ok_or(eyre!("Could not get user {user}"))?;

                let user_name_cstring = std::ffi::CString::new(user)?;

                nix::unistd::initgroups(&user_name_cstring, ugroup.gid)?;

                nix::unistd::setgid(ugroup.gid)?;

                nix::unistd::setuid(uuser.uid)?;

                if nix::unistd::setuid(0.into()).is_ok() {
                    bail!("Could not drop privileges, can still change back to uid 0");
                }

                info!("Dropped privileges to {user}:{group}");

                Ok(())
            }
            _ => Err(eyre!(
                "unprivileged_user_group not in correct format: user:group"
            )),
        }
    } else {
        warn!("privileges not dropped, unprivileged_user_group not set");
        Ok(())
    }
}

pub async fn run_command(rac_cfg: &RacConfig, cmd: &Command) -> Result<CommandResult> {
    use futures::future::BoxFuture;

    let timeout = rac_cfg.device.commands_timeout;

    let run_command_fut: BoxFuture<'_, Result<std::process::Output>> = match cmd.name.clone() {
        CommandName::Reboot(action) => action.execute().boxed(),
        CommandName::RestartService(action) => action.execute(&cmd.args).boxed(),
        CommandName::Echo(action) => action.execute(&cmd.args).boxed(),
    };

    let mut output = select! {
        result = run_command_fut => result?,
        () = tokio::time::sleep(timeout) => {
            bail!("command execution timed out after {} seconds", timeout.as_secs())
        }
    };

    if !output.status.success() {
        debug!("output={:?}", &output);
        warn!("command execute failed");
    }

    let max_output_len = 1024 * 8 * 100 - "[...]".len(); // 100 Kb max

    if output.stdout.len() > max_output_len {
        output.stdout.truncate(max_output_len);
        output.stdout.extend("[...]".as_bytes());
    }

    if output.stderr.len() > max_output_len {
        output.stdout.truncate(max_output_len);
        output.stdout.extend("[...]".as_bytes());
    }

    let result = CommandResult {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        error: None,
        exit_code: output.status.code(),
        finished_at: chrono::Utc::now(),
    };

    Ok(result)
}

pub async fn keep_session_loop(
    config: &RacConfig,
    client: &TorizonClient,
    session: &DeviceSession,
    events: &mut Receiver<dbus::Event>,
) -> Result<()> {
    let mut session_type = config.device.session.clone();

    let mut wait_handle = session_type
        .start()
        .await
        .wrap_err("starting local session handle")?;

    let session_valid = valid_session_metadata(client, &session.ssh).await?;
    if session_valid != ValidSession::Valid {
        debug!("session from server is invalid: {:#?}", &session.ssh);
        error!(
            "invalid session received from server: {:#?}",
            &session_valid
        );
        return Ok(());
    }

    let mut session_handle = ssh::start(config, &session.ssh, Arc::new(session_type)).await?;
    let validation_poll_timeout = config.device.validation_poll_timeout;

    loop {
        select! {
            () = tokio::time::sleep(validation_poll_timeout) => {


                match disconnect_if_session_invalid(client, session, &session_handle).await? {
                    ValidSession::Valid =>
                        continue,
                    _invalid =>
                        break,
                };
            },
            event = events.recv() => {
                debug!("dbus event ({:?}) received while ssh session is active", event?);
                debug!("checking session is still valid");
                match disconnect_if_session_invalid(client, session, &session_handle).await? {
                    ValidSession::Valid => {
                        continue
                    },
                    _invalid =>
                        break,
                };
            },
            r = &mut wait_handle => {
                error!("local session handle exited unexpectedly: {r:?}");
                break;
            },
            h = &mut session_handle => {
                if let Err(err) = h {
                    error!("error with ssh session: {:?}", err);
                }
                info!("ssh session ended");
                break;
            },
        }
    }

    Ok(())
}

async fn disconnect_if_session_invalid(
    torizon_client: &TorizonClient,
    session: &DeviceSession,
    session_handle: &Handle<Client>,
) -> Result<ValidSession> {
    let new_session = torizon_client.get_session().await?.map(|s| s.ssh);

    match is_session_valid(torizon_client, &session.ssh, new_session.as_ref()).await? {
        ValidSession::Valid => {
            info!("session still valid");
            Ok(ValidSession::Valid)
        }
        invalid => {
            warn!("session no longer valid ({invalid:?}), disconnecting client");
            session_handle
                .disconnect(
                    russh::Disconnect::ByApplication,
                    "disconnect, session not valid",
                    "en",
                )
                .await?;
            Ok(invalid)
        }
    }
}

#[derive(Debug, PartialEq)]
enum ValidSession {
    Valid,
    InvalidUptaneMetadata(Vec<String>),
    InvalidSessionIsGone,
    InvalidKeysChanged,
    InvalidReversePortChanged,
    InvalidRaServerUrlChanged,
    InvalidRaServerPubKeyChanged,
}

async fn valid_session_metadata(
    torizon_client: &TorizonClient,
    metadata: &SshSession,
) -> Result<ValidSession> {
    let remote_sessions_role = torizon_client.fetch_verified_remote_sessions().await?;
    let remote_sessions: RemoteSessionsMetadata =
        serde_json::from_value(remote_sessions_role.remote_sessions)?;

    let mut reasons = Vec::new();

    let remote_sessions_authorized_keydata: Vec<_> = remote_sessions
        .authorized_keys
        .iter()
        .map(ssh_key::PublicKey::key_data)
        .collect();

    for k in &metadata.authorized_pubkeys {
        if !remote_sessions_authorized_keydata.contains(&k.key_data()) {
            reasons.push(format!(
                "remote-sessions metadata does not allow client key {}",
                k.fingerprint(ssh_key::HashAlg::default())
            ));
        }
    }

    if !remote_sessions
        .ra_server_ssh_pubkeys
        .contains(&metadata.ra_server_ssh_pubkey)
    {
        reasons.push(format!(
            "remote-sessions metadata does not allow server key {}",
            metadata
                .ra_server_ssh_pubkey
                .fingerprint(ssh_key::HashAlg::default())
        ));
    }

    match metadata.ra_server_url.host_str() {
        Some(host) if !remote_sessions.ra_server_hosts.contains(&host.to_owned()) => {
            reasons.push(format!(
                "remote-sessions metadata does not allow server host {} for url {}. Allowed hosts: {}",
                host,
                metadata.ra_server_url,
                remote_sessions.ra_server_hosts.join(", "),
            ));
        }
        Some(_) => {}
        None => reasons.push(format!(
            "empty host on url {} not allowed",
            metadata.ra_server_url
        )),
    }

    if reasons.is_empty() {
        debug!("metadata is valid against remote-sessions.json");
        Ok(ValidSession::Valid)
    } else {
        Ok(ValidSession::InvalidUptaneMetadata(reasons))
    }
}

async fn is_session_valid(
    torizon_client: &TorizonClient,
    old: &SshSession,
    new: Option<&SshSession>,
) -> Result<ValidSession> {
    if new.is_none() {
        return Ok(ValidSession::InvalidSessionIsGone);
    }

    #[allow(clippy::unwrap_used)]
    let new = new.unwrap();

    let old_keys = &old.authorized_pubkeys;
    let new_keys = &new.authorized_pubkeys;

    if old_keys.len() != new_keys.len() {
        return Ok(ValidSession::InvalidKeysChanged);
    }

    let old_set: HashSet<String> = old_keys
        .iter()
        .flat_map(ssh_key::PublicKey::to_openssh)
        .collect();
    let new_set: HashSet<String> = new_keys
        .iter()
        .flat_map(ssh_key::PublicKey::to_openssh)
        .collect();

    if !old_set.is_superset(&new_set) {
        return Ok(ValidSession::InvalidKeysChanged);
    }

    if old.reverse_port != new.reverse_port {
        debug!("{new:?}");
        info!("Reverse port changed, session changed");
        return Ok(ValidSession::InvalidReversePortChanged);
    }

    if old.ra_server_url != new.ra_server_url {
        debug!("{new:?}");
        info!("ra_server_url changed, session changed");
        return Ok(ValidSession::InvalidRaServerUrlChanged);
    }

    if old.ra_server_ssh_pubkey != new.ra_server_ssh_pubkey {
        debug!("{new:?}");
        info!("ra_server_ssh_pubkey changed, session changed");
        return Ok(ValidSession::InvalidRaServerPubKeyChanged);
    }

    valid_session_metadata(torizon_client, new).await
}

#[derive(Debug, PartialEq, Serialize)]
enum ValidCommand {
    Valid,
    InvalidUptaneMetadata(Vec<String>),
}

async fn valid_command_metadata<T: UptaneMetadataProvider>(
    uptane_metadata_provider: &T,
    metadata: &Command,
) -> Result<ValidCommand> {
    let remote_sessions_role = uptane_metadata_provider
        .fetch_verified_remote_sessions()
        .await?;

    let mut reasons = Vec::new();

    if remote_sessions_role.remote_commands.is_none() {
        return Ok(ValidCommand::InvalidUptaneMetadata(vec![
            "no remote_commands in remote-sessions".into(),
        ]));
    }

    #[allow(clippy::unwrap_used)] // is_none() is used
    let remote_commands: RemoteCommandsPayload =
        serde_json::from_value(remote_sessions_role.remote_commands.unwrap())?;

    let allowed_parameters = remote_commands.allowed_commands.get(&metadata.name);

    if let Some(allowed_parameters) = allowed_parameters {
        let allowed_args = &allowed_parameters.args;

        for arg in &metadata.args {
            if !allowed_args.contains(&CommandArg(arg.into())) {
                let allowed_args = allowed_args
                    .iter()
                    .map(|s| format!("`{}`", s.0))
                    .collect::<Vec<String>>()
                    .join(",");

                reasons.push(format!(
                    "arg `{arg}` not allowed. Allowed arguments are: {allowed_args}"
                ));
            }
        }
    } else {
        reasons.push(format!("command is not present in remote-sessions metadata. The command is {:?}, allowed commands are: {:?}", metadata.name,  remote_commands.allowed_commands.keys()));
    }

    if reasons.is_empty() {
        Ok(ValidCommand::Valid)
    } else {
        Ok(ValidCommand::InvalidUptaneMetadata(reasons))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::sync::Once;

    static INIT: Once = Once::new();

    pub fn setup() {
        INIT.call_once(|| {
            env_logger::init();
            color_eyre::install().expect("error installing color_eyre");
        });
    }
}
