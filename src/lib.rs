#![deny(clippy::unwrap_used)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]

pub mod data_type;
pub mod device_keys;
pub mod local_session;
pub mod ras_client;

mod authorized_keys;
mod embedded_server;
mod spawned_sshd;
mod ssh;

use std::collections::HashSet;
use std::sync::Arc;

use eyre::bail;
use eyre::eyre;
use eyre::Context;
use tokio::select;

use crate::data_type::RacConfig;
use crate::data_type::*;
use crate::ras_client::*;
use log::*;

type Result<T> = color_eyre::Result<T>;

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

pub async fn keep_session_loop(
    config: &RacConfig,
    client: &RasClient,
    session: &DeviceSession,
) -> Result<()> {
    let mut session_type = config.device.session.clone();

    let mut wait_handle = session_type
        .start()
        .await
        .wrap_err("starting local session handle")?;

    let mut session_handle = ssh::start(config, &session.ssh, Arc::new(session_type)).await?;
    let poll_timeout = config.device.poll_timeout;

    loop {
        select! {
            r = &mut wait_handle => {
                error!("Local session handle exited unexpectedly: {r:?}");
                break;
            },
            h = &mut session_handle => {
                if let Err(err) = h {
                    error!("Error with ssh session: {:?}", err);
                }
                info!("ssh session ended");
                break;
            },
            _ = tokio::time::sleep(poll_timeout) => {
                let new_session = client.get_session().await?.map(|s| s.ssh);

                match session_still_valid(&session.ssh, new_session.as_ref()) {
                    ValidSession::Valid =>
                        debug!("Session still valid"),
                    invalid => {
                        warn!("session changed ({invalid:?}), disconnecting client");
                        session_handle.disconnect(russh::Disconnect::ByApplication, "disconnect, session not valid", "en").await?;
                        break;
                    },
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
enum ValidSession {
    Valid,
    InvalidSessionIsGone,
    InvalidKeysChanged,
    InvalidReversePortChanged,
    InvalidRaServerUrlChanged,
    InvalidRaServerPubKeyChanged,
}

fn session_still_valid(old: &SshSession, new: Option<&SshSession>) -> ValidSession {
    if new.is_none() {
        return ValidSession::InvalidSessionIsGone;
    }

    #[allow(clippy::unwrap_used)]
    let new = new.unwrap();

    let old_keys = &old.authorized_pubkeys;
    let new_keys = &new.authorized_pubkeys;

    if old_keys.len() != new_keys.len() {
        return ValidSession::InvalidKeysChanged;
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
        return ValidSession::InvalidKeysChanged;
    }

    if old.reverse_port != new.reverse_port {
        debug!("{new:?}");
        info!("Reverse port changed, session changed");
        return ValidSession::InvalidReversePortChanged;
    }

    if old.ra_server_url != new.ra_server_url {
        debug!("{new:?}");
        info!("ra_server_url changed, session changed");
        return ValidSession::InvalidRaServerUrlChanged;
    }

    if old.ra_server_ssh_pubkey != new.ra_server_ssh_pubkey {
        debug!("{new:?}");
        info!("ra_server_ssh_pubkey changed, session changed");
        return ValidSession::InvalidRaServerPubKeyChanged;
    }

    ValidSession::Valid
}

#[cfg(test)]
pub(crate) mod test {
    use std::sync::Once;

    static INIT: Once = Once::new();

    pub fn setup() {
        INIT.call_once(|| {
            env_logger::init();
            color_eyre::install().expect("error installed color_eyre");
        });
    }
}
