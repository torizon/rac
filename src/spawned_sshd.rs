// Copyright 2023 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::Permissions,
    future::Future,
    io::ErrorKind,
    path::{Path, PathBuf},
    process::ExitStatus,
    time::Duration,
};

use std::os::unix::prelude::PermissionsExt;

use color_eyre::Report;
use eyre::{bail, Context};
use futures::FutureExt;
use log::{debug, info, warn};
use russh::{client::Msg, Channel};
use ssh_key::PublicKey;
use tokio::{
    fs::OpenOptions,
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    process::Command,
};

use std::os::unix::ffi::OsStrExt;

use crate::{authorized_keys, device_keys, local_session::SpawnedSshdSession, Result};

async fn write_config_file(
    port: u16,
    config: &SpawnedSshdSession,
    authorized_keys_path: &Path,
) -> Result<PathBuf> {
    let host_key_path = ensure_host_key_exists(&config.config_dir, config.host_key_path.as_deref())
        .await
        .wrap_err("ensuring host key exists and is valid")?;

    let host_key_path = std::fs::canonicalize(host_key_path)?;
    let host_key_path = String::from_utf8_lossy(host_key_path.as_os_str().as_bytes());
    let authorized_keys_path = std::fs::canonicalize(authorized_keys_path)?;
    let authorized_keys_path = String::from_utf8_lossy(authorized_keys_path.as_os_str().as_bytes());

    let cfg = format!(
        r#"
Port {port}
ListenAddress 127.0.0.1
PidFile none
StrictModes {strict}
HostKey {host_key_path}
PermitRootLogin no
AuthorizedKeysFile {authorized_keys_path}
PasswordAuthentication no
AllowAgentForwarding no
AllowTcpForwarding yes
Subsystem       sftp    internal-sftp
PrintMotd  no
"#,
        strict = if config.strict_mode { "yes" } else { "no" }
    );
    let config_file = config.config_dir.join("sshd.conf");

    if tokio::fs::try_exists(&config_file).await? {
        warn!("config file exists");
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&config_file)
        .await?;

    file.write_all(cfg.as_bytes()).await?;

    let config_file = std::fs::canonicalize(&config_file)?;

    Ok(config_file)
}

async fn update_authorized_keys(config_dir: &Path, keys: &[PublicKey]) -> Result<PathBuf> {
    let authorized_keys_path = config_dir.join("authorized_keys");

    authorized_keys::update_keys(&authorized_keys_path, keys).await?;

    Ok(authorized_keys_path)
}

async fn ensure_host_key_exists(
    config_dir: &Path,
    host_key_path: Option<&Path>,
) -> Result<PathBuf> {
    let path = if let Some(path) = host_key_path {
        path.into()
    } else {
        config_dir.join("host_key_ed25519")
    };

    device_keys::read_or_create(&path).await?;

    Ok(path)
}

async fn find_free_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    Ok(listener.local_addr()?.port())
}

pub(crate) async fn ensure_sshd_chan_ready(port: u16) -> Result<TcpStream> {
    let tries = 10;

    for _ in 0..tries {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(chan) => {
                debug!("sshd ready to connect on port {port}");
                return Ok(chan);
            }
            Err(err) if err.kind() == ErrorKind::ConnectionRefused => {
                tokio::time::sleep(Duration::from_millis(500)).await;
                debug!("sshd not ready to connect: {err:?}");
            }
            Err(err) => return Err(err.into()),
        }
    }

    bail!("could not connect to sshd after {tries} tries");
}

pub(crate) async fn connect_channel(
    config_dir: &Path,
    port: u16,
    allowed_keys: &[ssh_key::PublicKey],
    client_channel: Channel<Msg>,
) -> crate::Result<()> {
    update_authorized_keys(config_dir, allowed_keys).await?;

    let buffer_size = 8 * 1024 * 1000;

    let mut sshd_chan = tokio::io::BufStream::with_capacity(
        buffer_size,
        buffer_size,
        ensure_sshd_chan_ready(port).await?,
    );

    let mut client_channel =
        tokio::io::BufStream::with_capacity(buffer_size, buffer_size, client_channel.into_stream());

    if let Err(err) = tokio::io::copy_bidirectional(&mut sshd_chan, &mut client_channel).await {
        info!("ssh <-> spawned sshd channel ended: {err:?}");
    }

    Ok(())
}

pub(crate) async fn spawn_sshd(
    config: &SpawnedSshdSession,
    allowed_keys: &[PublicKey],
) -> Result<(u16, impl Future<Output = Result<ExitStatus>>)> {
    tokio::fs::create_dir_all(&config.config_dir)
        .await
        .wrap_err(format!("creating config_dir: {:?}", config.config_dir))?;

    tokio::fs::set_permissions(&config.config_dir, Permissions::from_mode(0o700)).await?;

    let authorized_keys_path = update_authorized_keys(&config.config_dir, allowed_keys).await?;

    let free_port = find_free_port().await?;

    debug!("spawning sshd on port {free_port}");

    let config_file = write_config_file(free_port, config, &authorized_keys_path).await?;

    let config_file_path = String::from_utf8_lossy(config_file.as_os_str().as_bytes()).to_string();

    let mut cmd = Command::new(&config.sshd_path);
    cmd.arg("-D"); // run in foreground

    if log::max_level() <= log::Level::Debug {
        cmd.arg("-e"); // debug to sterr
    }

    cmd.arg("-f").arg(config_file_path);
    cmd.kill_on_drop(true);

    let mut child = cmd.spawn()?;

    debug!("sshd started on port {free_port}");

    let wait_handle = async move { child.wait().map(|r| r.map_err(Report::from)).await };

    Ok((free_port, wait_handle))
}
