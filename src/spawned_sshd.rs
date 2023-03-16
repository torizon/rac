use std::{
    future::Future,
    io::ErrorKind,
    path::{Path, PathBuf},
    process::ExitStatus,
    time::Duration,
};

use color_eyre::Report;
use eyre::Context;
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

use crate::{authorized_keys, device_keys, Result};

async fn write_config_file(
    port: u16,
    config_dir: &Path,
    host_key_path: &Path,
    authorized_keys_path: &Path,
) -> Result<PathBuf> {
    let host_key_path = std::fs::canonicalize(host_key_path)?;
    let host_key_path = String::from_utf8_lossy(host_key_path.as_os_str().as_bytes());
    let authorized_keys_path = std::fs::canonicalize(authorized_keys_path)?;
    let authorized_keys_path = String::from_utf8_lossy(authorized_keys_path.as_os_str().as_bytes());

    let cfg = format!(
        r#"
Port {port}
ListenAddress 127.0.0.1
ListenAddress ::1
PidFile none
HostKey {host_key_path}
PermitRootLogin no
AuthorizedKeysFile {authorized_keys_path}
PasswordAuthentication no
UsePAM no
AllowAgentForwarding no
AllowTcpForwarding yes
Subsystem       sftp    internal-sftp
"#
    );
    let config_file = config_dir.join("sshd.conf");

    if tokio::fs::try_exists(&config_file).await? {
        warn!("config file exists");
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
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

async fn ensure_host_key_exists(config_dir: &Path) -> Result<PathBuf> {
    let path = config_dir.join("host_key_ed25519");

    device_keys::read_or_create(&path).await?;

    Ok(path)
}

async fn find_free_port() -> Result<u16> {
    let listener = TcpListener::bind(("0.0.0.0", 0)).await?;
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

    eyre::bail!("could not connect to sshd after {tries} tries");
}

pub(crate) async fn connect_channel(
    sshd_path: &Path,
    config_dir: &Path,
    allowed_keys: &[ssh_key::PublicKey],
    client_channel: Channel<Msg>,
) -> crate::Result<()> {
    let (port, handle) = spawn_sshd(sshd_path, config_dir, allowed_keys)
        .await
        .wrap_err("error forking sshd")?;

    let buffer_size = 8 * 1024 * 1000;

    let mut sshd_chan = tokio::io::BufStream::with_capacity(
        buffer_size,
        buffer_size,
        ensure_sshd_chan_ready(port).await?,
    );

    let mut client_channel =
        tokio::io::BufStream::with_capacity(buffer_size, buffer_size, client_channel.into_stream());

    tokio::select! {
        exit_code = handle =>
            info!("sshd exited with status: {exit_code:?}"),
        res = tokio::io::copy_bidirectional(&mut sshd_chan, &mut client_channel) =>
            if let Err(err) = res {
                info!("ssh <-> spawned sshd channel ended: {err:?}");
            },
    }

    Ok(())
}

async fn spawn_sshd(
    sshd_path: &Path,
    config_dir: &Path,
    allowed_keys: &[PublicKey],
) -> Result<(u16, impl Future<Output = Result<ExitStatus>>)> {
    tokio::fs::create_dir_all(&config_dir)
        .await
        .wrap_err("creating config_dir")?;

    let authorized_keys_path = update_authorized_keys(config_dir, allowed_keys).await?;

    let host_key_path = ensure_host_key_exists(config_dir)
        .await
        .wrap_err("ensuring host key exists and is valid")?;

    let free_port = find_free_port().await?;

    let config_file =
        write_config_file(free_port, config_dir, &host_key_path, &authorized_keys_path).await?;

    let config_file_path = String::from_utf8_lossy(config_file.as_os_str().as_bytes()).to_string();

    let mut cmd = Command::new(sshd_path);
    cmd.arg("-D"); // run in foreground
    cmd.arg("-e"); // debug to sterr
    cmd.arg("-f").arg(config_file_path);
    cmd.kill_on_drop(true);

    let mut child = cmd.spawn()?;

    debug!("sshd started on port {free_port}");

    let wait_handle = async move { child.wait().map(|r| r.map_err(Report::from)).await };

    Ok((free_port, wait_handle))
}
