use async_trait::async_trait;
use eyre::eyre;
use eyre::Context;
use futures::{
    future::{self, BoxFuture, Pending},
    Future, FutureExt,
};
use log::{info, warn};
use russh::Channel;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};
use tokio::{net::TcpStream, task::JoinHandle};

use crate::{authorized_keys, data_type::SessionType, embedded_server, spawned_sshd, Result};

pub type LocalSshSessionHandle<'a> = BoxFuture<'a, Result<()>>;

impl SessionType {
    pub async fn start<'a>(&mut self) -> Result<LocalSshSessionHandle<'a>> {
        match self {
            SessionType::Embedded(session) => session.start().await,
            SessionType::TargetHost(session) => session.start().await,
            SessionType::SpawnedSshd(session) => session.start().await,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct EmbeddedSession {
    pub server_key_path: Option<PathBuf>,
    pub shell: PathBuf,
}

impl Default for EmbeddedSession {
    fn default() -> Self {
        Self {
            server_key_path: None,
            shell: "/usr/bin/bash".into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct TargetHostSession {
    pub authorized_keys_path: PathBuf,
    pub host_port: SocketAddr,
}

impl Default for TargetHostSession {
    fn default() -> Self {
        Self {
            authorized_keys_path: "/home/torizon/.ssh/authorized_keys".into(),
            #[allow(clippy::unwrap_used)]
            host_port: "127.0.0.1:22".parse().unwrap(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct SpawnedSshdSession {
    pub sshd_path: PathBuf,
    pub config_dir: PathBuf,
    used_port: Option<u16>,
}

impl Default for SpawnedSshdSession {
    fn default() -> Self {
        Self {
            sshd_path: "/usr/bin/sshd".into(),
            config_dir: "/run/rac".into(),
            used_port: None,
        }
    }
}

#[async_trait]
pub trait SessionHandling {
    async fn start<'a>(&mut self) -> Result<LocalSshSessionHandle<'a>>;

    async fn handle(
        &self,
        client: &crate::ssh::Client,
        channel: Channel<russh::client::Msg>,
    ) -> Result<()>;
}

#[async_trait]
impl SessionHandling for EmbeddedSession {
    async fn start<'a>(&mut self) -> Result<LocalSshSessionHandle<'a>> {
        Ok(future::pending().boxed())
    }

    async fn handle(
        &self,
        client: &crate::ssh::Client,
        channel: Channel<russh::client::Msg>,
    ) -> Result<()> {
        let allowed_public_keys = client.user_allowed_keys.clone();
        let server_key_path = self.server_key_path.clone();
        let shell = client.shell.clone();

        tokio::spawn(async move {
            let igress = channel.into_stream();

            match embedded_server::start_with(igress, allowed_public_keys, server_key_path, shell)
                .await
            {
                Ok(_) => info!("pty session finished"),
                Err(err) => warn!("pty session finished with error: {err:?}"),
            };
        });

        Ok(())
    }
}

#[async_trait]
impl SessionHandling for TargetHostSession {
    async fn start<'a>(&mut self) -> Result<LocalSshSessionHandle<'a>> {
        authorized_keys::update_keys(&self.authorized_keys_path, &[])
            .await
            .context("initializing target host session")
            .context("could not reset authorized keys")?;

        Ok(future::pending().boxed())
    }

    #[allow(clippy::similar_names)]
    async fn handle(
        &self,
        client: &crate::ssh::Client,
        channel: Channel<russh::client::Msg>,
    ) -> Result<()> {
        let remote_addr = self.host_port;
        let keys_path = self.authorized_keys_path.clone();

        authorized_keys::update_keys(&keys_path, &client.user_allowed_keys).await?;

        tokio::spawn(async move {
            let mut igress = channel.into_stream();
            let remote_conn = TcpStream::connect(remote_addr).await;

            match remote_conn {
                Err(err) => {
                    log::error!("Could not connect to ssh host: {:?} : {}", remote_addr, err);
                }
                Ok(mut egress) => {
                    let r = tokio::io::copy_bidirectional(&mut igress, &mut egress).await;
                    log::debug!("remote connection finished {:?}", r);
                }
            }

            if let Err(err) = authorized_keys::update_keys(&keys_path, &[]).await {
                warn!("Could not update authorized_keys after session end: {err:?}");
            }
        });

        Ok(())
    }
}

#[async_trait]
impl SessionHandling for SpawnedSshdSession {
    async fn start<'a>(&mut self) -> Result<LocalSshSessionHandle<'a>> {
        let sshd_path = self.sshd_path.clone();
        let config_dir = self.config_dir.clone();

        let (port, handle) = spawned_sshd::start___(&sshd_path, &config_dir).await?;

        self.used_port = Some(port);

        let f = handle.map(|_| Ok(())  );

        return Ok(f.boxed());
    }

    async fn handle(
        &self,
        client: &crate::ssh::Client,
        channel: Channel<russh::client::Msg>,
    ) -> Result<()> {
        let config_dir = self.config_dir.to_path_buf();
        let user_allowed_keys = client.user_allowed_keys.clone();

        let port = self.used_port.ok_or(eyre!("a spawned ssh session was requested, but a port is not yet assigned. Did you call `start`?"))?;

        tokio::spawn(async move {
            if let Err(err) = spawned_sshd::connect_channel(
                &config_dir,
                port,
                &user_allowed_keys,
                channel).await
            {
                warn!("could not start tunnel with spawned sshd {err:?}");
            }
        });

        Ok(())
    }
}
