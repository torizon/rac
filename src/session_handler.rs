use async_trait::async_trait;
use eyre::Context;
use log::{info, warn};
use russh::Channel;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};
use tokio::net::TcpStream;

use crate::{authorized_keys, data_type::SessionType, embedded_server, spawned_sshd};

impl SessionType {
    pub async fn ready(&self) -> crate::Result<()> {
        match self {
            SessionType::Embedded(session) => session.ready().await?,
            SessionType::TargetHost(session) => session.ready().await?,
            SessionType::SpawnedSshd(session) => session.ready().await?,
        }

        Ok(())
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
}

impl Default for SpawnedSshdSession {
    fn default() -> Self {
        Self {
            sshd_path: "/usr/bin/sshd".into(),
            config_dir: "/run/rac".into(),
        }
    }
}

#[async_trait]
pub trait SessionHandling {
    async fn ready(&self) -> crate::Result<()>;

    async fn handle(
        &self,
        client: &crate::ssh::Client,
        channel: Channel<russh::client::Msg>,
    ) -> crate::Result<()>;
}

#[async_trait]
impl SessionHandling for EmbeddedSession {
    async fn ready(&self) -> crate::Result<()> {
        Ok(())
    }

    async fn handle(
        &self,
        client: &crate::ssh::Client,
        channel: Channel<russh::client::Msg>,
    ) -> crate::Result<()> {
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
    async fn ready(&self) -> crate::Result<()> {
        authorized_keys::update_keys(&self.authorized_keys_path, &[])
            .await
            .context("initializing target host session")
            .context("could not reset authorized keys")?;
        Ok(())
    }

    #[allow(clippy::similar_names)]
    async fn handle(
        &self,
        client: &crate::ssh::Client,
        channel: Channel<russh::client::Msg>,
    ) -> crate::Result<()> {
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
    async fn ready(&self) -> crate::Result<()> {
        Ok(())
    }

    async fn handle(
        &self,
        client: &crate::ssh::Client,
        channel: Channel<russh::client::Msg>,
    ) -> crate::Result<()> {
        let sshd_path = self.sshd_path.clone();
        let config_dir = self.config_dir.clone();
        let user_allowed_keys = client.user_allowed_keys.clone();

        tokio::spawn(async move {
            if let Err(err) =
                spawned_sshd::connect_channel(&sshd_path, &config_dir, &user_allowed_keys, channel)
                    .await
            {
                warn!("could not start tunnel with spawned sshd {err:?}");
            }
        });

        Ok(())
    }
}
