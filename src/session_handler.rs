use async_trait::async_trait;
use eyre::Context;
use log::{info, warn};
use russh::Channel;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};
use tokio::net::TcpStream;

use crate::{
    authorized_keys,
    data_type::{RacConfig, SessionType},
    embedded_server,
};

impl SessionType {
    pub async fn ready(&self) -> crate::Result<()> {
        match self {
            SessionType::Embedded(session) => session.ready().await?,
            SessionType::TargetHost(session) => session.ready().await?,
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EmbeddedSession {
    pub server_key_path: Option<PathBuf>,
    pub shell: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TargetHostSession {
    pub authorized_keys_path: PathBuf,
    pub host_port: SocketAddr,
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

            match embedded_server::start_with(
                igress,
                allowed_public_keys,
                server_key_path,
                shell,
            )
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
        authorized_keys::update_keys(&self.authorized_keys_path, &vec![])
            .await
            .context("initializing target host session")
            .context("could not reset authorized keys")?;
        Ok(())
    }

    async fn handle(
        &self,
        client: &crate::ssh::Client,
        channel: Channel<russh::client::Msg>,
    ) -> crate::Result<()> {
        let remote_addr = self.host_port;

        authorized_keys::update_keys(&self.authorized_keys_path, &client.user_allowed_keys).await?;

        tokio::spawn(async move {
            let mut igress = channel.into_stream();
            let remote_conn = TcpStream::connect(remote_addr).await;

            match remote_conn {
                Err(err) => {
                    log::error!("Could not connect to ssh host: {:?} : {}", remote_addr, err)
                }
                Ok(mut egress) => {
                    let r = tokio::io::copy_bidirectional(&mut igress, &mut egress).await;
                    log::debug!("remote connection finished {:?}", r);
                }
            }
        });

        Ok(())
    }
}
