// Copyright 2023 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

use crate::data_type::RacConfig;
use crate::data_type::*;
use crate::local_session::{EmbeddedSession, SessionLifecycle};
use async_trait::async_trait;
use color_eyre::{eyre, eyre::bail};
use russh::client::Config;
use russh::*;
use russh_keys::*;
use socket2::TcpKeepalive;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::Result;

#[derive(Debug)]
pub struct Client {
    pub(crate) server_public_key: ssh_key::PublicKey,
    pub(crate) user_allowed_keys: Vec<ssh_key::PublicKey>,
    pub(crate) shell: Option<PathBuf>,
    pub(crate) session_type: Arc<LocalSession>,
}

#[async_trait]
impl client::Handler for Client {
    type Error = eyre::Error;

    async fn check_server_key(self, server_public_key: &key::PublicKey) -> Result<(Self, bool)> {
        let given_key = ssh_key::PublicKey::from_bytes(&server_public_key.public_key_bytes())?;

        if given_key.key_data() == self.server_public_key.key_data() {
            log::info!("Accepting server public key: {}", given_key.to_openssh()?);
            Ok((self, true))
        } else {
            Ok((self, false))
        }
    }

    #[allow(clippy::similar_names)]
    async fn server_channel_open_forwarded_tcpip(
        self,
        channel: Channel<russh::client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        _originator_port: u32,
        session: russh::client::Session,
    ) -> Result<(Self, russh::client::Session)> {
        log::info!(
            "Received connection from {} on {}:{} handling with {:?}",
            originator_address,
            connected_address,
            connected_port,
            &self.session_type,
        );

        match self.session_type.as_ref() {
            LocalSession::Embedded(session) => session.handle(&self, channel).await?,
            LocalSession::TargetHost(session) => session.handle(&self, channel).await?,
            LocalSession::SpawnedSshd(session) => session.handle(&self, channel).await?,
        }

        Ok((self, session))
    }
}

async fn connect_ssh<A: tokio::net::ToSocketAddrs>(
    ssh_config: Arc<Config>,
    addr: A,
    handler: Client,
) -> Result<russh::client::Handle<Client>> {
    let socket = TcpStream::connect(addr).await?;
    let sock_ref = socket2::SockRef::from(&socket);

    let mut ka = TcpKeepalive::new();
    ka = ka.with_time(Duration::from_secs(20));
    ka = ka.with_interval(Duration::from_secs(20));
    sock_ref.set_tcp_keepalive(&ka)?;

    let session = russh::client::connect_stream(ssh_config, socket, handler).await?;

    Ok(session)
}

pub async fn start(
    config: &RacConfig,
    ras_session: &SshSession,
    local_session: Arc<LocalSession>,
) -> crate::Result<russh::client::Handle<Client>> {
    let ssh_config = russh::client::Config::default();
    let ssh_config = Arc::new(ssh_config);

    let shell =
        if let LocalSession::Embedded(EmbeddedSession { shell, .. }) = local_session.as_ref() {
            Some(shell.clone())
        } else {
            None
        };

    let sh = Client {
        server_public_key: ras_session.ra_server_ssh_pubkey.clone(),
        user_allowed_keys: ras_session.authorized_pubkeys.clone(),
        session_type: local_session,
        shell,
    };

    let seckey = russh_keys::load_secret_key(&config.device.ssh_private_key_path, None)?;

    log::info!("ssh to {}", ras_session.ra_server_url.as_str(),);

    let Some(server_host) = ras_session.ra_server_url.domain() else {
        bail!(
            "invalid ras_session.ra_server_url: {:?} no domain",
            ras_session.ra_server_url
        );
    };

    let Some(server_port) = ras_session.ra_server_url.port() else {
        bail!(
            "invalid ras_session.ra_server_url: {:?} no port",
            ras_session.ra_server_url
        );
    };

    let mut session = connect_ssh(ssh_config, (server_host, server_port), sh).await?;

    let device_uuid = Uuid::parse_str(ras_session.ra_server_url.username())?;

    let auth_res = session
        .authenticate_publickey(device_uuid.to_string(), Arc::new(seckey))
        .await?;

    if !auth_res {
        bail!("Could not authenticate to ssh server")
    }

    log::info!(
        "requesting remote port forwarding to localhost:{} (-R)",
        ras_session.reverse_port
    );

    if !session
        .tcpip_forward("127.0.0.1", ras_session.reverse_port.into())
        .await?
    {
        bail!("could not set tcpi-forward on remote server (-R)")
    }

    Ok(session)
}
