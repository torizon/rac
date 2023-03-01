use crate::data_type::RacConfig;
use crate::data_type::*;
use async_trait::async_trait;
use russh::*;
use russh_keys::*;
use uuid::Uuid;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use color_eyre::{eyre::{self}, eyre::bail};

#[derive(Debug)]
pub struct Client {
    server_public_key: ssh_key::PublicKey,
    ssh_host_port: SocketAddr,
}

#[async_trait]
impl client::Handler for Client {
    type Error = eyre::Error;

    async fn check_server_key(
        self,
        server_public_key: &key::PublicKey,
    ) -> Result<(Self, bool), Self::Error> {
        let given_key = ssh_key::PublicKey::from_bytes(&server_public_key.public_key_bytes())?;

        // TODO: Not enough?
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
    ) -> Result<(Self, russh::client::Session), Self::Error> {

        log::info!(
            "Received connection from {} on {}:{} forwarding to {}",
            originator_address,
            connected_address,
            connected_port,
            self.ssh_host_port,
        );

        tokio::spawn(async move {
            let mut igress = channel.into_stream();
            let remote_conn = TcpStream::connect(self.ssh_host_port).await;

            match remote_conn {
                Err(err) => log::error!("Could not connect to ssh host: {:?} : {}", self.ssh_host_port, err),
                Ok(mut egress) => {
                    let r = tokio::io::copy_bidirectional(&mut igress, &mut egress).await;
                    log::debug!("remote connection finished {:?}", r);
                }
            }
        });

        Ok((self, session))
    }
}

pub async fn start(
    config: &RacConfig,
    ras_session: &SshSession,
) -> crate::Result<russh::client::Handle<Client>> {
    let ssh_config = russh::client::Config::default();
    let ssh_config = Arc::new(ssh_config);

    let sh = Client {
        server_public_key: ras_session.ra_server_ssh_pubkey.clone(),
        ssh_host_port: config.device.target_host_port,
    };

    let seckey = russh_keys::load_secret_key(&config.device.ssh_private_key_path, None)?;

    log::info!(
        "ssh to {}",
        ras_session.ra_server_url.as_str(),
    );

    let Some(server_host) = ras_session.ra_server_url.domain() else {
        bail!("invalid ras_session.ra_server_url: {:?} no domain", ras_session.ra_server_url);
    };

    let Some(server_port) = ras_session.ra_server_url.port() else {
        bail!("invalid ras_session.ra_server_url: {:?} no port", ras_session.ra_server_url);
    };

    let mut session = russh::client::connect(
        ssh_config,
        (server_host, server_port),
        sh,
    )
        .await?;

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
