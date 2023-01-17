use async_trait::async_trait;
use tokio::net::TcpStream;

use std::sync::Arc;

use russh::*;
use russh_keys::*;
use crate::data_type::*;
use crate::data_type::RacConfig;
use anyhow::Context;

#[derive(Debug)]
pub struct SshClient {
    server_public_key: key::PublicKey,
    ssh_host_port: String,
}

#[async_trait]
impl client::Handler for SshClient {
    type Error = russh::Error;

    async fn check_server_key(
        self,
        server_public_key: &key::PublicKey,
    ) -> Result<(Self, bool), Self::Error> {
        // TODO: Not enough
        if server_public_key.fingerprint() == self.server_public_key.fingerprint() {
            log::debug!("Accepting server public key: {:?}", server_public_key);
            log::info!("Accepting server public key: {}", server_public_key.public_key_base64());
            Ok((self, true))
        } else {
            Ok((self, false))
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        self,
        channel: Channel<russh::client::Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        session: russh::client::Session,
    ) -> Result<(Self, russh::client::Session), Self::Error> {

        let host_port = self.ssh_host_port.clone();

        log::info!("Received connection on remote port {}, forwarding to {}", connected_port, &host_port);

        tokio::spawn(async move {
            let mut channel_stream = channel.into_stream();
            let remote_conn = TcpStream::connect(host_port).await;
            if remote_conn.is_err() {
                log::error!("Could not connect to remote: {:?}", remote_conn);
                Err(remote_conn.unwrap_err())
            } else {
                let r = tokio::io::copy_bidirectional(&mut channel_stream, &mut remote_conn.unwrap()).await;
                log::debug!("remote connection finished {:?}", r);
                r
            }
        });

        Ok((self, session))
    }
}

pub async fn start_ssh(config: &RacConfig, device_uuid: &String, ras_session: &SshSession) -> Result<russh::client::Handle<SshClient>, anyhow::Error> {
    let ssh_config = russh::client::Config::default();
    let ssh_config = Arc::new(ssh_config);

    let mut split = ras_session.ra_server_ssh_pubkey.split_whitespace();

    let server_pubkey = match (split.next(), split.next()) {
        (Some(_), Some(key)) => parse_public_key_base64(key).context("could not parse server public key")?,
        _ => anyhow::bail!("Received invalid server public key for session: {}", ras_session.ra_server_ssh_pubkey),
    };

    let sh = SshClient {
        server_public_key: server_pubkey,
        ssh_host_port: config.device.ssh_host_port.clone(),
    };

    let seckey = russh_keys::load_secret_key(&config.device.ssh_private_key_path, None)?;

    log::info!("ssh to {}:{}", ras_session.ra_server_url.as_str(), ras_session.device_port);

    let mut session = russh::client::connect(ssh_config, (ras_session.ra_server_url.as_str(), ras_session.device_port), sh).await?;

    let auth_res = session
        .authenticate_publickey(device_uuid, Arc::new(seckey))
        .await?;

    if ! auth_res {
        anyhow::bail!("Could not authenticate to ssh server")
    }

    log::info!("requesting remote port forwarding to localhost:{} (-R)", ras_session.reverse_port);

    if ! session.tcpip_forward("127.0.0.1", ras_session.reverse_port.into()).await? {
        anyhow::bail!("could not set tcpi-forward on remote server (-R)")
    }

    Ok(session)
}
