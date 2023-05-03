// Copyright 2023 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use color_eyre::eyre::bail;
use color_eyre::eyre::Context;
use color_eyre::eyre::{self, eyre};
use log::debug;
use log::{info, warn};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use russh::{
    server::{Auth, Msg, Session},
    Channel, ChannelId, Pty,
};
use russh_keys::PublicKeyBase64;
use ssh_key::HashAlg;
use ssh_key::PublicKey;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::device_keys;
use crate::Result;

struct DeviceSshServer {
    allowed_public_keys: Vec<PublicKey>,
    shell: Option<PathBuf>,
}

impl DeviceSshServer {
    fn new_client_noaddr(&mut self) -> DeviceConnection {
        DeviceConnection {
            pty_session_req: None,
            pty_chan: None,
            pty_size_tx: None,
            allowed_public_keys: self.allowed_public_keys.clone(),
            shell: self.shell.clone(),
        }
    }
}

impl russh::server::Server for DeviceSshServer {
    type Handler = DeviceConnection;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        self.new_client_noaddr()
    }
}

#[derive(Debug)]
struct PtySessionRequest {
    term: String,
    size_rx: UnboundedReceiver<PtySize>,
    shell: PathBuf,
}

struct DeviceConnection {
    pty_session_req: Option<PtySessionRequest>,
    pty_chan: Option<Channel<Msg>>,
    pty_size_tx: Option<UnboundedSender<PtySize>>,
    allowed_public_keys: Vec<PublicKey>,
    shell: Option<PathBuf>,
}

impl DeviceConnection {
    async fn spawn_shell(
        mut pty_request: PtySessionRequest,
        channel: Channel<Msg>,
        session: russh::server::Handle,
    ) -> Result<()> {
        let channel_id = channel.id();
        let channel_stream = channel.into_stream();
        let (client_read, client_write) = tokio::io::split(channel_stream);

        debug!("{term} requested", term = &pty_request.term);

        let mut cmd = CommandBuilder::new(&pty_request.shell);
        cmd.env("TERM", pty_request.term);

        let pty_system = native_pty_system();

        let size = pty_request
            .size_rx
            .recv()
            .await
            .ok_or(eyre!("pty session req was not initialized with a size"))?;

        let pair = pty_system.openpty(size).map_err(|err| eyre!(err))?;

        let wait_handler = tokio::task::spawn_blocking(move || {
            let child = pair
                .slave
                .spawn_command(cmd)
                .map_err(|err| eyre!(err))
                .and_then(|mut c| c.wait().wrap_err("waiting for child"));

            match child {
                Ok(exit) => debug!("wait_handler: child exited: {exit:?}"),
                Err(err) => warn!("child exited with error: {err:#?}"),
            }
        });

        let mut reader = pair.master.try_clone_reader().map_err(|err| eyre!(err))?;
        let read_handler = tokio::task::spawn_blocking(move || {
            let mut client_write = tokio_util::io::SyncIoBridge::new(client_write);

            match std::io::copy(&mut reader, &mut client_write) {
                Ok(b) => debug!("copy pty_master => client finished. Copied {} bytes", b),
                Err(err) => warn!("copy pty_master => client failed {err:?}"),
            }
        });

        let mut writer = pair.master.take_writer().map_err(|err| eyre!(err))?;
        let write_handler = tokio::task::spawn_blocking(move || {
            let mut client_read = tokio_util::io::SyncIoBridge::new(client_read);
            match std::io::copy(&mut client_read, &mut writer) {
                Ok(b) => debug!("copy client => pty_master finished. Copied {} bytes", b),
                Err(err) => warn!("copy pty_master => client failed {err:?}"),
            }
        });

        let size_handler = tokio::task::spawn(async move {
            while let Some(size) = pty_request.size_rx.recv().await {
                if let Err(err) = pair.master.resize(size) {
                    warn!("could not resize pty: {err:#?}");
                }
            }
        });

        tokio::select! {
            res = wait_handler => {
                debug!("shell process terminated ({res:?}). Finishing shell");
            },
            res = size_handler => {
                debug!("Size channel terminated ({res:?}). Finished shell");
            },
            res = read_handler => {
                debug!("Pty read finished ({res:?}). Finished shell");
            },
            res = write_handler => {
                debug!("Pty write finished ({res:?}). Finished shell");
            },
        };

        info!("shell finished, closing channel");

        session
            .close(channel_id)
            .await
            .map_err(|_| eyre!("could not close channel {channel_id:?}"))?;

        Ok(())
    }
}

#[async_trait]
impl russh::server::Handler for DeviceConnection {
    type Error = eyre::Report;

    #[allow(unused_variables, clippy::unused_async)]
    async fn channel_open_session(
        mut self,
        channel: Channel<Msg>,
        session: Session,
    ) -> Result<(Self, bool, Session)> {
        info!("Got session request");
        self.pty_chan = Some(channel);
        Ok((self, true, session))
    }

    #[allow(clippy::unused_async)]
    async fn shell_request(
        mut self,
        channel: ChannelId,
        session: Session,
    ) -> Result<(Self, Session)> {
        debug!("got shell_request for {channel:?}");

        if let Some(req) = self.pty_session_req.take() {
            let chan = self
                .pty_chan
                .take()
                .ok_or_else(|| eyre!("channel not set"))?;
            debug_assert_eq!(chan.id(), channel);

            let handle = session.handle();

            tokio::spawn(async {
                if let Err(err) = Self::spawn_shell(req, chan, handle).await {
                    warn!("could not spawn shell on shell_request: {err:#?}");
                }
            });
        } else {
            bail!("Could not get channel to start session")
        };

        Ok((self, session))
    }

    async fn window_change_request(
        self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: Session,
    ) -> Result<(Self, Session)> {
        debug!("window_change_request received for {channel:?}");

        let size_chan = self
            .pty_size_tx
            .as_ref()
            .ok_or_else(|| eyre!("pty_size_tx is None"))?;

        let size = PtySize {
            cols: col_width.try_into()?,
            rows: row_height.try_into()?,
            pixel_width: pix_width.try_into()?,
            pixel_height: pix_height.try_into()?,
        };

        size_chan
            .send(size)
            .wrap_err("sending new size to pty size channel")?;

        Ok((self, session))
    }

    #[allow(unused_variables)]
    async fn pty_request(
        mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: Session,
    ) -> Result<(Self, Session)> {
        info!("got pty_request on {channel:?}");

        let (size_tx, size_rx) = tokio::sync::mpsc::unbounded_channel();

        size_tx.send(PtySize {
            rows: row_height.try_into()?,
            cols: col_width.try_into()?,
            pixel_width: pix_width.try_into()?,
            pixel_height: pix_height.try_into()?,
        })?;

        let shell = if let Some(ref s) = self.shell {
            s.clone()
        } else {
            bail!("configuration error, pty requested but shell not set")
        };

        self.pty_session_req = Some(PtySessionRequest {
            term: term.to_owned(),
            size_rx,
            shell,
        });

        self.pty_size_tx = Some(size_tx);

        Ok((self, session))
    }

    async fn auth_publickey(
        self,
        user: &str,
        public_key: &russh_keys::key::PublicKey,
    ) -> Result<(Self, Auth)> {
        debug!("got auth_publickey request from user: {}", user);

        let given_key = ssh_key::public::PublicKey::from_bytes(&public_key.public_key_bytes())?;

        for key in &self.allowed_public_keys {
            #[allow(clippy::redundant_else)]
            if key.key_data() == given_key.key_data() {
                return Ok((self, russh::server::Auth::Accept));
            } else {
                debug!("Wrong key {}", key.fingerprint(HashAlg::Sha256));
            }
        }

        Ok((
            self,
            russh::server::Auth::Reject {
                proceed_with_methods: None,
            },
        ))
    }
}

// Never actually panics, see source for generate_ed25519
#[allow(clippy::missing_panics_doc)]
pub async fn start_with<R>(
    stream: R,
    allowed_public_keys: Vec<PublicKey>,
    private_key_path: Option<PathBuf>,
    shell: Option<PathBuf>,
) -> Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let keypair = {
        if let Some(private_key_path) = private_key_path {
            let keypair = device_keys::read_or_create(&private_key_path).await?;
            russh_keys::decode_openssh(&keypair.to_bytes()?, None)?
        } else {
            #[allow(clippy::unwrap_used)]
            let key = russh_keys::key::KeyPair::generate_ed25519().unwrap();
            let fingerprint = key.clone_public_key()?.fingerprint();
            info!("embedded server private key path not provided, generated one for the session: fingerprint: {}", fingerprint);
            key
        }
    };

    let mut config = russh::server::Config::default();
    config.keys.push(keypair);

    let config = Arc::new(config);

    let mut server = DeviceSshServer {
        allowed_public_keys,
        shell,
    };

    let handler = server.new_client_noaddr();

    russh::server::run_stream(config, stream, handler)
        .await?
        .await
}
