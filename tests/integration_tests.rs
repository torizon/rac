mod common;

use std::{
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use color_eyre::eyre;
use http::StatusCode;
#[allow(clippy::wildcard_imports)]
use log::*;
use pretty_assertions::assert_eq;

use tokio::io::AsyncBufReadExt;

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use rac::{
    data_type::{DeviceSession, RacConfig, SessionType, SshSession},
    device_keys,
    ras_client::RasClient,
    session_handler::{EmbeddedSession, SpawnedSshdSession, TargetHostSession},
};
use russh::server::{Auth, Server, Session};
use ssh_key::rand_core::OsRng;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, ToSocketAddrs},
    sync::OnceCell,
};
use uuid::Uuid;

use url::Url;

#[derive(Clone)]
struct DirectorState {
    current_session: Arc<Mutex<Option<DeviceSession>>>,
}

#[allow(clippy::unused_async)]
async fn get_sessions(State(state): State<Arc<DirectorState>>) -> Response {
    let session = state.current_session.lock().unwrap();

    if let Some(ref dev_sess) = *session {
        return Json(dev_sess.clone()).into_response();
    }

    StatusCode::NOT_FOUND.into_response()
}

fn fake_ras(state: Arc<DirectorState>) -> Router {
    Router::new()
        .route("/sessions", get(get_sessions))
        .with_state(state)
        .route("/ok", get(|| async { "OK".to_string() }))
}

type Result<T> = color_eyre::Result<T>;

struct DeviceSshServer {}

impl russh::server::Server for DeviceSshServer {
    type Handler = DeviceConnection;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        DeviceConnection {}
    }
}

async fn start_device_ssh() -> (SocketAddr, ssh_key::PublicKey) {
    let (send, recv) = tokio::sync::oneshot::channel::<u16>();

    let secret_key = ssh_key::PrivateKey::random(OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let keypair = russh_keys::decode_openssh(&secret_key.to_bytes().unwrap(), None).unwrap();

    let mut config = russh::server::Config::default();
    config.keys.push(keypair);

    let config = Arc::new(config);

    tokio::spawn(async move {
        let socket = TcpListener::bind(("0.0.0.0", 0_u16)).await.unwrap();

        send.send(socket.local_addr().unwrap().port()).unwrap();

        let mut sh = DeviceSshServer {};

        while let Ok((socket, _)) = socket.accept().await {
            let config = config.clone();
            let server = sh.new_client(socket.peer_addr().ok());

            match russh::server::run_stream(config, socket, server).await {
                Err(err) => debug!("session could not be started with error: {}", err),
                Ok(session) => {
                    tokio::spawn(async {
                        if let Err(err) = session.await {
                            debug!("Session exited with error: {}", err);
                        }
                    });
                }
            };
        }
    });

    let socket_addr: SocketAddr = format!("0.0.0.0:{}", recv.await.unwrap()).parse().unwrap();

    (socket_addr, secret_key.public_key().clone())
}

struct DeviceConnection {}

#[async_trait]
impl russh::server::Handler for DeviceConnection {
    type Error = eyre::Error;

    async fn tcpip_forward(
        self,
        _address: &str,
        port: &mut u32,
        session: Session,
    ) -> Result<(Self, bool, Session)> {
        let port = *port;
        let session_handle = session.handle();

        tokio::spawn(async move {
            // #[allow[clippy()]]
            let server = TcpListener::bind(("127.0.0.1", port.try_into().unwrap()))
                .await
                .unwrap();

            loop {
                let session_handle = session_handle.clone();
                let (mut ingress, addr) = server.accept().await.unwrap();

                tokio::spawn(async move {
                    let channel = session_handle
                        .channel_open_forwarded_tcpip(
                            "127.0.0.1",
                            port,
                            addr.ip().to_string(),
                            u32::from(addr.port()),
                        )
                        .await
                        .unwrap();

                    let mut egress = channel.into_stream();

                    match tokio::io::copy_bidirectional(&mut ingress, &mut egress).await {
                        Ok(res) => info!("remote session ended: {:?}", res),
                        Err(err) => warn!("remote session ended with error: {}", err),
                    }
                });
            }
        });

        Ok((self, true, session))
    }

    async fn auth_publickey(
        self,
        _user: &str,
        _public_key: &russh_keys::key::PublicKey,
    ) -> Result<(Self, Auth)> {
        Ok((self, russh::server::Auth::Accept))
    }
}

fn find_free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("0.0.0.0", 0))?;
    Ok(listener.local_addr()?.port())
}

async fn start_ras(
    ssh_host: SocketAddr,
    server_public_key: ssh_key::PublicKey,
    user_public_key: Option<ssh_key::PublicKey>,
) -> (SocketAddr, Arc<DirectorState>) {
    let listener = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
    let addr = listener.local_addr().unwrap();

    let user_public_key = user_public_key.unwrap_or_else(|| {
        let private = ssh_key::PrivateKey::random(OsRng, ssh_key::Algorithm::Ed25519).unwrap();
        private.public_key().clone()
    });

    let device_session = {
        let device_id = Uuid::new_v4();

        DeviceSession {
            ssh: SshSession {
                authorized_pubkeys: vec![user_public_key],
                reverse_port: find_free_port().unwrap(),
                ra_server_url: Url::parse(&format!(
                    "ssh://{}@{}:{}",
                    device_id,
                    &ssh_host.ip(),
                    &ssh_host.port()
                ))
                .unwrap(),
                ra_server_ssh_pubkey: server_public_key,
            },
        }
    };

    let director_state = Arc::new(DirectorState {
        current_session: Arc::new(Mutex::new(Some(device_session))),
    });

    let moved_state = director_state.clone();

    tokio::spawn(async move {
        axum::Server::from_tcp(listener)
            .unwrap()
            .serve(fake_ras(moved_state).into_make_service())
            .await
            .unwrap();
    });

    (addr, director_state)
}

static ONCE: OnceCell<()> = OnceCell::const_new();

// This starts separate fake ras/http and ras/ssh servers. This is not
// ideal but otherwise we need to start and share a tokio runtime
async fn setup(user_key: Option<ssh_key::PublicKey>) -> (RacConfig, Arc<DirectorState>) {
    ONCE.get_or_init(|| async {
        env_logger::init();
        color_eyre::install().unwrap();
    })
    .await;

    let (ssh_addr, public_key) = start_device_ssh().await;

    let (ras_addr, director_state) = start_ras(ssh_addr, public_key, user_key).await;

    let mut rac_config = RacConfig::default();

    rac_config.torizon.url = Url::from_str(&format!("http://{ras_addr}")).unwrap();
    rac_config.device.session = SessionType::TargetHost(TargetHostSession {
        authorized_keys_path: "/tmp/mykeys".into(),
        host_port: ras_addr,
    });

    (rac_config, director_state)
}

// Full test of the happy path
//
// Starts an ssh server acting as RAS ssh API and a http acting as RAS http api
// Keep the normal RAC session loop with a remote tcp forward, connect the forward back to RAS/http
// Use the remote tcp forward by querying using HTTP using a standard HTTP client.
#[tokio::test]
async fn full_happy_path() {
    let (rac_config, director_state) = setup(None).await;

    let ras_client = RasClient::without_tls(rac_config.clone()).unwrap();

    let session = ras_client.get_session().await.unwrap().unwrap();

    device_keys::read_or_create(&rac_config.device.ssh_private_key_path)
        .await
        .unwrap();

    let session_rport = session.ssh.reverse_port;

    let session_handler = tokio::spawn(async move {
        rac::keep_session_loop(&rac_config, &ras_client, &session)
            .await
            .unwrap();
    });

    info!("Sleeping to wait for session loop to get the session");
    tokio::time::sleep(Duration::from_secs(1)).await;

    let client = reqwest::Client::new();

    let external_url = format!("http://localhost:{session_rport}/ok");

    let resp = client.get(external_url).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.text().await.unwrap(), "OK");

    {
        let mut current_session = director_state.current_session.lock().unwrap();
        *current_session = None;
    }

    if let Err(err) = tokio::time::timeout(Duration::from_secs(5), session_handler).await {
        panic!("session did not end successfully after 5 seconds: {err:?}")
    }
}

#[tokio::test]
async fn test_keys_changed() {
    let (rac_config, director_state) = setup(None).await;

    let ras_client = RasClient::without_tls(rac_config.clone()).unwrap();

    let session = ras_client.get_session().await.unwrap().unwrap();

    device_keys::read_or_create(&rac_config.device.ssh_private_key_path)
        .await
        .unwrap();

    let session_handler = tokio::spawn(async move {
        rac::keep_session_loop(&rac_config, &ras_client, &session)
            .await
            .unwrap();
    });

    info!("Sleeping to wait for session loop to get the session");
    tokio::time::sleep(Duration::from_secs(1)).await;

    {
        let mut current_session = director_state.current_session.lock().unwrap();
        let session = current_session.as_mut().unwrap();
        session.ssh.authorized_pubkeys.clear();
    }

    if let Err(err) = tokio::time::timeout(Duration::from_secs(5), session_handler).await {
        panic!("session did not end successfully after 5 seconds: {err:?}")
    }
}

struct UserClient {}

#[async_trait]
impl russh::client::Handler for UserClient {
    type Error = eyre::ErrReport;

    async fn check_server_key(
        self,
        server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<(Self, bool)> {
        println!("check_server_key: {server_public_key:?}");
        Ok((self, true))
    }
}

struct UserSession {
    session: russh::client::Handle<UserClient>,
}

impl UserSession {
    async fn connect<A: ToSocketAddrs>(
        user: impl Into<String>,
        addrs: A,
        key: ssh_key::PrivateKey,
    ) -> Result<Self> {
        let keypair = russh_keys::decode_openssh(&key.to_bytes().unwrap(), None)?;
        //let keypair = russh_keys::key::;
        let config = russh::client::Config::default();
        let config = Arc::new(config);
        let sh = UserClient {};
        let mut session = russh::client::connect(config, addrs, sh).await?;
        let _auth_res = session
            .authenticate_publickey(user, Arc::new(keypair))
            .await?;
        Ok(Self { session })
    }

    async fn echo_hello(&mut self) -> Result<String> {
        let bell = '\u{7}'.try_into().unwrap();
        let mut channel = self.session.channel_open_session().await?;

        channel
            .request_pty(true, "xterm", 100, 100, 100, 100, &[])
            .await?;
        channel.request_shell(true).await?;

        let (r, mut w) = tokio::io::split(channel.into_stream());
        let mut r = tokio::io::BufReader::new(r);

        let mut buf = Vec::new();
        r.read_until(bell, &mut buf).await?;
        buf.clear();

        w.write_all("echo HELLO\n".as_bytes()).await?;

        r.read_until(bell, &mut buf).await?;
        let str_buf = String::from_utf8_lossy(&buf);
        let output = console::strip_ansi_codes(&str_buf);

        Ok(output.to_string())
    }
}

#[tokio::test]
async fn test_embedded_server() {
    let user_key = ssh_key::PrivateKey::random(OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let (mut rac_config, _) = setup(Some(user_key.public_key().clone())).await;

    rac_config.device.session = SessionType::Embedded(EmbeddedSession::default());

    let ras_client = RasClient::without_tls(rac_config.clone()).unwrap();

    let session = ras_client.get_session().await.unwrap().unwrap();

    let ssh_session = session.ssh.clone();

    device_keys::read_or_create(&rac_config.device.ssh_private_key_path)
        .await
        .unwrap();

    tokio::spawn(async move {
        rac::keep_session_loop(&rac_config, &ras_client, &session)
            .await
            .unwrap();
    });

    info!("Sleeping to wait for session loop to get the session");
    tokio::time::sleep(Duration::from_secs(1)).await;

    let port = ssh_session.reverse_port;
    let mut ssh = UserSession::connect("ignored", ("0.0.0.0", port), user_key)
        .await
        .unwrap();
    let res = ssh.echo_hello().await.unwrap();

    assert!(res.contains("echo HELLO\r\n\rHELLO\r\n"));
}

#[tokio::test]
async fn test_spawned_sshd() {
    let user_key = ssh_key::PrivateKey::random(OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let (mut rac_config, _) = setup(Some(user_key.public_key().clone())).await;

    rac_config.device.session = SessionType::SpawnedSshd(SpawnedSshdSession {
        sshd_path: "/usr/bin/sshd".into(),
        config_dir: "./rac-test".into(),
    });

    let ras_client = RasClient::without_tls(rac_config.clone()).unwrap();

    let session = ras_client.get_session().await.unwrap().unwrap();

    let ssh_session = session.ssh.clone();

    device_keys::read_or_create(&rac_config.device.ssh_private_key_path)
        .await
        .unwrap();

    device_keys::read_or_create(&rac_config.device.ssh_private_key_path)
        .await
        .unwrap();

    let _session_handler = tokio::spawn(async move {
        rac::keep_session_loop(&rac_config, &ras_client, &session)
            .await
            .unwrap();
    });

    info!("Sleeping to wait for session loop to get the session");
    tokio::time::sleep(Duration::from_secs(1)).await;

    let user = whoami::username();

    let port = ssh_session.reverse_port;
    let mut ssh = UserSession::connect(user, ("0.0.0.0", port), user_key)
        .await
        .unwrap();
    let res = ssh.echo_hello().await.unwrap();

    assert!(res.contains("echo HELLO"));
}
