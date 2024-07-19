// Copyright 2023 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

mod common;

use std::{
    collections::HashMap,
    net::SocketAddr,
    num::NonZeroU64,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use chrono::Utc;
use color_eyre::eyre;
use http::StatusCode;
#[allow(clippy::wildcard_imports)]
use log::*;
use pretty_assertions::assert_eq;

use serde_json::json;
use tokio::io::AsyncReadExt;

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use rac::{
    data_type::{DeviceSession, LocalSession, RacConfig, SshSession}, dbus::Event, device_keys, local_session::{EmbeddedSession, SpawnedSshdSession, TargetHostSession}, torizon::{self, TorizonClient}
};
use russh::server::{Auth, Server, Session};
use ssh_key::rand_core::OsRng;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, ToSocketAddrs},
    sync::OnceCell,
};
use tokio_retry::strategy::FixedInterval;
use tokio_stream::wrappers::ReceiverStream;
use tough::{
    schema::{RemoteSessions, RoleKeys, RoleType, Root, Signed},
    sign::Sign,
};
use uuid::Uuid;

use url::Url;

type Result<T> = color_eyre::Result<T>;

struct DirectorState {
    root: Signed<Root>,
    remote_sessions: Mutex<Signed<RemoteSessions>>,
}

impl DirectorState {
    async fn generate(
        authorized_keys: Vec<ssh_key::PublicKey>,
        ra_server_pubkeys: Vec<ssh_key::PublicKey>,
    ) -> Result<DirectorState> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
        let key_pair = tough::sign::parse_keypair(pkcs8_bytes.as_ref())?;

        let mut keys = HashMap::new();
        keys.insert(key_pair.tuf_key().key_id()?, key_pair.tuf_key());

        let role_keys = RoleKeys {
            keyids: vec![key_pair.tuf_key().key_id()?],
            threshold: NonZeroU64::new(1).unwrap(),
            _extra: Default::default(),
        };

        let mut roles = HashMap::new();
        roles.insert(RoleType::Root, role_keys.clone());
        roles.insert(RoleType::RemoteSessions, role_keys);

        let root = Root {
            spec_version: String::new(),
            consistent_snapshot: false,
            version: NonZeroU64::new(1).unwrap(),
            expires: Utc::now() + chrono::Duration::days(365),
            keys,
            roles: tough::schema::Roles::new(&roles),
            _extra: HashMap::new(),
        };

        let signed_root = Self::sign(&key_pair, root).await?;

        let mut authorized_keys_map = HashMap::<usize, serde_json::Value>::new();

        for (idx, k) in authorized_keys.iter().cloned().enumerate() {
            authorized_keys_map.insert(idx, json!({ "pubkey": k }));
        }

        let ssh_remote_session = json!({
                "ssh": {
                    "authorized_keys": authorized_keys_map,
                    "ra_server_hosts": vec!["0.0.0.0", "localhost"],
                    "ra_server_ssh_pubkeys": ra_server_pubkeys,
                }
        });

        let remote_sessions = RemoteSessions {
            remote_sessions: ssh_remote_session,
            expires: Utc::now() + chrono::Duration::days(360),
            version: NonZeroU64::new(1).unwrap(),
            _extra: HashMap::new(),
        };

        let signed_rs = Self::sign(&key_pair, remote_sessions).await?;

        Ok(Self {
            root: signed_root,
            remote_sessions: Mutex::new(signed_rs),
        })
    }

    async fn sign<T: tough::schema::Role>(key: &dyn Sign, payload: T) -> Result<Signed<T>> {
        let rng = ring::rand::SystemRandom::new();

        let mut data = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(
            &mut data,
            olpc_cjson::CanonicalFormatter::new(),
        );

        payload.serialize(&mut ser)?;
        let sig = key.sign(&data, &rng).await.unwrap();

        let mut signed = Signed {
            signed: payload,
            signatures: Vec::new(),
        };

        signed.signatures.push(tough::schema::Signature {
            keyid: key.tuf_key().key_id()?,
            sig: sig.into(),
        });

        Ok(signed)
    }

    async fn clear(&self) {
        let mut remote_sessions = self.remote_sessions.lock().unwrap();
        let new_state = DirectorState::generate(vec![], vec![]).await.unwrap();
        *remote_sessions = new_state.remote_sessions.lock().unwrap().clone();
    }
}

async fn get_root(State(state): State<Arc<DirectorState>>) -> Response {
    Json(state.root.clone()).into_response()
}

async fn get_remote_sessions(State(state): State<Arc<DirectorState>>) -> Response {
    let remote_sessions = state.remote_sessions.lock().unwrap().clone();
    Json(remote_sessions).into_response()
}

fn fake_director(state: Arc<DirectorState>) -> Router {
    Router::new()
        .route("/director/root.json", get(get_root))
        .with_state(state.clone())
        .route("/director/remote-sessions.json", get(get_remote_sessions))
        .with_state(state)
}

struct RasState {
    current_session: Mutex<Option<DeviceSession>>,
}

#[allow(clippy::unused_async)]
async fn get_sessions(State(state): State<Arc<RasState>>) -> Response {
    let session = state.current_session.lock().unwrap();

    if let Some(ref dev_sess) = *session {
        return Json(dev_sess.clone()).into_response();
    }

    StatusCode::NOT_FOUND.into_response()
}

fn fake_ras(state: Arc<RasState>) -> Router {
    Router::new()
        .route("/sessions", get(get_sessions))
        .with_state(state)
        .route("/ok", get(|| async { "OK".to_string() }))
}

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
) -> (SocketAddr, Arc<RasState>, Arc<DirectorState>) {
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
                authorized_pubkeys: vec![user_public_key.clone()],
                reverse_port: find_free_port().unwrap(),
                ra_server_url: Url::parse(&format!(
                    "ssh://{}@{}:{}",
                    device_id,
                    &ssh_host.ip(),
                    &ssh_host.port()
                ))
                .unwrap(),
                ra_server_ssh_pubkey: server_public_key.clone(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        }
    };

    let director_state = Arc::new(
        DirectorState::generate(vec![user_public_key], vec![server_public_key])
            .await
            .unwrap(),
    );

    let ras_state = Arc::new(RasState {
        current_session: Mutex::new(Some(device_session)),
    });

    let app = fake_ras(ras_state.clone()).merge(fake_director(director_state.clone()));

    tokio::spawn(async move {
        axum::Server::from_tcp(listener)
            .unwrap()
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    (addr, ras_state, director_state)
}

static ONCE: OnceCell<()> = OnceCell::const_new();

// This starts separate fake ras/http and ras/ssh servers. This is not
// ideal but otherwise we need to start and share a tokio runtime
async fn setup(
    user_key: Option<ssh_key::PublicKey>,
) -> (RacConfig, Arc<RasState>, Arc<DirectorState>) {
    ONCE.get_or_init(|| async {
        env_logger::init();
        color_eyre::install().unwrap();
    })
    .await;

    let (ssh_addr, public_key) = start_device_ssh().await;

    let (ras_addr, ras_state, director_state) = start_ras(ssh_addr, public_key, user_key).await;

    let mut rac_config = RacConfig::default();

    let (_, authorized_keys_temp_file) = tempfile::Builder::new()
        .prefix("rac-authorized-keys")
        .tempfile()
        .unwrap()
        .keep()
        .unwrap();

    rac_config.torizon.url = Url::from_str(&format!("http://{ras_addr}")).unwrap();
    rac_config.device.session = LocalSession::TargetHost(TargetHostSession {
        authorized_keys_path: authorized_keys_temp_file,
        host_port: ras_addr,
    });

    let tmp_dir = tempfile::Builder::new()
        .prefix("rac-uptane")
        .tempdir()
        .unwrap()
        .into_path();

    rac_config.device.local_tuf_repo_path = tmp_dir;

    (rac_config, ras_state, director_state)
}

// Full test of an error free execution
//
// Starts an ssh server acting as RAS ssh API and a http acting as RAS http api
// Keep the normal RAC session loop with a remote tcp forward, connect the forward back to RAS/http
// Use the remote tcp forward by querying using HTTP using a standard HTTP client.
#[tokio::test]
async fn full_no_error() {
    let (rac_config, ras_state, _) = setup(None).await;

    let torizon_client = TorizonClient::new(
        rac_config.clone(),
        torizon::notls_http_client(&rac_config).unwrap(),
    );

    let session = torizon_client.get_session().await.unwrap().unwrap();

    device_keys::read_or_create(&rac_config.device.ssh_private_key_path)
        .await
        .unwrap();

    let session_rport = session.ssh.reverse_port;

    let session_handler = tokio::spawn(async move {
        let mut dbus_events = futures::stream::pending();        
        rac::keep_session_loop(&rac_config, &torizon_client, &session, &mut dbus_events)
            .await
            .unwrap();
    });

    tokio_retry::Retry::spawn(FixedInterval::from_millis(500).take(10), || {
        port_open(session_rport)
    })
    .await
    .unwrap();

    let client = reqwest::Client::new();
    let external_url = format!("http://localhost:{session_rport}/ok");
    let resp = client.get(external_url).send().await.unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.text().await.unwrap(), "OK");

    {
        let mut current_session = ras_state.current_session.lock().unwrap();
        *current_session = None;
    }

    if let Err(err) = tokio::time::timeout(Duration::from_secs(5), session_handler).await {
        panic!("session did not end successfully after 5 seconds: {err:?}")
    }
}

// Full test of an error free execution
//
// Starts an ssh server acting as RAS ssh API and a http acting as RAS http api
// Keep the normal RAC session loop with a remote tcp forward, connect the forward back to RAS/http
// Use the remote tcp forward by querying using HTTP using a standard HTTP client.
#[tokio::test]
async fn test_director_error() {
    let (rac_config, _, director_state) = setup(None).await;

    let torizon_client = TorizonClient::new(
        rac_config.clone(),
        torizon::notls_http_client(&rac_config).unwrap(),
    );

    director_state.clear().await;

    let session = torizon_client.get_session().await.unwrap().unwrap();

    device_keys::read_or_create(&rac_config.device.ssh_private_key_path)
        .await
        .unwrap();

    let session_handler = tokio::spawn(async move {
        let mut dbus_events = futures::stream::pending();
        rac::keep_session_loop(&rac_config, &torizon_client, &session, &mut dbus_events).await
    });

    match tokio::time::timeout(Duration::from_secs(2), session_handler).await {
        Err(err) => panic!("session did not end successfully after 2 seconds: {err:?}"),
        Ok(res) => {
            let err = res.unwrap().err().unwrap().to_string();
            assert!(err.contains("Failed to verify remote-sessions metadata"));
        }
    }
}

async fn port_open(port: u16) -> Result<bool> {
    tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    Ok(true)
}

#[tokio::test]
async fn test_keys_changed() {
    let (rac_config, ras_state, _) = setup(None).await;

    let torizon_client = TorizonClient::new(
        rac_config.clone(),
        torizon::notls_http_client(&rac_config).unwrap(),
    );

    let session = torizon_client.get_session().await.unwrap().unwrap();
    let rport = session.ssh.reverse_port;

    device_keys::read_or_create(&rac_config.device.ssh_private_key_path)
        .await
        .unwrap();

    let session_handler = tokio::spawn(async move {
        let mut dbus_events = futures::stream::pending();
        rac::keep_session_loop(&rac_config, &torizon_client, &session, &mut dbus_events)
            .await
            .unwrap();
    });

    tokio_retry::Retry::spawn(FixedInterval::from_millis(500).take(10), || {
        port_open(rport)
    })
    .await
    .unwrap();

    {
        let mut current_session = ras_state.current_session.lock().unwrap();
        let session = current_session.as_mut().unwrap();
        session.ssh.authorized_pubkeys.clear();
    }

    if let Err(err) = tokio::time::timeout(Duration::from_secs(5), session_handler).await {
        panic!("session did not end successfully after 5 seconds: {err:?}")
    }
}

#[tokio::test]
async fn test_keys_changed_without_poll() {
    let (mut rac_config, ras_state, _) = setup(None).await;

    // Never poll unless we receive dbus event, so session_handler is only complete if the event
    // is processed
    rac_config.device.validation_poll_timeout = Duration::from_secs(3600);

    let torizon_client = TorizonClient::new(
        rac_config.clone(),
        torizon::notls_http_client(&rac_config).unwrap(),
    );

    let session = torizon_client.get_session().await.unwrap().unwrap();
    let rport = session.ssh.reverse_port;

    device_keys::read_or_create(&rac_config.device.ssh_private_key_path)
        .await
        .unwrap();

    let (tx, rx) = tokio::sync::mpsc::channel(1);

    let session_handler = tokio::spawn(async move {
        let mut dbus_events = ReceiverStream::new(rx);
        rac::keep_session_loop(&rac_config, &torizon_client, &session, &mut dbus_events)
            .await
            .unwrap();
    });

    tokio_retry::Retry::spawn(FixedInterval::from_millis(500).take(10), || {
        port_open(rport)
    })
    .await
    .unwrap();

    {
        let mut current_session = ras_state.current_session.lock().unwrap();
        let session = current_session.as_mut().unwrap();
        session.ssh.authorized_pubkeys.clear();
    }

    tx.send(Event::PollRasNow(serde_json::Value::Null)).await.unwrap();

    if let Err(err) = tokio::time::timeout(Duration::from_secs(5), session_handler).await {
        panic!("session did not end after 5 seconds: {err:?}")
    }
}


#[tokio::test]
async fn test_director_changed() {
    let (rac_config, _, director_state) = setup(None).await;
    
    let torizon_client = TorizonClient::new(
        rac_config.clone(),
        torizon::notls_http_client(&rac_config).unwrap(),
    );

    let session = torizon_client.get_session().await.unwrap().unwrap();
    let rport = session.ssh.reverse_port;

    device_keys::read_or_create(&rac_config.device.ssh_private_key_path)
        .await
        .unwrap();

    let mut dbus_events = futures::stream::pending();

    let session_handler = tokio::spawn(async move {
        rac::keep_session_loop(&rac_config, &torizon_client, &session, &mut dbus_events)
            .await
            .unwrap();
    });

    tokio_retry::Retry::spawn(FixedInterval::from_millis(500).take(10), || {
        port_open(rport)
    })
    .await
    .unwrap();

    director_state.clear().await;

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
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<(Self, bool)> {
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
        let config = russh::client::Config::default();
        let config = Arc::new(config);
        let sh = UserClient {};

        let mut session = russh::client::connect(config, addrs, sh).await?;
        let _auth_res = session
            .authenticate_publickey(user, Arc::new(keypair))
            .await?;

        Ok(Self { session })
    }

    async fn ready(&mut self) -> Result<bool> {
        let channel = self.session.channel_open_session().await?;

        channel
            .request_pty(true, "xterm", 200, 200, 200, 200, &[])
            .await?;
        channel.request_shell(true).await?;

        let (mut r, mut w) = tokio::io::split(channel.into_stream());

        w.write_all("export PS1=\\>\n".as_bytes()).await?;

        // TODO: Would a flush help?

        while let Ok(b) = r.read_u8().await {
            if b == b'>' {
                break;
            } else {
                info!("test: waiting for prompt");
                w.write_u8(b'\n').await?;
            }
        }
        Ok(true)
    }
}

#[tokio::test]
async fn test_embedded_server() {
    let user_key = ssh_key::PrivateKey::random(OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let (mut rac_config, _, _) = setup(Some(user_key.public_key().clone())).await;

    rac_config.device.session = LocalSession::Embedded(EmbeddedSession::default());

    let torizon_client = TorizonClient::new(
        rac_config.clone(),
        torizon::notls_http_client(&rac_config).unwrap(),
    );

    let session = torizon_client.get_session().await.unwrap().unwrap();

    let ssh_session = session.ssh.clone();

    device_keys::read_or_create(&rac_config.device.ssh_private_key_path)
        .await
        .unwrap();



    tokio::spawn(async move {
        let mut dbus_events = futures::stream::pending();
        rac::keep_session_loop(&rac_config, &torizon_client, &session, &mut dbus_events)
            .await
            .unwrap();
    });

    let port = ssh_session.reverse_port;

    tokio_retry::Retry::spawn(FixedInterval::from_millis(500).take(10), || port_open(port))
        .await
        .unwrap();

    let mut ssh = UserSession::connect("ignored", ("0.0.0.0", port), user_key)
        .await
        .unwrap();
    let res = ssh.ready().await.unwrap();

    assert!(res)
}

#[tokio::test]
async fn test_spawned_sshd() {
    let user_key = ssh_key::PrivateKey::random(OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let (mut rac_config, _, _) = setup(Some(user_key.public_key().clone())).await;

    let mut local_session_handler = SpawnedSshdSession::default();
    local_session_handler.config_dir = "./rac-test".into();
    local_session_handler.strict_mode = false;

    // On CI we run as root, so set user to a normal user and set permissions in config dir
    let user = if std::env::var("CI").ok().unwrap_or_default() == "true" {
        if let Err(err) = std::fs::create_dir("./rac-test") {
            debug!("could not create config_dir: {}", err)
        }

        let uid = nix::unistd::User::from_name("ci").unwrap().unwrap().uid;
        let gid = nix::unistd::Group::from_name("ci").unwrap().unwrap().gid;
        nix::unistd::chown("./rac-test", Some(uid), Some(gid)).unwrap();

        "ci".to_owned()
    } else {
        local_session_handler.config_dir = "./rac-test".into();
        nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap()
            .name
    };

    rac_config.device.session = LocalSession::SpawnedSshd(local_session_handler);

    let torizon_client = TorizonClient::new(
        rac_config.clone(),
        torizon::notls_http_client(&rac_config).unwrap(),
    );
    let session = torizon_client.get_session().await.unwrap().unwrap();
    let ssh_session = session.ssh.clone();

    device_keys::read_or_create(&rac_config.device.ssh_private_key_path)
        .await
        .unwrap();

    let _session_handler = tokio::spawn(async move {
        let mut dbus_events = futures::stream::pending();
        rac::keep_session_loop(&rac_config, &torizon_client, &session, &mut dbus_events)
            .await
            .unwrap();
    });

    let reverse_port = ssh_session.reverse_port;

    tokio_retry::Retry::spawn(FixedInterval::from_millis(500).take(10), || {
        port_open(reverse_port)
    })
    .await
    .unwrap();

    let port = ssh_session.reverse_port;
    let mut ssh = UserSession::connect(user, ("0.0.0.0", port), user_key)
        .await
        .unwrap();

    let res = ssh.ready().await.unwrap();

    assert!(res)
}
