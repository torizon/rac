use std::{path::PathBuf, time::Duration};

use crate::local_session::*;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum LocalSession {
    Embedded(EmbeddedSession),
    TargetHost(TargetHostSession),
    SpawnedSshd(SpawnedSshdSession),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TorizonConfig {
    pub url: Url,
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
    pub server_cert_path: PathBuf,
    #[serde(skip_serializing)]
    pub namespace: Option<Uuid>,
    #[serde(skip_serializing, default = "default_http_timeout")]
    pub http_timeout: Duration,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceConfig {
    pub ssh_private_key_path: PathBuf,
    #[serde(skip_serializing, default = "default_poll_timeout")]
    pub poll_timeout: Duration,
    pub session: LocalSession,
    pub unprivileged_user_group: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct RacConfig {
    pub torizon: TorizonConfig,
    pub device: DeviceConfig,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SshSession {
    pub authorized_pubkeys: Vec<ssh_key::PublicKey>,
    pub reverse_port: u16,
    pub ra_server_url: Url,
    pub ra_server_ssh_pubkey: ssh_key::PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceSession {
    pub ssh: SshSession,
}

#[derive(Deserialize, Debug)]
pub struct SignedPayload<T> {
    pub signatures: Vec<String>,
    pub signed: T,
}

#[derive(Serialize)]
pub struct DeviceKey {
    pub key: ssh_key::PublicKey,
}

impl Default for TorizonConfig {
    fn default() -> Self {
        Self {
            #[allow(clippy::unwrap_used)]
            url: Url::parse("http://dgw.torizon.io").unwrap(),
            client_cert_path: PathBuf::from("client.pem"),
            client_key_path: PathBuf::from("client.key"),
            server_cert_path: PathBuf::from("server.key"),
            namespace: None,
            http_timeout: default_http_timeout(),
        }
    }
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            ssh_private_key_path: "device-key.sec".into(),
            poll_timeout: default_poll_timeout(),
            session: LocalSession::default(),
            unprivileged_user_group: None,
        }
    }
}

impl Default for LocalSession {
    fn default() -> Self {
        LocalSession::TargetHost(TargetHostSession {
            #[allow(clippy::unwrap_used)]
            host_port: "127.0.0.1:22".parse().unwrap(),
            authorized_keys_path: "/home/torizon/.ssh/authorized_keys2".into(),
        })
    }
}

fn default_poll_timeout() -> Duration {
    Duration::from_secs(3)
}

fn default_http_timeout() -> Duration {
    Duration::from_secs(10)
}
