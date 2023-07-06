// Copyright 2023 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub director_url: Option<Url>,
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
    #[serde(default = "default_local_config_path")]
    pub local_tuf_repo_path: PathBuf,
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
            director_url: None,
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
            local_tuf_repo_path: default_local_config_path(),
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

fn default_local_config_path() -> PathBuf {
    "uptane-repo".into()
}

impl<'de> Deserialize<'de> for RemoteSessionsMetadata {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RemoteSessionsMetadataDe {
            #[serde(deserialize_with = "deserialize_public_key_map")]
            authorized_keys: Vec<ssh_key::PublicKey>,
            ra_server_hosts: Vec<String>,
            ra_server_ssh_pubkeys: Vec<ssh_key::PublicKey>,
        }

        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = RemoteSessionsMetadata;

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut rs = None;

                while let Some(k) = map.next_key::<String>()? {
                    if k == "ssh" {
                        let entry: RemoteSessionsMetadataDe = map.next_value()?;

                        rs = Some(RemoteSessionsMetadata {
                            authorized_keys: entry.authorized_keys,
                            ra_server_hosts: entry.ra_server_hosts,
                            ra_server_ssh_pubkeys: entry.ra_server_ssh_pubkeys,
                        });
                    }
                }

                rs.ok_or(serde::de::Error::missing_field("ssh"))
            }

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map")
            }
        }

        deserializer.deserialize_map(Visitor)
    }
}

fn deserialize_public_key_map<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<ssh_key::PublicKey>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct KeyData {
        pubkey: ssh_key::PublicKey,
    }

    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<ssh_key::PublicKey>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a map")
        }

        fn visit_map<M>(self, mut access: M) -> std::result::Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut seq = Vec::new();

            while let Some((_, key_data)) = access.next_entry::<String, KeyData>()? {
                seq.push(key_data.pubkey);
            }

            Ok(seq)
        }
    }

    deserializer.deserialize_map(Visitor)
}

// RemoteSessionMetadata comes nested in a `ssh` key, so we use an explicit Deserializer
// authorized_keys is a map key-id -> key map, but we just need the public key so we use a simpler
// explicit deserializer
#[derive(Debug)]
pub struct RemoteSessionsMetadata {
    pub authorized_keys: Vec<ssh_key::PublicKey>,
    pub ra_server_hosts: Vec<String>,
    pub ra_server_ssh_pubkeys: Vec<ssh_key::PublicKey>,
}
