// Copyright 2023 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fmt::Display, path::PathBuf, time::Duration};

use crate::{
    command::{EchoAction, RebootAction, RebootServiceAction},
    local_session::*,
};
use chrono::{DateTime, Utc};
use eyre::OptionExt;
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
    #[serde(skip_serializing, default = "default_validation_poll_timeout")]
    pub validation_poll_timeout: Duration,
    pub session: LocalSession,
    pub unprivileged_user_group: Option<String>,
    #[serde(skip_serializing, default = "default_enable_dbus_client")]
    pub enable_dbus_client: bool,
    #[serde(skip_serializing, default = "default_commands_dir")]
    pub commands_dir: PathBuf,
    #[serde(skip_serializing, default = "default_commands_timeout")]
    pub commands_timeout: Duration,
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
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceSession {
    pub ssh: SshSession,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<serde_json::Value>,
    pub exit_code: Option<i32>,
    pub finished_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommandsResponse {
    pub values: HashMap<u32, Command>,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct CommandId(Uuid);

impl CommandId {
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
}

impl TryFrom<String> for CommandId {
    type Error = eyre::Report;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let uuid_str = value
            .strip_prefix("urn:tdx-ota:command:")
            .ok_or_eyre("urn for CommandId must have the format urn:tdx-ota:<uuid>")?;

        let cmd_id = Uuid::try_from(uuid_str).map(CommandId)?;

        Ok(cmd_id)
    }
}

impl From<CommandId> for String {
    fn from(val: CommandId) -> Self {
        val.to_string()
    }
}

impl Display for CommandId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "urn:tdx-ota:command:{}", self.0)
    }
}

impl std::fmt::Debug for CommandId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CommandId(urn:tdx-ota:command:{})", self.0)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CommandName {
    Reboot(#[serde(skip)] RebootAction),
    RestartService(#[serde(skip)] RebootServiceAction),
    Echo(#[serde(skip)] EchoAction),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Command {
    pub id: CommandId,
    pub name: CommandName,
    pub args: Vec<String>,
    pub created_at: DateTime<Utc>,
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
            validation_poll_timeout: default_validation_poll_timeout(),
            session: LocalSession::default(),
            unprivileged_user_group: None,
            enable_dbus_client: default_enable_dbus_client(),
            commands_dir: default_commands_dir(),
            commands_timeout: default_commands_timeout(),
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

fn default_validation_poll_timeout() -> Duration {
    Duration::from_secs(3)
}

fn default_http_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_local_config_path() -> PathBuf {
    "uptane-repo".into()
}

fn default_enable_dbus_client() -> bool {
    false
}

fn default_commands_dir() -> PathBuf {
    "commands".into()
}

fn default_commands_timeout() -> Duration {
    Duration::from_secs(30)
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

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct CommandArg(pub String);

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteCommandsPayload {
    pub allowed_commands: HashMap<CommandName, CommandParameters>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandParameters {
    pub args: Vec<CommandArg>,
}
