use std::path::PathBuf;

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TorizonConfig {
    pub url: String,
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
    pub server_cert_path: PathBuf,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceConfig {
    pub ssh_host_port: String,
    pub ssh_public_key_path: String,
    pub ssh_private_key_path: String,
    pub authorized_keys_path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RacConfig {
    pub torizon: TorizonConfig,
    pub device: DeviceConfig
}

#[derive(Deserialize, Debug)]
pub struct SshSession {
    pub authorized_pubkeys: Vec<String>,
    pub reverse_port: u16,
    pub device_port: u16,
    pub ra_server_url: String,
    pub ra_server_ssh_pubkey: String,
}

#[derive(Deserialize, Debug)]
pub struct DeviceSession {
    pub ssh: SshSession,
}

#[derive(Deserialize, Debug)]
pub struct SignedPayload<T> {
    pub signatures: Vec<String>,
    pub signed: T
}


#[derive(Serialize)]
pub struct DeviceKey {
    pub key: String
}
