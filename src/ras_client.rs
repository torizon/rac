use reqwest::StatusCode;
use std::{io::{Write, Seek}, collections::HashSet};
use anyhow::Context;
use anyhow::anyhow;
use crate::data_type::RacConfig;
use crate::data_type::*;

pub struct RasClient {
    http_client: reqwest::Client,
    config: RacConfig,
}

impl RasClient {
    pub fn new(config: RacConfig) -> Result<Self, anyhow::Error> {
        let mut cb = reqwest::Client::builder();

        let server_cert_bytes = std::fs::read(&config.torizon.server_cert_path).context(format!("Could not read {:?}", &config.torizon.server_cert_path))?;
        let server_cert = reqwest::Certificate::from_pem(&server_cert_bytes)?;

        let mut client_cert =  std::fs::read(&config.torizon.client_cert_path).context(format!("Could not read {:?}", &config.torizon.client_cert_path))?;
        let mut client_key = std::fs::read(&config.torizon.client_key_path).context(format!("Could not read {:?}", &config.torizon.client_key_path))?;
        client_cert.append(&mut client_key);

        let identity = reqwest::Identity::from_pem(&client_cert)?;

        cb = cb.add_root_certificate(server_cert);

        cb = cb.identity(identity);

        Ok(RasClient {
            http_client: cb.build()?,
            config,
        })
    }

    pub fn update_authorized_keys(&self, new_keys: &Vec<String>) -> Result<(), anyhow::Error> {
        log::debug!("updating local device authorized keys");

        let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&self.config.device.authorized_keys_path).context("opening authorized keys file")?;

        use std::io::{self, BufRead};

        let mut new_file = Vec::<u8>::new();

        let lines = std::io::BufReader::new(&file).lines();

        for l in lines {
            if let Ok(key) = l {
                if ! key.ends_with("added by ras-client") {
                    new_file.write(key.as_bytes())?;
                    new_file.write("\n".as_bytes())?;
                }
            } else {
                log::debug!("Ignored line: {:?}", l)
            }
        }

        file.set_len(0)?;
        file.seek(io::SeekFrom::Start(0))?;
        file.write(&new_file)?;

        for k in new_keys {
            file.write(k.as_bytes())?;
        }

        file.flush()?;

        Ok(())
    }

    pub fn keys_changed(old: &Vec<String>, new: &Vec<String>) -> bool {
        if old.len() != new.len() {
            return true
        }

        let old_set: HashSet<&String> = old.iter().collect();
        let new_set: HashSet<&String> = new.iter().collect();

        old_set.difference(&new_set).next().is_some()
    }

    pub async fn add_device_pubkey(&self) -> Result<(), anyhow::Error> {
        let url = format!("{}/public-keys", &self.config.torizon.url);
        let mut req = self.http_client.post(url);

        let pk = String::from_utf8(std::fs::read(&self.config.device.ssh_public_key_path)?)?;

        log::debug!("Adding public key to ras: {}", &pk);

        let keys = DeviceKey { key: pk };

        req = req.json(&keys);

        let resp = req.send().await?;

        if ! resp.status().is_success() {
            anyhow::bail!("Could not add device keys to server: {:?}", resp)
        }

        Ok(())
    }

    pub async fn get_session(&self) -> Result<Option<(SshSession, String)>, anyhow::Error> {
        let url = format!("{}/sessions", &self.config.torizon.url);
        let req = self.http_client.get(url);
        let response = req.send().await?;

        if response.status() == StatusCode::NOT_FOUND {
            log::info!("No remote session found for device");
            return Ok(None)
        }

        if ! response.status().is_success() {
            anyhow::bail!("Could not get device sessions: {:?}", response);
        }

        let device_id = response.headers()
            .get("x-trx-device-uuid")
            .ok_or(anyhow!("server did not return device uuid"))?
            .to_str()?
            .to_owned();

        let payload = response.json::<SignedPayload<DeviceSession>>().await?;

        Ok(Some((payload.signed.ssh, device_id.to_owned())))
    }
}
