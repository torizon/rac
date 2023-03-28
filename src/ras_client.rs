use crate::data_type::RacConfig;
use crate::data_type::*;
use crate::Result;
use color_eyre::eyre::{self, Context};
use eyre::bail;
use log::*;
use reqwest::{IntoUrl, StatusCode};

pub struct RasClient {
    http_client: reqwest::Client,
    config: RacConfig,
}

impl RasClient {
    pub fn without_tls(config: RacConfig) -> Result<Self> {
        let mut cb = reqwest::Client::builder();

        cb = cb.user_agent(Self::user_agent());
        cb = cb.timeout(config.torizon.http_timeout);

        Ok(RasClient {
            http_client: cb.build()?,
            config,
        })
    }

    pub fn with_tls(config: RacConfig) -> Result<Self> {
        let mut cb = reqwest::Client::builder();

        let server_cert_bytes = std::fs::read(&config.torizon.server_cert_path).wrap_err(
            format!("Could not read {:?}", &config.torizon.server_cert_path),
        )?;

        let server_cert = reqwest::Certificate::from_pem(&server_cert_bytes)?;

        let mut client_cert = std::fs::read(&config.torizon.client_cert_path).context(format!(
            "Could not read {:?}",
            &config.torizon.client_cert_path
        ))?;

        let mut client_key = std::fs::read(&config.torizon.client_key_path).context(format!(
            "Could not read {:?}",
            &config.torizon.client_key_path
        ))?;

        client_cert.append(&mut client_key);

        let identity = reqwest::Identity::from_pem(&client_cert)?;

        cb = cb.add_root_certificate(server_cert);
        cb = cb.identity(identity);
        cb = cb.user_agent(Self::user_agent());
        cb = cb.timeout(config.torizon.http_timeout);

        Ok(RasClient {
            http_client: cb.build()?,
            config,
        })
    }

    fn user_agent() -> String {
        format!(
            "RAC/{} {} {} rustc-{}-{}",
            env!("VERGEN_GIT_SEMVER"),
            env!("VERGEN_GIT_SHA_SHORT"),
            env!("VERGEN_BUILD_TIMESTAMP"),
            env!("VERGEN_RUSTC_SEMVER"),
            env!("VERGEN_CARGO_TARGET_TRIPLE"),
        )
    }

    fn http_request<U: IntoUrl>(&self, method: reqwest::Method, url: U) -> reqwest::RequestBuilder {
        let mut req = self.http_client.request(method, url);

        if let Some(ref ns) = self.config.torizon.namespace {
            debug!("Setting namespace to {}", ns);
            req = req.header("x-ats-namespace", ns.to_string());
        }

        req
    }

    pub async fn add_device_pubkey(&self, pub_key: &ssh_key::PublicKey) -> Result<()> {
        let url = self.config.torizon.url.join("public-keys")?;
        let mut req = self.http_request(reqwest::Method::POST, url);

        info!(
            "Adding device public key to ras: {}",
            pub_key.fingerprint(ssh_key::HashAlg::default()),
        );

        let keys = DeviceKey {
            key: pub_key.clone(),
        };

        req = req.json(&keys);

        let resp = req.send().await?;

        if !resp.status().is_success() {
            error!("resp: {:?}", resp);
            let body = resp.text().await.unwrap_or(String::new());
            bail!("Could not add device keys to server {}", body)
        }

        Ok(())
    }

    pub async fn get_session(&self) -> Result<Option<DeviceSession>> {
        let url = self.config.torizon.url.join("sessions")?;
        let req = self.http_request(reqwest::Method::GET, url);
        let response = req.send().await?;

        if response.status() == StatusCode::NOT_FOUND {
            info!("No remote session found for device");
            return Ok(None);
        }

        if !response.status().is_success() {
            bail!("Could not get device sessions: {:?}", response);
        }

        let payload = response.json::<DeviceSession>().await?;

        Ok(Some(payload))
    }
}
