// Copyright 2023 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

use std::io::Cursor;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use crate::data_type::RacConfig;
use crate::data_type::*;
use crate::RemoteSessionsMetadata;
use crate::Result;
use bytes::Buf;
use bytes::Bytes;
use color_eyre::eyre::{self, Context};
use eyre::bail;
use eyre::eyre;

use log::*;
use reqwest::header::HeaderValue;
use reqwest::StatusCode;
use std::io::Read;
use tokio::io::AsyncReadExt;
use url::Url;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone)]
pub struct TorizonClient {
    http_client: reqwest::Client,
    config: RacConfig,
}

impl TorizonClient {
    #[must_use]
    pub fn new(config: RacConfig, http_client: reqwest::Client) -> Self {
        Self {
            http_client,
            config,
        }
    }

    pub async fn add_device_pubkey(&self, pub_key: &ssh_key::PublicKey) -> Result<()> {
        let url = self.config.torizon.url.join("public-keys")?;
        let mut req = self.http_client.request(reqwest::Method::POST, url);

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
        let req = self.http_client.request(reqwest::Method::GET, url);
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

    pub async fn fetch_latest_root(&self) -> Result<Bytes> {
        let url = self.director_url().join("root.json")?;

        let req = self.http_client.request(reqwest::Method::GET, url);
        let response = req.send().await?;

        if !response.status().is_success() {
            bail!("Could not get device root.json: {:?}", response);
        }

        let payload = response.bytes().await?;

        Ok(payload)
    }

    pub async fn fetch_verified_remote_sessions(&self) -> Result<RemoteSessionsMetadata> {
        let loader = UptaneRepositoryLoader::new(
            self.clone(),
            self.http_client.clone(),
            self.director_url(),
            self.config.device.local_tuf_repo_path.clone(),
        );

        let remote_sessions_json = loader.load_remote_sessions().await?;
        let remote_sessions = serde_json::from_value(remote_sessions_json)?;

        Ok(remote_sessions)
    }

    fn director_url(&self) -> Url {
        self.config.torizon.director_url.clone().unwrap_or({
            let mut url = self.config.torizon.url.clone();
            url.set_path("/director/");
            url
        })
    }
}

pub fn tls_http_client(config: &RacConfig) -> Result<reqwest::Client> {
    let mut cb = reqwest::Client::builder();

    let server_cert_bytes = std::fs::read(&config.torizon.server_cert_path).wrap_err(format!(
        "Could not read {:?}",
        &config.torizon.server_cert_path
    ))?;

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
    cb = cb.user_agent(user_agent());
    cb = cb.timeout(config.torizon.http_timeout);

    Ok(cb.build()?)
}

pub fn notls_http_client(config: &RacConfig) -> Result<reqwest::Client> {
    let mut cb = reqwest::Client::builder();

    cb = cb.user_agent(user_agent());
    cb = cb.timeout(config.torizon.http_timeout);

    if let Some(ref ns) = config.torizon.namespace {
        debug!("Setting namespace to {}", ns);
        let mut header_map = reqwest::header::HeaderMap::new();
        header_map.insert("x-ats-namespace", HeaderValue::from_str(&ns.to_string())?);
        cb = cb.default_headers(header_map);
    }

    Ok(cb.build()?)
}

fn user_agent() -> String {
    format!(
        "RAC/{} ({}; {}; rustc-{}-{})",
        env!("VERGEN_GIT_SEMVER"),
        env!("VERGEN_GIT_SHA_SHORT"),
        env!("VERGEN_BUILD_TIMESTAMP"),
        env!("VERGEN_RUSTC_SEMVER"),
        env!("VERGEN_CARGO_TARGET_TRIPLE"),
    )
}

#[derive(Debug, Clone)]
struct TorizonToughTransport {
    http: reqwest::Client,
    rt: tokio::runtime::Handle,
}

impl TorizonToughTransport {
    fn new(http: reqwest::Client, rt: tokio::runtime::Handle) -> Self {
        Self { http, rt }
    }
}

impl tough::Transport for TorizonToughTransport {
    fn fetch(
        &self,
        url: url::Url,
    ) -> std::result::Result<Box<dyn Read + Send>, tough::TransportError> {
        let request = self
            .http
            .request(reqwest::Method::GET, url.clone())
            .build()
            .map_err(|err| {
                tough::TransportError::new_with_cause(
                    tough::TransportErrorKind::Other,
                    url.clone(),
                    err,
                )
            })?;

        let response_bytes = self.rt.block_on(async {
            let resp = self.http.execute(request).await.map_err(|err| {
                tough::TransportError::new_with_cause(
                    tough::TransportErrorKind::Other,
                    url.clone(),
                    err,
                )
            })?;

            if resp.status() == reqwest::StatusCode::NOT_FOUND
                || resp.status() == reqwest::StatusCode::FAILED_DEPENDENCY
            {
                Err(tough::TransportError::new(
                    tough::TransportErrorKind::FileNotFound,
                    url,
                ))
            } else if resp.status().is_success() {
                resp.bytes().await.map_err(|err| {
                    tough::TransportError::new_with_cause(
                        tough::TransportErrorKind::Other,
                        url,
                        err,
                    )
                })
            } else {
                #[allow(clippy::unwrap_used)]
                Err(tough::TransportError::new_with_cause(
                    tough::TransportErrorKind::Other,
                    url,
                    resp.error_for_status()
                        .expect_err("expected error response"),
                ))
            }
        });

        Ok(Box::new(response_bytes?.reader()))
    }
}

#[derive(Debug)]
pub struct UptaneRepositoryLoader {
    local_repo_path: PathBuf,
    repository_url: Url,
    torizon_client: TorizonClient,
    http_client: reqwest::Client,
}

impl UptaneRepositoryLoader {
    #[must_use]
    pub fn new(
        torizon_client: TorizonClient,
        http_client: reqwest::Client,
        director_url: Url,
        local_repo_path: PathBuf,
    ) -> Self {
        Self {
            local_repo_path,
            repository_url: director_url,
            torizon_client,
            http_client,
        }
    }

    /// Get a trusted root for this repository
    ///
    /// If a root.json is available on the local filesystem, use that root, otherwise, download
    /// the latest root.json directly using `TorizonClient`, and use that as a trusted root.
    ///
    /// This is Trust on First Use. Once we save root.json on the local filessytem, subsequent
    /// usages will use that root.json to verify rotations to the latest version
    async fn load_trusted_root<P: AsRef<Path>>(
        local_tuf_path: P,
        torizon_client: &TorizonClient,
    ) -> Result<Box<dyn Read + Send>> {
        let local_root = local_tuf_path.as_ref().join("root.json");

        let r: Box<dyn Read + Send> = match tokio::fs::File::open(&local_root)
            .await
            .context(format!("{}", &local_root.to_string_lossy()))
        {
            Ok(mut f) => {
                debug!("read trusted root.json from local repository");
                let mut buf = Vec::new();
                f.read_to_end(&mut buf).await?;
                Box::new(Cursor::new(buf))
            }
            Err(err) => {
                debug!(
                    "Could not load local root.json {err}. Will fetch trusted root from the server"
                );
                trace!("Error when reading root.json: {err:?}");
                let fetched_root = torizon_client.fetch_latest_root().await?;

                if let Err(err) =
                    std::fs::File::create(&local_root).and_then(|mut f| f.write_all(&fetched_root))
                {
                    warn!("could not save latest root to local cache: {}", err);
                } else {
                    info!("saved trusted root to {}", &local_root.to_string_lossy());
                }

                Box::new(fetched_root.reader())
            }
        };

        Ok(r)
    }

    pub async fn load_remote_sessions(&self) -> Result<serde_json::Value> {
        let trusted_root =
            Self::load_trusted_root(&self.local_repo_path, &self.torizon_client).await?;

        let mut repository_loader = tough::RepositoryLoader::new(
            trusted_root,
            self.repository_url.clone(),
            self.repository_url.clone(),
        );

        repository_loader = repository_loader.transport(TorizonToughTransport::new(
            self.http_client.clone(),
            tokio::runtime::Handle::current(),
        ));
        repository_loader = repository_loader.datastore(&self.local_repo_path);

        // tough runs reqwest::blocking, so we need to tell tokio runtime that this is going to block
        let repo = tokio::task::spawn_blocking(|| repository_loader.load_uptane()).await??;

        let remote_sessions = repo
            .remote_sessions()
            .map_err(|err| eyre!("could not get remote-sessions: {}", err))?
            .signed
            .remote_sessions
            .clone();

        Ok(remote_sessions)
    }
}

#[allow(clippy::unwrap_used)]
#[test]
fn validates_remote_sessions_rsa() {
    let trusted_root = std::fs::File::open("tests/data/root-rsa.json").unwrap();

    let repository_url = Url::parse(&format!(
        "file://{}/{}",
        env!("CARGO_MANIFEST_DIR"),
        "tests/data/"
    ))
    .unwrap();

    let mut repository_loader =
        tough::RepositoryLoader::new(trusted_root, repository_url.clone(), repository_url);

    repository_loader = repository_loader.transport(tough::FilesystemTransport);

    let repo = repository_loader.load_uptane().unwrap();

    assert!(repo
        .remote_sessions()
        .unwrap()
        .signed
        .remote_sessions
        .is_object())
}

#[allow(clippy::unwrap_used)]
#[test]
fn validates_remote_sessions_unknown_roles() {
    let trusted_root = std::fs::File::open("tests/data/root-offline-updates.json").unwrap();

    let repository_url = Url::parse(&format!(
        "file://{}/{}",
        env!("CARGO_MANIFEST_DIR"),
        "tests/data/"
    ))
    .unwrap();

    let mut repository_loader =
        tough::RepositoryLoader::new(trusted_root, repository_url.clone(), repository_url);

    repository_loader = repository_loader.transport(tough::FilesystemTransport);

    repository_loader.load_uptane().unwrap();
}

#[allow(clippy::unwrap_used)]
#[test]
fn validates_root_unknown_roles() {
    let trusted_root = std::fs::File::open("tests/data/root-offline-updates-only.json").unwrap();

    let repository_url = Url::parse(&format!(
        "file://{}/{}",
        env!("CARGO_MANIFEST_DIR"),
        "tests/data/"
    ))
    .unwrap();

    let mut repository_loader =
        tough::RepositoryLoader::new(trusted_root, repository_url.clone(), repository_url);

    repository_loader = repository_loader.transport(tough::FilesystemTransport);

    let repo = repository_loader.load_uptane().unwrap();

    assert_eq!(
        repo.remote_sessions().err().unwrap(),
        "remote-sessions not set in root.json"
    )
}
