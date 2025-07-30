// Copyright 2023 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use tokio::io::AsyncWriteExt;
use tough::schema::RemoteSessions;

use crate::data_type::RacConfig;
use crate::data_type::*;
use crate::Result;
use bytes::Bytes;
use color_eyre::eyre::{self, Context};
use eyre::bail;
use eyre::eyre;

use async_trait::async_trait;
use futures::Stream;
use futures::StreamExt;
use log::*;
use reqwest::header::HeaderValue;
use reqwest::StatusCode;
use serde::Deserialize;
use serde::Serialize;
use tokio::io::AsyncReadExt;
use url::Url;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone)]
pub struct TorizonClient {
    pub(crate) http_client: reqwest::Client,
    pub(crate) config: RacConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RasError {
    code: String,
    description: String,
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

    pub async fn get_commands(&self) -> Result<CommandsResponse> {
        let url = self.config.torizon.url.join("commands")?;
        let req = self.http_client.request(reqwest::Method::GET, url);
        let response = req.send().await?;

        if !response.status().is_success() {
            bail!("Could not get device remote commands: {:?}", response);
        }

        let payload = response.json::<CommandsResponse>().await?;

        Ok(payload)
    }

    pub async fn send_command_result(
        &self,
        cmd_id: &CommandId,
        result: &CommandResult,
    ) -> Result<()> {
        let url = self
            .config
            .torizon
            .url
            .join(&format!("commands/{cmd_id}/result"))?;
        let req = self
            .http_client
            .request(reqwest::Method::POST, url)
            .json(result);
        let response = req.send().await?;

        if !response.status().is_success() {
            if response.status() == StatusCode::BAD_REQUEST {
                let response_body = response.text().await.unwrap_or_default();

                if let Ok(ras_err) = serde_json::from_str::<RasError>(&response_body) {
                    if ras_err.code == "command_not_found" {
                        debug!(
                            "command {} not found in server. report already sent?",
                            cmd_id
                        );
                        return Ok(());
                    }
                    bail!("RAS error: {}", ras_err.description);
                } else {
                    bail!("Invalid BAD_REQUEST response: {}", response_body);
                }
            }

            let text = response.text().await.unwrap_or_default();
            bail!("Could not send command result: {}", text);
        }

        Ok(())
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

    pub(crate) fn director_url(&self) -> Url {
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

    if let Some(ns) = config.torizon.namespace {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-ats-namespace",
            reqwest::header::HeaderValue::from_str(&ns.to_string())?,
        );
        cb = cb.default_headers(headers);
    }

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

#[must_use]
pub fn user_agent() -> String {
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
}

impl TorizonToughTransport {
    fn new(http: reqwest::Client) -> Self {
        Self { http }
    }
}

#[async_trait]
impl tough::Transport for TorizonToughTransport {
    async fn fetch(
        &self,
        url: url::Url,
    ) -> std::result::Result<
        Pin<Box<dyn Stream<Item = std::result::Result<Bytes, tough::TransportError>> + Send>>,
        tough::TransportError,
    > {
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
            let bytes_stream = resp.bytes_stream().map(move |item| {
                item.map_err(|err| {
                    tough::TransportError::new_with_cause(
                        tough::TransportErrorKind::Other,
                        url.clone(),
                        err,
                    )
                })
            });

            Ok(bytes_stream.boxed())
        } else {
            #[allow(clippy::unwrap_used)]
            Err(tough::TransportError::new_with_cause(
                tough::TransportErrorKind::Other,
                url,
                resp.error_for_status()
                    .expect_err("expected error response"),
            ))
        }
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
    ) -> Result<Bytes> {
        let local_root = local_tuf_path.as_ref().join("root.json");

        let r = match tokio::fs::File::open(&local_root)
            .await
            .context(format!("{}", &local_root.to_string_lossy()))
        {
            Ok(mut f) => {
                debug!("read trusted root.json from local repository");
                let mut buf = Vec::new();
                f.read_to_end(&mut buf).await?;
                Bytes::from(buf)
            }
            Err(err) => {
                debug!(
                    "Could not load local root.json {err}. Will fetch trusted root from the server"
                );
                trace!("Error when reading root.json: {err:?}");
                let fetched_root = torizon_client.fetch_latest_root().await?;

                let res = async {
                    let mut f = tokio::fs::File::create(&local_root).await?;
                    f.write_all(&fetched_root).await
                };

                if let Err(err) = res.await {
                    warn!("could not save latest root to local cache: {}", err);
                } else {
                    info!("saved trusted root to {}", &local_root.to_string_lossy());
                }

                fetched_root
            }
        };

        Ok(r)
    }

    pub async fn load_remote_sessions(&self) -> Result<RemoteSessions> {
        let trusted_root =
            Self::load_trusted_root(&self.local_repo_path, &self.torizon_client).await?;

        let mut repository_loader = tough::RepositoryLoader::new(
            &trusted_root,
            self.repository_url.clone(),
            self.repository_url.clone(),
        );

        repository_loader =
            repository_loader.transport(TorizonToughTransport::new(self.http_client.clone()));
        repository_loader = repository_loader.datastore(&self.local_repo_path);

        let repo = repository_loader.load_uptane().await?;

        let remote_sessions = repo
            .remote_sessions()
            .map_err(|err| eyre!("could not get remote-sessions: {}", err))?
            .signed
            .clone();

        Ok(remote_sessions)
    }
}

pub trait UptaneMetadataProvider: std::fmt::Debug {
    #[allow(async_fn_in_trait)]
    async fn fetch_verified_remote_sessions(&self) -> Result<RemoteSessions>;
}

impl UptaneMetadataProvider for TorizonClient {
    async fn fetch_verified_remote_sessions(&self) -> Result<RemoteSessions> {
        let loader = crate::UptaneRepositoryLoader::new(
            self.clone(),
            self.http_client.clone(),
            self.director_url(),
            self.config.device.local_tuf_repo_path.clone(),
        );

        let remote_sessions = loader.load_remote_sessions().await?;

        Ok(remote_sessions)
    }
}

#[cfg(test)]
use std::io::Read;

#[allow(clippy::unwrap_used)]
#[tokio::test]
async fn validates_remote_sessions_rsa() {
    let mut trusted_root = Vec::new();
    std::fs::File::open("tests/data/root-rsa.json")
        .unwrap()
        .read_to_end(&mut trusted_root)
        .unwrap();

    let repository_url = Url::parse(&format!(
        "file://{}/{}",
        env!("CARGO_MANIFEST_DIR"),
        "tests/data/"
    ))
    .unwrap();

    let mut repository_loader =
        tough::RepositoryLoader::new(&trusted_root, repository_url.clone(), repository_url);

    repository_loader = repository_loader.transport(tough::FilesystemTransport);

    let repo = repository_loader.load_uptane().await.unwrap();

    assert!(repo
        .remote_sessions()
        .unwrap()
        .signed
        .remote_sessions
        .is_object());
}

#[allow(clippy::unwrap_used)]
#[tokio::test]
async fn validates_remote_sessions_unknown_roles() {
    let mut trusted_root = Vec::new();
    std::fs::File::open("tests/data/root-offline-updates.json")
        .unwrap()
        .read_to_end(&mut trusted_root)
        .unwrap();

    let repository_url = Url::parse(&format!(
        "file://{}/{}",
        env!("CARGO_MANIFEST_DIR"),
        "tests/data/"
    ))
    .unwrap();

    let mut repository_loader =
        tough::RepositoryLoader::new(&trusted_root, repository_url.clone(), repository_url);

    repository_loader = repository_loader.transport(tough::FilesystemTransport);

    repository_loader.load_uptane().await.unwrap();
}

#[allow(clippy::unwrap_used)]
#[tokio::test]
async fn validates_root_unknown_roles() {
    let mut trusted_root = Vec::new();
    std::fs::File::open("tests/data/root-offline-updates-only.json")
        .unwrap()
        .read_to_end(&mut trusted_root)
        .unwrap();

    let repository_url = Url::parse(&format!(
        "file://{}/{}",
        env!("CARGO_MANIFEST_DIR"),
        "tests/data/"
    ))
    .unwrap();

    let mut repository_loader =
        tough::RepositoryLoader::new(&trusted_root, repository_url.clone(), repository_url);

    repository_loader = repository_loader.transport(tough::FilesystemTransport);

    let repo = repository_loader.load_uptane().await.unwrap();

    assert_eq!(
        repo.remote_sessions().err().unwrap(),
        "remote-sessions not set in root.json"
    );
}
