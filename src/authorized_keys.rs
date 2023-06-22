// Copyright 2023 Toradex A.G.
// SPDX-License-Identifier: Apache-2.0

use crate::Result;
use color_eyre::eyre::eyre;
use color_eyre::eyre::Context;
use log::*;
use ssh_key::PublicKey;
use std::path::Path;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncSeekExt;
use tokio::io::AsyncWriteExt;

pub async fn update_keys(authorized_keys: impl AsRef<Path>, new_keys: &[PublicKey]) -> Result<()> {
    debug!("updating local device authorized keys");
    let path = authorized_keys.as_ref();

    let mut file = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o644)
        .open(path)
        .await
        .wrap_err("opening authorized keys file")?;

    let mut new_file = Vec::<u8>::new();

    let mut lines = tokio::io::BufReader::new(&mut file).lines();

    while let Some(key) = lines.next_line().await? {
        if !key.contains("added by rac") {
            new_file.write_all(key.as_bytes()).await?;
            new_file.write_all("\n".as_bytes()).await?;
        }
    }

    file.set_len(0).await?;
    file.rewind().await?;
    file.write_all(&new_file).await?;

    for k in new_keys {
        let mut k = k.clone();

        k.set_comment(format!(
            "{}{}added by rac on {}",
            k.comment(),
            if k.comment().is_empty() { "" } else { " " },
            chrono::Local::now()
        ));
        let encoded_key = k.to_openssh().map_err(|err| eyre!("{err:?}"))?;
        file.write_all(encoded_key.as_bytes()).await?;
        file.write_all("\n".as_bytes()).await?;
    }

    file.flush().await?;

    Ok(())
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use pretty_assertions::assert_eq;
    use ssh_key::{rand_core::OsRng, PublicKey};
    use std::fs::File;
    use std::io::BufRead;
    use std::io::Read;
    use std::io::Write;

    fn read_all_keys<R: Read>(file: R) -> Vec<PublicKey> {
        std::io::BufReader::new(file)
            .lines()
            .flatten()
            .flat_map(|l| l.parse())
            .collect()
    }

    fn new_key() -> PublicKey {
        ssh_key::PrivateKey::random(OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    use crate::test::setup;

    #[tokio::test]
    async fn test_updates_empty_keys() {
        setup();

        let mut file = tempfile::NamedTempFile::new().unwrap();
        let existing_key = new_key();

        file.write_all(existing_key.to_openssh().unwrap().as_bytes())
            .unwrap();
        file.as_file().flush().unwrap();

        update_keys(&file.path(), &[]).await.unwrap();

        let file = file.reopen().unwrap();

        let mut new_keys = read_all_keys(&file);
        let e = new_keys.pop().unwrap();

        assert_eq!(e, existing_key);
    }

    #[tokio::test]
    async fn test_removes_rac_keys() {
        setup();

        let mut file = tempfile::NamedTempFile::new().unwrap();

        let mut existing_key = new_key();
        existing_key.set_comment("added by rac");

        file.write_all(existing_key.to_openssh().unwrap().as_bytes())
            .unwrap();
        file.flush().unwrap();

        update_keys(&file.path(), &[]).await.unwrap();

        let file = file.reopen().unwrap();

        let new_keys = read_all_keys(&file);
        assert_eq!(new_keys.len(), 0);
    }

    #[tokio::test]
    async fn test_preserves_key_comments() {
        setup();

        let file = tempfile::NamedTempFile::new().unwrap();

        let mut new_key = new_key();
        new_key.set_comment("my comment");

        update_keys(&file.path(), &[new_key]).await.unwrap();

        let keys = read_all_keys(&file);

        let comment = keys.first().unwrap().comment();

        assert!(comment.contains("my comment added by rac"));
    }

    #[tokio::test]
    async fn test_creates_file_if_misssing() {
        setup();

        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_owned();
        file.close().unwrap();

        let new_key = new_key();
        update_keys(&path, &[new_key.clone()]).await.unwrap();

        let file = File::open(&path).unwrap();
        let mut keys = read_all_keys(&file);

        assert_eq!(keys.pop().unwrap().key_data(), new_key.key_data());
    }
}
