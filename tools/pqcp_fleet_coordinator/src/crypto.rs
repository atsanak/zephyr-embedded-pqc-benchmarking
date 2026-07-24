// SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use argon2::Argon2;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use pqcrypto_mldsa::mldsa65::{
    detached_sign_ctx, keypair, verify_detached_signature_ctx, DetachedSignature, PublicKey,
    SecretKey,
};
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
    SecretKey as SecretKeyTrait,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize)]
struct KeyFile {
    schema_version: u32,
    algorithm: String,
    public_key_b64: String,
    kdf: String,
    salt_b64: String,
    nonce_b64: String,
    encrypted_secret_key_b64: String,
}

#[derive(Clone)]
pub struct FleetSigner {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    fingerprint: [u8; 32],
}

impl FleetSigner {
    #[cfg(test)]
    pub(crate) fn generate_for_test() -> Self {
        let (public_key, secret_key) = keypair();
        Self::from_bytes(
            public_key.as_bytes().to_vec(),
            secret_key.as_bytes().to_vec(),
        )
        .expect("generated ML-DSA-65 keypair must be valid")
    }

    pub fn load_or_generate(path: &Path, force: bool) -> Result<Self> {
        if path.exists() && !force {
            return Self::load(path);
        }
        if path.exists() && force {
            fs::remove_file(path)
                .with_context(|| format!("remove existing key {}", path.display()))?;
        }
        let (public_key, secret_key) = keypair();
        let signer = Self::from_bytes(
            public_key.as_bytes().to_vec(),
            secret_key.as_bytes().to_vec(),
        )?;
        signer.store(path)?;
        Ok(signer)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let encoded =
            fs::read(path).with_context(|| format!("read signing key {}", path.display()))?;
        let key_file: KeyFile =
            serde_json::from_slice(&encoded).context("parse signing key file")?;
        if key_file.schema_version != 2
            || key_file.algorithm != "ML-DSA-65"
            || key_file.kdf != "Argon2id"
        {
            bail!("unsupported signing key format");
        }
        let public_key = STANDARD.decode(key_file.public_key_b64)?;
        let salt = STANDARD.decode(key_file.salt_b64)?;
        let nonce = STANDARD.decode(key_file.nonce_b64)?;
        if salt.len() != 16 || nonce.len() != 24 {
            bail!("invalid encrypted signing key parameters");
        }
        let encrypted_secret = STANDARD.decode(key_file.encrypted_secret_key_b64)?;
        let mut encryption_key = derive_encryption_key(&salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&encryption_key));
        let secret_key = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &encrypted_secret,
                    aad: &public_key,
                },
            )
            .map_err(|_| anyhow::anyhow!("signing key passphrase rejected"))?;
        encryption_key.zeroize();
        Self::from_bytes(public_key, secret_key)
    }

    fn from_bytes(public_key: Vec<u8>, secret_key: Vec<u8>) -> Result<Self> {
        PublicKey::from_bytes(&public_key).context("invalid ML-DSA-65 public key")?;
        SecretKey::from_bytes(&secret_key).context("invalid ML-DSA-65 secret key")?;
        let digest = Sha256::digest(&public_key);
        let mut fingerprint = [0_u8; 32];
        fingerprint.copy_from_slice(&digest);
        Ok(Self {
            public_key,
            secret_key,
            fingerprint,
        })
    }

    fn store(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .with_context(|| format!("create key directory {}", parent.display()))?;
        }
        let mut salt = [0_u8; 16];
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut salt)
            .map_err(|error| anyhow::anyhow!("generate signing key salt: {error}"))?;
        getrandom::fill(&mut nonce)
            .map_err(|error| anyhow::anyhow!("generate signing key nonce: {error}"))?;
        let mut encryption_key = derive_encryption_key(&salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&encryption_key));
        let encrypted_secret = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &self.secret_key,
                    aad: &self.public_key,
                },
            )
            .map_err(|_| anyhow::anyhow!("encrypt signing key"))?;
        encryption_key.zeroize();
        let key_file = KeyFile {
            schema_version: 2,
            algorithm: "ML-DSA-65".to_owned(),
            public_key_b64: STANDARD.encode(&self.public_key),
            kdf: "Argon2id".to_owned(),
            salt_b64: STANDARD.encode(salt),
            nonce_b64: STANDARD.encode(nonce),
            encrypted_secret_key_b64: STANDARD.encode(encrypted_secret),
        };
        let encoded = serde_json::to_vec_pretty(&key_file)?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, encoded)
            .with_context(|| format!("write temporary key {}", temporary.display()))?;
        set_private_permissions(&temporary)?;
        fs::rename(&temporary, path)
            .with_context(|| format!("install signing key {}", path.display()))?;
        Ok(())
    }

    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<Vec<u8>> {
        let secret = SecretKey::from_bytes(&self.secret_key).context("load secret key")?;
        Ok(detached_sign_ctx(message, context, &secret)
            .as_bytes()
            .to_vec())
    }

    pub fn verify(&self, message: &[u8], context: &[u8], signature: &[u8]) -> Result<()> {
        let public = PublicKey::from_bytes(&self.public_key).context("load public key")?;
        let signature =
            DetachedSignature::from_bytes(signature).context("load detached signature")?;
        verify_detached_signature_ctx(&signature, message, context, &public)
            .map_err(|_| anyhow::anyhow!("ML-DSA-65 signature rejected"))
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }
}

fn derive_encryption_key(salt: &[u8]) -> Result<[u8; 32]> {
    let mut passphrase = std::env::var("PQCP_FLEET_KEY_PASSPHRASE")
        .context("PQCP_FLEET_KEY_PASSPHRASE is required for the encrypted root key")?;
    if passphrase.len() < 12 {
        passphrase.zeroize();
        bail!("PQCP_FLEET_KEY_PASSPHRASE must contain at least 12 characters");
    }
    let mut output = [0_u8; 32];
    let result = Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .map_err(|error| anyhow::anyhow!("derive root-key encryption key: {error}"));
    passphrase.zeroize();
    result?;
    Ok(output)
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("protect signing key {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
