// SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::cbor::{signed_credential, signed_voucher, verify_enrollment_request};
use crate::crypto::FleetSigner;
use crate::db::Database;
use crate::model::{DeviceEnrollment, EnrollmentResponse};

const MLDSA65_PUBLIC_KEY_BYTES: usize = 1952;
const MLDSA65_CAPABILITY_BIT: u32 = 1 << 1;

pub fn issue_enrollment(
    database: &Database,
    signer: &FleetSigner,
    domain: &str,
    request_cbor: &[u8],
    now_ms: u64,
) -> Result<EnrollmentResponse> {
    let enrollment = verify_enrollment_request(request_cbor, now_ms)?;
    validate_enrollment(&enrollment)?;
    if enrollment.domain_id != domain {
        bail!("enrollment request targets another policy domain");
    }
    database.verify_factory_admission(&enrollment)?;

    // Signing precedes inventory mutation. A provider failure can consume a
    // sequence number, but it cannot leave an enrolled device without its
    // voucher and credential.
    let first_sequence = database.allocate_artifact_sequences(2)?;
    let voucher = signed_voucher(
        signer,
        domain,
        &enrollment,
        first_sequence,
        now_ms,
        now_ms.saturating_add(300_000),
    )?;
    let credential = signed_credential(
        signer,
        domain,
        &enrollment,
        first_sequence.saturating_add(1),
        now_ms,
        now_ms.saturating_add(86_400_000),
    )?;
    let device = database.enroll_device(&enrollment, now_ms)?;

    Ok(EnrollmentResponse {
        device,
        voucher_cbor_b64: STANDARD.encode(voucher),
        credential_cbor_b64: STANDARD.encode(credential),
        root_public_key_b64: STANDARD.encode(signer.public_key()),
        root_fingerprint_hex: signer.fingerprint_hex(),
    })
}

fn validate_enrollment(enrollment: &DeviceEnrollment) -> Result<()> {
    validate_identifier(&enrollment.device_id, 48, "device_id")?;
    validate_identifier(&enrollment.product_class, 32, "product_class")?;
    if enrollment.firmware_version.is_empty() || enrollment.firmware_version.len() >= 24 {
        bail!("firmware_version must contain 1..23 characters");
    }
    if enrollment.boot_counter == 0 {
        bail!("boot_counter must be non-zero");
    }
    if enrollment.supported_mlkem_mask == 0
        || enrollment.supported_mldsa_mask & MLDSA65_CAPABILITY_BIT == 0
    {
        bail!("device must advertise ML-KEM and ML-DSA-65 support");
    }
    let public_key = STANDARD
        .decode(&enrollment.factory_public_key_b64)
        .context("factory_public_key_b64 is not valid base64")?;
    if public_key.len() != MLDSA65_PUBLIC_KEY_BYTES {
        bail!("factory public key is not an ML-DSA-65 public key");
    }
    let fingerprint = hex::encode(Sha256::digest(&public_key));
    if fingerprint != enrollment.factory_fingerprint_hex.to_ascii_lowercase() {
        bail!("factory key fingerprint mismatch");
    }
    let operational_key = STANDARD
        .decode(&enrollment.operational_public_key_b64)
        .context("operational_public_key_b64 is not valid base64")?;
    if operational_key.len() != MLDSA65_PUBLIC_KEY_BYTES {
        bail!("operational public key is not an ML-DSA-65 public key");
    }
    if hex::decode(&enrollment.hardware_id_digest_hex)?.len() != 32 {
        bail!("hardware identity digest must contain 32 bytes");
    }
    Ok(())
}

fn validate_identifier(value: &str, capacity: usize, field: &str) -> Result<()> {
    if value.is_empty() || value.len() >= capacity {
        bail!("{field} must contain 1..{} characters", capacity - 1);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("{field} contains unsupported characters");
    }
    Ok(())
}
