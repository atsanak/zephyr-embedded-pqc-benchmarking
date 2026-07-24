// SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

use std::io::Cursor;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ciborium::value::{Integer, Value};
use pqcrypto_mldsa::mldsa65::{verify_detached_signature_ctx, DetachedSignature, PublicKey};
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto::FleetSigner;
use crate::model::{DeviceEnrollment, Policy, Revocation};

const SCHEMA_VERSION: u64 = 1;
const PROTOCOL_VERSION: u64 = 1;
const ENROLLMENT_KIND: u64 = 1;
const VOUCHER_KIND: u64 = 2;
const CREDENTIAL_KIND: u64 = 3;
const POLICY_KIND: u64 = 4;
const REVOCATION_KIND: u64 = 5;
const MLDSA65_PUBLIC_KEY_BYTES: usize = 1952;
const MLDSA65_SIGNATURE_BYTES: usize = 3309;
const DIGEST_BYTES: usize = 32;
const SIGNATURE_CONTEXT: &[u8] = b"PQCP-FLEET-CBOR-V1";
const KNOWN_MLKEM_MASK: u32 = (1 << 0) | (1 << 1) | (1 << 2);
const KNOWN_MLDSA_MASK: u32 = (1 << 0) | (1 << 1) | (1 << 2);
const KNOWN_CAPABILITY_MASK: u32 = (1 << 8) - 1;

pub fn verify_enrollment_request(input: &[u8], now_ms: u64) -> Result<DeviceEnrollment> {
    let value: Value =
        ciborium::de::from_reader(Cursor::new(input)).context("decode fleet enrollment CBOR")?;
    if encode_value(&value)? != input {
        bail!("enrollment request is not in canonical array encoding");
    }
    let top = array(&value, 2, "top-level enrollment")?;
    let envelope = array(&top[0], 12, "enrollment envelope")?;
    let payload = array(&top[1], 14, "enrollment payload")?;
    if unsigned(&envelope[0])? != SCHEMA_VERSION
        || unsigned(&envelope[1])? != PROTOCOL_VERSION
        || unsigned(&envelope[2])? != ENROLLMENT_KIND
    {
        bail!("unsupported enrollment protocol or message type");
    }
    let message_id = unsigned(&envelope[3])?;
    let sequence = unsigned(&envelope[4])?;
    let policy_epoch = unsigned(&envelope[5])?;
    let revocation_epoch = unsigned(&envelope[6])?;
    let issued_at_ms = unsigned(&envelope[7])?;
    let expires_at_ms = unsigned(&envelope[8])?;
    let nonce = bytes_exact(&envelope[9], DIGEST_BYTES, "nonce")?;
    let device_id = text(&envelope[10], 48, "device_id")?;
    let domain_id = text(&envelope[11], 48, "domain_id")?;
    if message_id == 0 || sequence == 0 || issued_at_ms == 0 || expires_at_ms <= issued_at_ms {
        bail!("invalid enrollment envelope counters or lifetime");
    }
    if now_ms != 0 && (expires_at_ms <= now_ms || issued_at_ms > now_ms.saturating_add(60_000)) {
        bail!("enrollment request is expired or issued too far in the future");
    }

    let stage = unsigned(&payload[0])?;
    let boot_counter = unsigned(&payload[1])?;
    let enrollment_counter = unsigned(&payload[2])?;
    let supported_mlkem_mask = u32_value(&payload[3], "supported_mlkem_mask")?;
    let supported_mldsa_mask = u32_value(&payload[4], "supported_mldsa_mask")?;
    let capabilities = u32_value(&payload[5], "capabilities")?;
    let firmware_version = text(&payload[6], 24, "firmware_version")?;
    let product_class = text(&payload[7], 32, "product_class")?;
    let factory_public_key =
        bytes_exact(&payload[8], MLDSA65_PUBLIC_KEY_BYTES, "factory_public_key")?;
    let factory_fingerprint = bytes_exact(&payload[9], DIGEST_BYTES, "factory_fingerprint")?;
    let hardware_id_digest = bytes_exact(&payload[10], DIGEST_BYTES, "hardware_id_digest")?;
    let operational_public_key = bytes_exact(
        &payload[11],
        MLDSA65_PUBLIC_KEY_BYTES,
        "operational_public_key",
    )?;
    let operational_present = boolean(&payload[12], "operational_key_present")?;
    let signature = bytes_exact(&payload[13], MLDSA65_SIGNATURE_BYTES, "signature")?;
    if !(1..=3).contains(&stage)
        || boot_counter == 0
        || enrollment_counter == 0
        || supported_mlkem_mask == 0
        || supported_mlkem_mask & !KNOWN_MLKEM_MASK != 0
        || supported_mldsa_mask & (1 << 1) == 0
        || supported_mldsa_mask & !KNOWN_MLDSA_MASK != 0
        || capabilities == 0
        || capabilities & !KNOWN_CAPABILITY_MASK != 0
        || !operational_present
        || nonce.iter().all(|value| *value == 0)
        || operational_public_key.iter().all(|value| *value == 0)
    {
        bail!("invalid enrollment capabilities or counters");
    }
    let calculated_fingerprint = Sha256::digest(&factory_public_key);
    if calculated_fingerprint.as_slice() != factory_fingerprint {
        bail!("factory key fingerprint mismatch");
    }
    let unsigned_value = Value::Array(vec![top[0].clone(), Value::Array(payload[..13].to_vec())]);
    verify_signature(
        &factory_public_key,
        &encode_value(&unsigned_value)?,
        &signature,
    )?;

    Ok(DeviceEnrollment {
        device_id,
        domain_id,
        product_class,
        firmware_version,
        factory_public_key_b64: STANDARD.encode(&factory_public_key),
        factory_fingerprint_hex: hex::encode(factory_fingerprint),
        operational_public_key_b64: STANDARD.encode(operational_public_key),
        hardware_id_digest_hex: hex::encode(hardware_id_digest),
        supported_mlkem_mask,
        supported_mldsa_mask,
        capabilities,
        boot_counter,
        request_sequence: sequence,
        policy_epoch,
        revocation_epoch,
        nonce_b64: STANDARD.encode(nonce),
    })
}

pub fn signed_voucher(
    signer: &FleetSigner,
    domain: &str,
    enrollment: &DeviceEnrollment,
    sequence: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> Result<Vec<u8>> {
    let factory_fingerprint = hex::decode(&enrollment.factory_fingerprint_hex)?;
    let operational_public = STANDARD.decode(&enrollment.operational_public_key_b64)?;
    let operational_fingerprint = Sha256::digest(&operational_public);
    let payload = vec![
        bytes(&factory_fingerprint),
        bytes(&operational_fingerprint),
        bytes(signer.public_key()),
        unsigned_value(enrollment.capabilities.into()),
        text_value(&enrollment.product_class),
    ];
    sign_artifact(
        signer,
        VOUCHER_KIND,
        sequence,
        enrollment.policy_epoch,
        enrollment.revocation_epoch.max(1),
        issued_at_ms,
        expires_at_ms,
        &STANDARD.decode(&enrollment.nonce_b64)?,
        &enrollment.device_id,
        domain,
        payload,
    )
}

pub fn signed_credential(
    signer: &FleetSigner,
    domain: &str,
    enrollment: &DeviceEnrollment,
    sequence: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> Result<Vec<u8>> {
    let operational_public = STANDARD.decode(&enrollment.operational_public_key_b64)?;
    let payload = vec![
        text_value(&format!("cred-{sequence}")),
        bytes(&operational_public),
        unsigned_value(enrollment.supported_mlkem_mask.into()),
        unsigned_value(enrollment.supported_mldsa_mask.into()),
        unsigned_value(enrollment.capabilities.into()),
        unsigned_value(issued_at_ms),
        unsigned_value(expires_at_ms),
        unsigned_value(sequence),
        text_value(&enrollment.product_class),
    ];
    sign_artifact(
        signer,
        CREDENTIAL_KIND,
        sequence,
        enrollment.policy_epoch,
        enrollment.revocation_epoch.max(1),
        issued_at_ms,
        expires_at_ms,
        &STANDARD.decode(&enrollment.nonce_b64)?,
        &enrollment.device_id,
        domain,
        payload,
    )
}

pub fn signed_policy(signer: &FleetSigner, domain: &str, policy: &Policy) -> Result<Vec<u8>> {
    let flags = 1_u64 | u64::from(policy.forbid_downgrade) << 1;
    let nonce = Sha256::digest(format!("PQCP-FLEET-POLICY:{}", policy.policy_id));
    let payload = vec![
        unsigned_value(1 << 1),
        unsigned_value(1 << 1),
        unsigned_value(768),
        unsigned_value(65),
        unsigned_value(3),
        unsigned_value(1),
        unsigned_value(flags),
        unsigned_value(8),
        unsigned_value(16),
        unsigned_value(policy.canary_percent.into()),
        unsigned_value(86_400_000),
        unsigned_value(3_600_000),
        unsigned_value(16 * 1024 * 1024),
        unsigned_value(3_600_000),
        text_value(&policy.profile),
    ];
    sign_artifact(
        signer,
        POLICY_KIND,
        policy.sequence,
        policy.epoch,
        1,
        policy.created_at_ms,
        policy.created_at_ms.saturating_add(86_400_000),
        &nonce,
        "*",
        domain,
        payload,
    )
}

pub fn signed_revocation(
    signer: &FleetSigner,
    domain: &str,
    revocation: &Revocation,
) -> Result<Vec<u8>> {
    let nonce = Sha256::digest(format!(
        "PQCP-FLEET-REVOCATION:{}",
        revocation.revocation_id
    ));
    let payload = vec![
        unsigned_value(revocation.previous_epoch),
        unsigned_value(revocation.next_refresh_ms),
        unsigned_value(revocation.offline_grace_ms),
        Value::Array(vec![Value::Array(vec![
            unsigned_value(revocation.kind.wire_value()),
            text_value(&revocation.subject_id),
            unsigned_value(revocation.effective_at_ms),
            unsigned_value(revocation.reason.into()),
        ])]),
    ];
    sign_artifact(
        signer,
        REVOCATION_KIND,
        revocation.sequence,
        0,
        revocation.epoch,
        revocation.created_at_ms,
        revocation.created_at_ms.saturating_add(86_400_000),
        &nonce,
        &revocation.target_device_id,
        domain,
        payload,
    )
}

fn sign_artifact(
    signer: &FleetSigner,
    kind: u64,
    sequence: u64,
    policy_epoch: u64,
    revocation_epoch: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: &[u8],
    device_id: &str,
    domain: &str,
    payload: Vec<Value>,
) -> Result<Vec<u8>> {
    if sequence == 0 || issued_at_ms == 0 || expires_at_ms <= issued_at_ms {
        bail!("invalid signed artifact lifetime or sequence");
    }
    if nonce.len() != DIGEST_BYTES {
        bail!("fleet nonce must contain 32 bytes");
    }
    let envelope = Value::Array(vec![
        unsigned_value(SCHEMA_VERSION),
        unsigned_value(PROTOCOL_VERSION),
        unsigned_value(kind),
        unsigned_value(random_nonzero_u64()),
        unsigned_value(sequence),
        unsigned_value(policy_epoch),
        unsigned_value(revocation_epoch),
        unsigned_value(issued_at_ms),
        unsigned_value(expires_at_ms),
        bytes(nonce),
        text_value(device_id),
        text_value(domain),
    ]);
    let unsigned_value = Value::Array(vec![envelope.clone(), Value::Array(payload.clone())]);
    let unsigned_cbor = encode_value(&unsigned_value)?;
    let signature = signer.sign(&unsigned_cbor, SIGNATURE_CONTEXT)?;
    signer.verify(&unsigned_cbor, SIGNATURE_CONTEXT, &signature)?;
    let mut signed_payload = payload;
    signed_payload.push(bytes(&signature));
    encode_value(&Value::Array(vec![envelope, Value::Array(signed_payload)]))
}

pub fn cohort_bucket(device_id: &str, policy_id: &str) -> u16 {
    let mut hasher = Sha256::new();
    hasher.update(b"PQCP-FLEET-COHORT-V1");
    hasher.update((device_id.len() as u64).to_be_bytes());
    hasher.update(device_id.as_bytes());
    hasher.update((policy_id.len() as u64).to_be_bytes());
    hasher.update(policy_id.as_bytes());
    let digest = hasher.finalize();
    u16::from_be_bytes([digest[0], digest[1]]) % 10_000
}

fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let public_key = PublicKey::from_bytes(public_key).context("invalid ML-DSA-65 public key")?;
    let signature =
        DetachedSignature::from_bytes(signature).context("invalid ML-DSA-65 signature")?;
    verify_detached_signature_ctx(&signature, message, SIGNATURE_CONTEXT, &public_key)
        .map_err(|_| anyhow::anyhow!("fleet enrollment signature rejected"))
}

fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    ciborium::ser::into_writer(value, &mut output).context("encode canonical CBOR array")?;
    Ok(output)
}

fn array<'a>(value: &'a Value, expected: usize, field: &str) -> Result<&'a [Value]> {
    match value {
        Value::Array(values) if values.len() == expected => Ok(values),
        _ => bail!("{field} must be an array of {expected} fields"),
    }
}

fn unsigned(value: &Value) -> Result<u64> {
    match value {
        Value::Integer(value) => u64::try_from(*value).context("negative or oversized integer"),
        _ => bail!("expected unsigned integer"),
    }
}

fn u32_value(value: &Value, field: &str) -> Result<u32> {
    u32::try_from(unsigned(value)?).with_context(|| format!("{field} exceeds u32"))
}

fn text(value: &Value, capacity: usize, field: &str) -> Result<String> {
    match value {
        Value::Text(value)
            if !value.is_empty()
                && value.len() < capacity
                && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) =>
        {
            Ok(value.clone())
        }
        _ => bail!("{field} is invalid"),
    }
}

fn bytes_exact(value: &Value, length: usize, field: &str) -> Result<Vec<u8>> {
    match value {
        Value::Bytes(value) if value.len() == length => Ok(value.clone()),
        _ => bail!("{field} must contain exactly {length} bytes"),
    }
}

fn boolean(value: &Value, field: &str) -> Result<bool> {
    match value {
        Value::Bool(value) => Ok(*value),
        _ => bail!("{field} must be a boolean"),
    }
}

fn unsigned_value(value: u64) -> Value {
    Value::Integer(Integer::from(value))
}

fn text_value(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn random_nonzero_u64() -> u64 {
    let value = Uuid::new_v4().as_u128() as u64;
    value.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrollment_fixture(signer: &FleetSigner, issued_at_ms: u64, expires_at_ms: u64) -> Vec<u8> {
        let public_key = signer.public_key().to_vec();
        let fingerprint = Sha256::digest(&public_key);
        let envelope = Value::Array(vec![
            unsigned_value(SCHEMA_VERSION),
            unsigned_value(PROTOCOL_VERSION),
            unsigned_value(ENROLLMENT_KIND),
            unsigned_value(7),
            unsigned_value(11),
            unsigned_value(0),
            unsigned_value(1),
            unsigned_value(issued_at_ms),
            unsigned_value(expires_at_ms),
            bytes(&[0x5a; DIGEST_BYTES]),
            text_value("edge-001"),
            text_value("pqcp.local"),
        ]);
        let payload = vec![
            unsigned_value(1),
            unsigned_value(2),
            unsigned_value(3),
            unsigned_value(1 << 1),
            unsigned_value(1 << 1),
            unsigned_value(0x3f),
            text_value("1.0.0"),
            text_value("gateway"),
            bytes(&public_key),
            bytes(&fingerprint),
            bytes(&[0xa5; DIGEST_BYTES]),
            bytes(&public_key),
            Value::Bool(true),
        ];
        let unsigned_message = Value::Array(vec![envelope.clone(), Value::Array(payload.clone())]);
        let signature = signer
            .sign(
                &encode_value(&unsigned_message).expect("encode fixture"),
                SIGNATURE_CONTEXT,
            )
            .expect("sign fixture");
        let mut signed_payload = payload;
        signed_payload.push(bytes(&signature));
        encode_value(&Value::Array(vec![envelope, Value::Array(signed_payload)]))
            .expect("encode signed fixture")
    }

    #[test]
    fn enrollment_verification_enforces_lifetime_and_signature() {
        let signer = FleetSigner::generate_for_test();
        let encoded = enrollment_fixture(&signer, 1_000, 5_000);

        let enrollment = verify_enrollment_request(&encoded, 2_000).expect("valid enrollment");
        assert_eq!(enrollment.device_id, "edge-001");
        assert!(verify_enrollment_request(&encoded, 5_000).is_err());

        let future = enrollment_fixture(&signer, 70_001, 80_000);
        assert!(verify_enrollment_request(&future, 10_000).is_err());

        let mut tampered = encoded;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(verify_enrollment_request(&tampered, 2_000).is_err());
    }

    #[test]
    fn enrollment_verification_rejects_trailing_and_noncanonical_data() {
        let signer = FleetSigner::generate_for_test();
        let encoded = enrollment_fixture(&signer, 1_000, 5_000);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(verify_enrollment_request(&trailing, 2_000).is_err());

        let mut noncanonical = Vec::with_capacity(encoded.len() + 1);
        noncanonical.extend_from_slice(&encoded[..2]);
        noncanonical.extend_from_slice(&[0x18, 0x01]);
        noncanonical.extend_from_slice(&encoded[3..]);
        assert!(verify_enrollment_request(&noncanonical, 2_000).is_err());
    }

    #[test]
    fn cohort_assignment_is_stable_and_policy_scoped() {
        let first = cohort_bucket("edge-001", "policy-a");

        assert_eq!(first, cohort_bucket("edge-001", "policy-a"));
        assert!(first < 10_000);
        assert_ne!(first, cohort_bucket("edge-001", "policy-b"));
    }
}
