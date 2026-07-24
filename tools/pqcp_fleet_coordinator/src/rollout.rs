// SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use uuid::Uuid;

use crate::cbor::{signed_policy, signed_revocation};
use crate::crypto::FleetSigner;
use crate::db::Database;
use crate::model::{
    Policy, PolicyInput, Revocation, RevocationInput, RevocationKind, Rollout, RolloutInput,
};

const REVOCATION_REFRESH_MS: u64 = 86_400_000;
const REVOCATION_OFFLINE_GRACE_MS: u64 = 172_800_000;

pub fn publish_policy(
    database: &Database,
    signer: &FleetSigner,
    domain: &str,
    input: PolicyInput,
) -> Result<Policy> {
    validate_policy(&input)?;
    let now_ms = now_ms();
    let mut policy = Policy {
        policy_id: Uuid::new_v4().to_string(),
        epoch: database.next_policy_epoch()?,
        sequence: database.allocate_artifact_sequences(1)?,
        profile: input.profile,
        canary_percent: input.canary_percent,
        minimum_observations: input.minimum_observations,
        maximum_failure_permille: input.maximum_failure_permille,
        observation_window_ms: input.observation_window_ms,
        forbid_downgrade: input.forbid_downgrade,
        require_persistent_identity: input.require_persistent_identity,
        artifact_cbor_b64: String::new(),
        created_at_ms: now_ms,
    };
    policy.artifact_cbor_b64 = STANDARD.encode(signed_policy(signer, domain, &policy)?);
    database.insert_policy(&policy)?;
    Ok(policy)
}

pub fn start_rollout(database: &Database, input: RolloutInput) -> Result<Rollout> {
    let policy = database
        .policy(&input.policy_id)?
        .context("policy not found")?;
    let started_at_ms = now_ms();
    let rollout = Rollout {
        rollout_id: Uuid::new_v4().to_string(),
        policy_id: policy.policy_id.clone(),
        policy_epoch: policy.epoch,
        profile: policy.profile.clone(),
        state: "canary".to_owned(),
        cohort_size: 0,
        observations: 0,
        successes: 0,
        failures: 0,
        started_at_ms,
        observation_deadline_ms: started_at_ms.saturating_add(policy.observation_window_ms),
        completed_at_ms: None,
        decision_reason: None,
    };
    database.create_rollout(&rollout, &policy)
}

pub fn publish_revocation(
    database: &Database,
    signer: &FleetSigner,
    domain: &str,
    input: RevocationInput,
) -> Result<Revocation> {
    validate_revocation(database, domain, &input)?;
    let device = database
        .device(&input.target_device_id)?
        .context("target device not found")?;
    let created_at_ms = now_ms();
    let effective_at_ms = input.effective_at_ms.unwrap_or(created_at_ms);
    let mut revocation = Revocation {
        revocation_id: Uuid::new_v4().to_string(),
        target_device_id: input.target_device_id,
        kind: input.kind,
        subject_id: input.subject_id,
        previous_epoch: device.revocation_epoch,
        epoch: device.revocation_epoch.saturating_add(1),
        sequence: database.allocate_artifact_sequences(1)?,
        reason: input.reason,
        effective_at_ms,
        next_refresh_ms: created_at_ms.saturating_add(REVOCATION_REFRESH_MS),
        offline_grace_ms: REVOCATION_OFFLINE_GRACE_MS,
        artifact_cbor_b64: String::new(),
        created_at_ms,
    };
    revocation.artifact_cbor_b64 = STANDARD.encode(signed_revocation(signer, domain, &revocation)?);
    database.insert_revocation(&revocation)?;
    Ok(revocation)
}

fn validate_revocation(
    database: &Database,
    domain: &str,
    revocation: &RevocationInput,
) -> Result<()> {
    if revocation.target_device_id.is_empty()
        || revocation.target_device_id.len() >= 48
        || revocation.subject_id.is_empty()
        || revocation.subject_id.len() >= 48
    {
        bail!("revocation identifiers must contain 1..47 characters");
    }
    let device = database
        .device(&revocation.target_device_id)?
        .context("target device not found")?;
    if device.state == "decommissioned" {
        bail!("decommissioned devices cannot receive revocations");
    }
    match revocation.kind {
        RevocationKind::Device if revocation.subject_id != revocation.target_device_id => {
            bail!("device revocation subject must match target_device_id");
        }
        RevocationKind::Domain if revocation.subject_id != domain => {
            bail!("domain revocation subject must match the coordinator domain");
        }
        _ => {}
    }
    Ok(())
}

fn validate_policy(policy: &PolicyInput) -> Result<()> {
    if policy.profile.is_empty() || policy.profile.len() >= 32 {
        bail!("profile must contain 1..31 characters");
    }
    if !policy
        .profile
        .bytes()
        .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_' | b'.'))
    {
        bail!("profile contains unsupported characters");
    }
    if !(1..=100).contains(&policy.canary_percent) {
        bail!("canary percent must be in 1..=100");
    }
    if policy.minimum_observations == 0 {
        bail!("minimum observations must be non-zero");
    }
    if policy.maximum_failure_permille > 1000 {
        bail!("maximum failure permille must be <= 1000");
    }
    if policy.observation_window_ms < 1_000 {
        bail!("observation window must be at least one second");
    }
    Ok(())
}

pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
