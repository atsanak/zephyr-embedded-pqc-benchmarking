// SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentSubmission {
    pub request_cbor_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactoryAdmission {
    pub device_id: String,
    pub product_class: String,
    pub factory_fingerprint_hex: String,
    pub hardware_id_digest_hex: String,
    pub capabilities: u32,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEnrollment {
    pub device_id: String,
    pub domain_id: String,
    pub product_class: String,
    pub firmware_version: String,
    pub factory_public_key_b64: String,
    pub factory_fingerprint_hex: String,
    pub operational_public_key_b64: String,
    pub hardware_id_digest_hex: String,
    pub supported_mlkem_mask: u32,
    pub supported_mldsa_mask: u32,
    pub capabilities: u32,
    pub boot_counter: u64,
    pub request_sequence: u64,
    pub policy_epoch: u64,
    pub revocation_epoch: u64,
    pub nonce_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub device_id: String,
    pub product_class: String,
    pub firmware_version: String,
    pub factory_fingerprint_hex: String,
    pub state: String,
    pub supported_mlkem_mask: u32,
    pub supported_mldsa_mask: u32,
    pub capabilities: u32,
    pub boot_counter: u64,
    pub policy_epoch: u64,
    pub revocation_epoch: u64,
    pub last_sequence: u64,
    pub last_seen_ms: u64,
    pub active_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub device: Device,
    pub voucher_cbor_b64: String,
    pub credential_cbor_b64: String,
    pub root_public_key_b64: String,
    pub root_fingerprint_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    pub profile: String,
    pub canary_percent: u8,
    pub minimum_observations: u32,
    pub maximum_failure_permille: u32,
    pub observation_window_ms: u64,
    pub forbid_downgrade: bool,
    pub require_persistent_identity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub policy_id: String,
    pub epoch: u64,
    pub sequence: u64,
    pub profile: String,
    pub canary_percent: u8,
    pub minimum_observations: u32,
    pub maximum_failure_permille: u32,
    pub observation_window_ms: u64,
    pub forbid_downgrade: bool,
    pub require_persistent_identity: bool,
    pub artifact_cbor_b64: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum RevocationKind {
    Credential,
    Device,
    Domain,
}

impl RevocationKind {
    pub fn wire_value(self) -> u64 {
        match self {
            Self::Credential => 1,
            Self::Device => 2,
            Self::Domain => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Device => "device",
            Self::Domain => "domain",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "credential" => Some(Self::Credential),
            "device" => Some(Self::Device),
            "domain" => Some(Self::Domain),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationInput {
    pub target_device_id: String,
    pub kind: RevocationKind,
    pub subject_id: String,
    pub reason: u32,
    pub effective_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    pub revocation_id: String,
    pub target_device_id: String,
    pub kind: RevocationKind,
    pub subject_id: String,
    pub previous_epoch: u64,
    pub epoch: u64,
    pub sequence: u64,
    pub reason: u32,
    pub effective_at_ms: u64,
    pub next_refresh_ms: u64,
    pub offline_grace_ms: u64,
    pub artifact_cbor_b64: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutInput {
    pub policy_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rollout {
    pub rollout_id: String,
    pub policy_id: String,
    pub policy_epoch: u64,
    pub profile: String,
    pub state: String,
    pub cohort_size: u64,
    pub observations: u64,
    pub successes: u64,
    pub failures: u64,
    pub started_at_ms: u64,
    pub observation_deadline_ms: u64,
    pub completed_at_ms: Option<u64>,
    pub decision_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationInput {
    pub device_id: String,
    pub sequence: u64,
    pub success: bool,
    pub latency_us: u64,
    pub cycles: u64,
    pub stack_bytes: u64,
    pub sessions_remaining: u32,
    pub reason_mask: u32,
    pub observed_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub observation_id: String,
    pub rollout_id: String,
    pub device_id: String,
    pub sequence: u64,
    pub success: bool,
    pub latency_us: u64,
    pub cycles: u64,
    pub stack_bytes: u64,
    pub sessions_remaining: u32,
    pub reason_mask: u32,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CohortMember {
    pub rollout_id: String,
    pub device_id: String,
    pub bucket: u16,
    pub selected: bool,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutStatus {
    pub rollout: Rollout,
    pub cohort: Vec<CohortMember>,
    pub recent_observations: Vec<Observation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub event_id: i64,
    pub kind: String,
    pub subject_id: String,
    pub detail: serde_json::Value,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetStatus {
    pub devices: u64,
    pub operational_devices: u64,
    pub policies: u64,
    pub active_rollouts: u64,
    pub last_event_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    pub status: &'static str,
    pub protocol: &'static str,
    pub root_fingerprint_hex: String,
    pub database: FleetStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub error: String,
}
