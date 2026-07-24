// SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use serde_json::json;

use crate::cbor::cohort_bucket;
use crate::model::{
    CohortMember, Device, DeviceEnrollment, Event, FactoryAdmission, FleetStatus, Observation,
    ObservationInput, Policy, Revocation, RevocationKind, Rollout, RolloutStatus,
};

#[derive(Clone)]
pub struct Database {
    path: Arc<PathBuf>,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create database directory {}", parent.display()))?;
        }
        Ok(Self {
            path: Arc::new(path),
        })
    }

    fn connect(&self) -> Result<Connection> {
        let connection = Connection::open(self.path.as_ref())
            .with_context(|| format!("open fleet database {}", self.path.display()))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;
        Ok(connection)
    }

    pub fn migrate(&self) -> Result<()> {
        let connection = self.connect()?;
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                product_class TEXT NOT NULL,
                firmware_version TEXT NOT NULL,
                factory_public_key_b64 TEXT NOT NULL,
                factory_fingerprint_hex TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL,
                supported_mlkem_mask INTEGER NOT NULL,
                supported_mldsa_mask INTEGER NOT NULL,
                capabilities INTEGER NOT NULL,
                boot_counter INTEGER NOT NULL,
                policy_epoch INTEGER NOT NULL DEFAULT 0,
                revocation_epoch INTEGER NOT NULL DEFAULT 0,
                last_sequence INTEGER NOT NULL DEFAULT 0,
                last_seen_ms INTEGER NOT NULL,
                active_profile TEXT
            );

            CREATE TABLE IF NOT EXISTS factory_admissions (
                device_id TEXT PRIMARY KEY,
                product_class TEXT NOT NULL,
                factory_fingerprint_hex TEXT NOT NULL UNIQUE,
                hardware_id_digest_hex TEXT NOT NULL,
                capabilities INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policies (
                policy_id TEXT PRIMARY KEY,
                epoch INTEGER NOT NULL UNIQUE,
                sequence INTEGER NOT NULL,
                profile TEXT NOT NULL,
                canary_percent INTEGER NOT NULL,
                minimum_observations INTEGER NOT NULL,
                maximum_failure_permille INTEGER NOT NULL,
                observation_window_ms INTEGER NOT NULL,
                forbid_downgrade INTEGER NOT NULL,
                require_persistent_identity INTEGER NOT NULL,
                artifact_cbor_b64 TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rollouts (
                rollout_id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL REFERENCES policies(policy_id),
                state TEXT NOT NULL,
                started_at_ms INTEGER NOT NULL,
                observation_deadline_ms INTEGER NOT NULL,
                completed_at_ms INTEGER,
                decision_reason TEXT
            );

            CREATE TABLE IF NOT EXISTS cohorts (
                rollout_id TEXT NOT NULL REFERENCES rollouts(rollout_id) ON DELETE CASCADE,
                device_id TEXT NOT NULL REFERENCES devices(device_id),
                bucket INTEGER NOT NULL,
                selected INTEGER NOT NULL,
                state TEXT NOT NULL,
                PRIMARY KEY (rollout_id, device_id)
            );

            CREATE TABLE IF NOT EXISTS observations (
                observation_id TEXT PRIMARY KEY,
                rollout_id TEXT NOT NULL REFERENCES rollouts(rollout_id) ON DELETE CASCADE,
                device_id TEXT NOT NULL REFERENCES devices(device_id),
                sequence INTEGER NOT NULL,
                success INTEGER NOT NULL,
                latency_us INTEGER NOT NULL,
                cycles INTEGER NOT NULL,
                stack_bytes INTEGER NOT NULL,
                sessions_remaining INTEGER NOT NULL,
                reason_mask INTEGER NOT NULL,
                observed_at_ms INTEGER NOT NULL,
                UNIQUE (rollout_id, device_id, sequence)
            );

            CREATE TABLE IF NOT EXISTS revocations (
                revocation_id TEXT PRIMARY KEY,
                target_device_id TEXT NOT NULL,
                subject_kind TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                previous_epoch INTEGER NOT NULL,
                epoch INTEGER NOT NULL,
                sequence INTEGER NOT NULL,
                reason INTEGER NOT NULL,
                effective_at_ms INTEGER NOT NULL,
                next_refresh_ms INTEGER NOT NULL,
                offline_grace_ms INTEGER NOT NULL,
                artifact_cbor_b64 TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_devices_state ON devices(state);
            CREATE INDEX IF NOT EXISTS idx_rollouts_state ON rollouts(state);
            CREATE INDEX IF NOT EXISTS idx_observations_rollout ON observations(rollout_id);
            CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at_ms);
            ",
        )?;
        ensure_column(
            &connection,
            "policies",
            "sequence",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &connection,
            "revocations",
            "target_device_id",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_column(
            &connection,
            "revocations",
            "previous_epoch",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &connection,
            "revocations",
            "sequence",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &connection,
            "revocations",
            "next_refresh_ms",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &connection,
            "revocations",
            "offline_grace_ms",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &connection,
            "revocations",
            "artifact_cbor_b64",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        Ok(())
    }

    pub fn admit_factory(&self, admission: &FactoryAdmission) -> Result<()> {
        if admission.device_id.is_empty()
            || admission.device_id.len() >= 48
            || admission.product_class.is_empty()
            || admission.product_class.len() >= 32
            || admission.capabilities == 0
            || hex::decode(&admission.factory_fingerprint_hex)?.len() != 32
            || hex::decode(&admission.hardware_id_digest_hex)?.len() != 32
        {
            bail!("invalid factory admission");
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        transaction
            .execute(
                "INSERT INTO factory_admissions (
                device_id, product_class, factory_fingerprint_hex,
                hardware_id_digest_hex, capabilities, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    admission.device_id,
                    admission.product_class,
                    admission.factory_fingerprint_hex.to_ascii_lowercase(),
                    admission.hardware_id_digest_hex.to_ascii_lowercase(),
                    admission.capabilities,
                    admission.created_at_ms,
                ],
            )
            .context("admit factory identity")?;
        insert_event(
            &transaction,
            "factory.admitted",
            &admission.device_id,
            &json!({
                "product_class": admission.product_class,
                "factory_fingerprint_hex": admission.factory_fingerprint_hex,
            }),
            admission.created_at_ms,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn verify_factory_admission(&self, enrollment: &DeviceEnrollment) -> Result<()> {
        let admission = self
            .connect()?
            .query_row(
                "SELECT product_class, factory_fingerprint_hex,
                        hardware_id_digest_hex, capabilities
                 FROM factory_admissions WHERE device_id = ?1",
                params![enrollment.device_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, u32>(3)?,
                    ))
                },
            )
            .optional()?
            .context("factory identity is not admitted")?;
        if admission.0 != enrollment.product_class
            || admission.1 != enrollment.factory_fingerprint_hex.to_ascii_lowercase()
            || admission.2 != enrollment.hardware_id_digest_hex.to_ascii_lowercase()
            || enrollment.capabilities & !admission.3 != 0
        {
            bail!("enrollment request does not match factory admission");
        }
        Ok(())
    }

    pub fn enroll_device(&self, enrollment: &DeviceEnrollment, now_ms: u64) -> Result<Device> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let previous = transaction
            .query_row(
                "SELECT factory_fingerprint_hex, boot_counter, last_sequence
                 FROM devices WHERE device_id = ?1",
                params![enrollment.device_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                },
            )
            .optional()?;
        let next_sequence = if let Some((fingerprint, boot_counter, last_sequence)) = previous {
            if fingerprint != enrollment.factory_fingerprint_hex {
                bail!("device identifier is already bound to another factory key");
            }
            if enrollment.boot_counter < boot_counter {
                bail!("stale boot counter");
            }
            if enrollment.request_sequence <= last_sequence {
                bail!("stale enrollment sequence");
            }
            enrollment.request_sequence
        } else {
            enrollment.request_sequence
        };
        transaction.execute(
            "
            INSERT INTO devices (
                device_id, product_class, firmware_version,
                factory_public_key_b64, factory_fingerprint_hex, state,
                supported_mlkem_mask, supported_mldsa_mask, capabilities,
                boot_counter, policy_epoch, revocation_epoch,
                last_sequence, last_seen_ms
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, 'operational', ?6, ?7, ?8, ?9,
                ?10, ?11, ?12, ?13
            )
            ON CONFLICT(device_id) DO UPDATE SET
                product_class = excluded.product_class,
                firmware_version = excluded.firmware_version,
                supported_mlkem_mask = excluded.supported_mlkem_mask,
                supported_mldsa_mask = excluded.supported_mldsa_mask,
                capabilities = excluded.capabilities,
                boot_counter = excluded.boot_counter,
                policy_epoch = MAX(devices.policy_epoch, excluded.policy_epoch),
                revocation_epoch = MAX(devices.revocation_epoch, excluded.revocation_epoch),
                last_sequence = excluded.last_sequence,
                last_seen_ms = excluded.last_seen_ms
            ",
            params![
                enrollment.device_id,
                enrollment.product_class,
                enrollment.firmware_version,
                enrollment.factory_public_key_b64,
                enrollment.factory_fingerprint_hex,
                enrollment.supported_mlkem_mask,
                enrollment.supported_mldsa_mask,
                enrollment.capabilities,
                enrollment.boot_counter,
                enrollment.policy_epoch,
                enrollment.revocation_epoch.max(1),
                next_sequence,
                now_ms,
            ],
        )?;
        insert_event(
            &transaction,
            "device.enrolled",
            &enrollment.device_id,
            &json!({
                "product_class": enrollment.product_class,
                "firmware_version": enrollment.firmware_version,
                "boot_counter": enrollment.boot_counter,
            }),
            now_ms,
        )?;
        transaction.commit()?;
        self.device(&enrollment.device_id)?
            .context("enrolled device disappeared")
    }

    pub fn device(&self, device_id: &str) -> Result<Option<Device>> {
        self.connect()?
            .query_row(
                "SELECT device_id, product_class, firmware_version,
                        factory_fingerprint_hex, state, supported_mlkem_mask,
                        supported_mldsa_mask, capabilities, boot_counter,
                        policy_epoch, revocation_epoch, last_sequence,
                        last_seen_ms, active_profile
                 FROM devices WHERE device_id = ?1",
                params![device_id],
                device_from_row,
            )
            .optional()
            .context("load device")
    }

    pub fn list_devices(&self, state: Option<&str>) -> Result<Vec<Device>> {
        let connection = self.connect()?;
        let sql = if state.is_some() {
            "SELECT device_id, product_class, firmware_version,
                    factory_fingerprint_hex, state, supported_mlkem_mask,
                    supported_mldsa_mask, capabilities, boot_counter,
                    policy_epoch, revocation_epoch, last_sequence,
                    last_seen_ms, active_profile
             FROM devices WHERE state = ?1 ORDER BY device_id"
        } else {
            "SELECT device_id, product_class, firmware_version,
                    factory_fingerprint_hex, state, supported_mlkem_mask,
                    supported_mldsa_mask, capabilities, boot_counter,
                    policy_epoch, revocation_epoch, last_sequence,
                    last_seen_ms, active_profile
             FROM devices ORDER BY device_id"
        };
        let mut statement = connection.prepare(sql)?;
        let rows = if let Some(state) = state {
            statement.query_map(params![state], device_from_row)?
        } else {
            statement.query_map([], device_from_row)?
        };
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("list devices")
    }

    pub fn next_policy_epoch(&self) -> Result<u64> {
        self.connect()?
            .query_row(
                "SELECT COALESCE(MAX(epoch), 0) + 1 FROM policies",
                [],
                |row| row.get(0),
            )
            .context("allocate policy epoch")
    }

    pub fn allocate_artifact_sequences(&self, count: u64) -> Result<u64> {
        if count == 0 {
            bail!("artifact sequence allocation must be non-zero");
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let stored: Option<String> = transaction
            .query_row(
                "SELECT value FROM metadata WHERE key = 'artifact_sequence'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let stored = stored
            .as_deref()
            .map(str::parse::<u64>)
            .transpose()
            .context("artifact sequence metadata is invalid")?
            .unwrap_or(0);
        let observed: u64 = transaction.query_row(
            "SELECT COALESCE(MAX(last_sequence), 0) FROM devices",
            [],
            |row| row.get(0),
        )?;
        let first = stored.max(observed).saturating_add(1);
        let last = first
            .checked_add(count.saturating_sub(1))
            .context("artifact sequence space exhausted")?;
        transaction.execute(
            "INSERT INTO metadata (key, value) VALUES ('artifact_sequence', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![last.to_string()],
        )?;
        transaction.commit()?;
        Ok(first)
    }

    pub fn insert_policy(&self, policy: &Policy) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO policies (
                policy_id, epoch, sequence, profile, canary_percent,
                minimum_observations, maximum_failure_permille,
                observation_window_ms, forbid_downgrade,
                require_persistent_identity, artifact_cbor_b64, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                policy.policy_id,
                policy.epoch,
                policy.sequence,
                policy.profile,
                policy.canary_percent,
                policy.minimum_observations,
                policy.maximum_failure_permille,
                policy.observation_window_ms,
                policy.forbid_downgrade,
                policy.require_persistent_identity,
                policy.artifact_cbor_b64,
                policy.created_at_ms,
            ],
        )?;
        insert_event(
            &transaction,
            "policy.published",
            &policy.policy_id,
            &json!({
                "epoch": policy.epoch,
                "profile": policy.profile,
                "canary_percent": policy.canary_percent,
            }),
            policy.created_at_ms,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn policy(&self, policy_id: &str) -> Result<Option<Policy>> {
        self.connect()?
            .query_row(
                "SELECT policy_id, epoch, sequence, profile, canary_percent,
                        minimum_observations, maximum_failure_permille,
                        observation_window_ms, forbid_downgrade,
                        require_persistent_identity, artifact_cbor_b64,
                        created_at_ms
                 FROM policies WHERE policy_id = ?1",
                params![policy_id],
                policy_from_row,
            )
            .optional()
            .context("load policy")
    }

    pub fn list_policies(&self) -> Result<Vec<Policy>> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT policy_id, epoch, sequence, profile, canary_percent,
                    minimum_observations, maximum_failure_permille,
                    observation_window_ms, forbid_downgrade,
                    require_persistent_identity, artifact_cbor_b64,
                    created_at_ms
             FROM policies ORDER BY epoch DESC",
        )?;
        let policies = statement
            .query_map([], policy_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("list policies")?;
        Ok(policies)
    }

    pub fn insert_revocation(&self, revocation: &Revocation) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let current_epoch: u64 = transaction
            .query_row(
                "SELECT revocation_epoch FROM devices WHERE device_id = ?1",
                params![revocation.target_device_id],
                |row| row.get(0),
            )
            .optional()?
            .context("target device not found")?;
        if current_epoch != revocation.previous_epoch
            || revocation.epoch != revocation.previous_epoch.saturating_add(1)
        {
            bail!("revocation epoch changed while artifact was being issued");
        }
        transaction.execute(
            "INSERT INTO revocations (
                revocation_id, target_device_id, subject_kind, subject_id,
                previous_epoch, epoch, sequence, reason, effective_at_ms,
                next_refresh_ms, offline_grace_ms, artifact_cbor_b64,
                created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                revocation.revocation_id,
                revocation.target_device_id,
                revocation.kind.as_str(),
                revocation.subject_id,
                revocation.previous_epoch,
                revocation.epoch,
                revocation.sequence,
                revocation.reason,
                revocation.effective_at_ms,
                revocation.next_refresh_ms,
                revocation.offline_grace_ms,
                revocation.artifact_cbor_b64,
                revocation.created_at_ms,
            ],
        )?;
        transaction.execute(
            "UPDATE devices
             SET revocation_epoch = ?2, state = 'revocation_pending'
             WHERE device_id = ?1",
            params![revocation.target_device_id, revocation.epoch],
        )?;
        insert_event(
            &transaction,
            "revocation.published",
            &revocation.revocation_id,
            &json!({
                "target_device_id": revocation.target_device_id,
                "kind": revocation.kind.as_str(),
                "subject_id": revocation.subject_id,
                "epoch": revocation.epoch,
                "reason": revocation.reason,
                "effective_at_ms": revocation.effective_at_ms,
            }),
            revocation.created_at_ms,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list_revocations(&self) -> Result<Vec<Revocation>> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT revocation_id, target_device_id, subject_kind, subject_id,
                    previous_epoch, epoch, sequence, reason, effective_at_ms,
                    next_refresh_ms, offline_grace_ms, artifact_cbor_b64,
                    created_at_ms
             FROM revocations ORDER BY created_at_ms DESC, revocation_id",
        )?;
        let revocations = statement
            .query_map([], revocation_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("list revocations")?;
        Ok(revocations)
    }

    pub fn create_rollout(&self, rollout: &Rollout, policy: &Policy) -> Result<Rollout> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let active: u64 = transaction.query_row(
            "SELECT COUNT(*) FROM rollouts
             WHERE state IN ('draft', 'canary', 'observing', 'promoting', 'draining')",
            [],
            |row| row.get(0),
        )?;
        if active != 0 {
            bail!("another rollout is already active");
        }
        transaction.execute(
            "INSERT INTO rollouts (
                rollout_id, policy_id, state, started_at_ms, observation_deadline_ms
             ) VALUES (?1, ?2, 'draft', ?3, ?4)",
            params![
                rollout.rollout_id,
                rollout.policy_id,
                rollout.started_at_ms,
                rollout.observation_deadline_ms,
            ],
        )?;

        let mut candidates = {
            let mut statement = transaction.prepare(
                "SELECT device_id FROM devices
                 WHERE state = 'operational' ORDER BY device_id",
            )?;
            let devices = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            devices
        };
        let threshold = u16::from(policy.canary_percent) * 100;
        let mut buckets: Vec<(String, u16, bool)> = candidates
            .drain(..)
            .map(|device_id| {
                let bucket = cohort_bucket(&device_id, &policy.policy_id);
                let selected = bucket < threshold;
                (device_id, bucket, selected)
            })
            .collect();
        if !buckets.is_empty() && !buckets.iter().any(|(_, _, selected)| *selected) {
            if let Some((_, _, selected)) = buckets.iter_mut().min_by_key(|(_, bucket, _)| *bucket)
            {
                *selected = true;
            }
        }
        for (device_id, bucket, selected) in &buckets {
            transaction.execute(
                "INSERT INTO cohorts (rollout_id, device_id, bucket, selected, state)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    rollout.rollout_id,
                    device_id,
                    bucket,
                    selected,
                    if *selected { "pending" } else { "held" },
                ],
            )?;
        }
        insert_event(
            &transaction,
            "rollout.draft",
            &rollout.rollout_id,
            &json!({
                "policy_id": policy.policy_id,
                "profile": policy.profile,
            }),
            rollout.started_at_ms,
        )?;
        transaction.execute(
            "UPDATE rollouts SET state = 'canary' WHERE rollout_id = ?1",
            params![rollout.rollout_id],
        )?;
        insert_event(
            &transaction,
            "rollout.canary",
            &rollout.rollout_id,
            &json!({
                "policy_id": policy.policy_id,
                "profile": policy.profile,
                "selected": buckets.iter().filter(|(_, _, selected)| *selected).count(),
                "eligible": buckets.len(),
            }),
            rollout.started_at_ms,
        )?;
        transaction.commit()?;
        self.rollout(&rollout.rollout_id)?
            .context("created rollout disappeared")
    }

    pub fn rollout(&self, rollout_id: &str) -> Result<Option<Rollout>> {
        let connection = self.connect()?;
        connection
            .query_row(
                "
                SELECT r.rollout_id, r.policy_id, p.epoch, p.profile, r.state,
                       (SELECT COUNT(*) FROM cohorts c
                        WHERE c.rollout_id = r.rollout_id AND c.selected = 1),
                       (SELECT COUNT(*) FROM observations o
                        WHERE o.rollout_id = r.rollout_id),
                       (SELECT COUNT(*) FROM observations o
                        WHERE o.rollout_id = r.rollout_id AND o.success = 1),
                       (SELECT COUNT(*) FROM observations o
                        WHERE o.rollout_id = r.rollout_id AND o.success = 0),
                       r.started_at_ms, r.observation_deadline_ms,
                       r.completed_at_ms, r.decision_reason
                FROM rollouts r
                JOIN policies p ON p.policy_id = r.policy_id
                WHERE r.rollout_id = ?1
                ",
                params![rollout_id],
                rollout_from_row,
            )
            .optional()
            .context("load rollout")
    }

    pub fn record_observation(&self, rollout_id: &str, observation: &Observation) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let rollout_state: Option<String> = transaction
            .query_row(
                "SELECT state FROM rollouts WHERE rollout_id = ?1",
                params![rollout_id],
                |row| row.get(0),
            )
            .optional()?;
        if !matches!(rollout_state.as_deref(), Some("canary" | "observing")) {
            bail!("rollout is not accepting observations");
        }
        let selected: Option<bool> = transaction
            .query_row(
                "SELECT selected FROM cohorts WHERE rollout_id = ?1 AND device_id = ?2",
                params![rollout_id, observation.device_id],
                |row| row.get(0),
            )
            .optional()?;
        if selected != Some(true) {
            bail!("device is not in the selected canary cohort");
        }
        let last_sequence: u64 = transaction.query_row(
            "SELECT COALESCE(MAX(sequence), 0) FROM observations
             WHERE rollout_id = ?1 AND device_id = ?2",
            params![rollout_id, observation.device_id],
            |row| row.get(0),
        )?;
        if observation.sequence <= last_sequence {
            bail!("observation sequence is stale");
        }
        transaction.execute(
            "INSERT INTO observations (
                observation_id, rollout_id, device_id, sequence, success,
                latency_us, cycles, stack_bytes, sessions_remaining,
                reason_mask, observed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                observation.observation_id,
                rollout_id,
                observation.device_id,
                observation.sequence,
                observation.success,
                observation.latency_us,
                observation.cycles,
                observation.stack_bytes,
                observation.sessions_remaining,
                observation.reason_mask,
                observation.observed_at_ms,
            ],
        )?;
        transaction.execute(
            "UPDATE cohorts SET state = ?3
             WHERE rollout_id = ?1 AND device_id = ?2",
            params![
                rollout_id,
                observation.device_id,
                if observation.success {
                    "healthy"
                } else {
                    "failed"
                },
            ],
        )?;
        transaction.execute(
            "UPDATE rollouts SET state = 'observing'
             WHERE rollout_id = ?1 AND state = 'canary'",
            params![rollout_id],
        )?;
        insert_event(
            &transaction,
            "rollout.observation",
            rollout_id,
            &json!({
                "device_id": observation.device_id,
                "success": observation.success,
                "reason_mask": observation.reason_mask,
                "latency_us": observation.latency_us,
            }),
            observation.observed_at_ms,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn evaluate_rollout(&self, rollout_id: &str, now_ms: u64) -> Result<Rollout> {
        let rollout = self.rollout(rollout_id)?.context("rollout not found")?;
        if !matches!(rollout.state.as_str(), "canary" | "observing") {
            return Ok(rollout);
        }
        let policy = self
            .policy(&rollout.policy_id)?
            .context("rollout policy not found")?;
        let timed_out = now_ms >= rollout.observation_deadline_ms;
        let enough = rollout.observations >= u64::from(policy.minimum_observations);
        let failure_exceeded = rollout.observations != 0
            && rollout.failures.saturating_mul(1000)
                > u64::from(policy.maximum_failure_permille).saturating_mul(rollout.observations);
        let all_selected_reported =
            rollout.cohort_size != 0 && rollout.observations >= rollout.cohort_size;
        let decision = if failure_exceeded && (enough || policy.maximum_failure_permille == 0) {
            Some((
                "rolled_back",
                format!(
                    "canary failure rate {}/{} exceeded {} permille",
                    rollout.failures, rollout.observations, policy.maximum_failure_permille
                ),
            ))
        } else if timed_out && !enough {
            Some((
                "rolled_back",
                format!(
                    "observation deadline expired with {}/{} required reports",
                    rollout.observations, policy.minimum_observations
                ),
            ))
        } else if enough && all_selected_reported && !failure_exceeded {
            Some((
                "completed",
                format!(
                    "{} canary observations accepted with {} failures",
                    rollout.observations, rollout.failures
                ),
            ))
        } else {
            None
        };
        if let Some((state, reason)) = decision {
            self.complete_rollout(rollout_id, state, &reason, now_ms)?;
        }
        self.rollout(rollout_id)?
            .context("evaluated rollout disappeared")
    }

    fn complete_rollout(
        &self,
        rollout_id: &str,
        state: &str,
        reason: &str,
        now_ms: u64,
    ) -> Result<()> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        if state == "completed" {
            let changed = transaction.execute(
                "UPDATE rollouts SET state = 'promoting', decision_reason = ?2
                 WHERE rollout_id = ?1 AND state IN ('canary', 'observing')",
                params![rollout_id, reason],
            )?;
            if changed == 0 {
                bail!("rollout is no longer eligible for promotion");
            }
            insert_event(
                &transaction,
                "rollout.promoting",
                rollout_id,
                &json!({ "reason": reason }),
                now_ms,
            )?;
            transaction.execute(
                "UPDATE devices
                 SET policy_epoch = (
                         SELECT p.epoch FROM rollouts r
                         JOIN policies p ON p.policy_id = r.policy_id
                         WHERE r.rollout_id = ?1
                     ),
                     active_profile = (
                         SELECT p.profile FROM rollouts r
                         JOIN policies p ON p.policy_id = r.policy_id
                         WHERE r.rollout_id = ?1
                     )
                 WHERE state = 'operational'",
                params![rollout_id],
            )?;
            transaction.execute(
                "UPDATE cohorts SET state = 'promoted' WHERE rollout_id = ?1",
                params![rollout_id],
            )?;
            transaction.execute(
                "UPDATE rollouts SET state = 'draining' WHERE rollout_id = ?1",
                params![rollout_id],
            )?;
            insert_event(
                &transaction,
                "rollout.draining",
                rollout_id,
                &json!({
                    "reason": reason,
                    "action": "retire sessions bound to the previous profile",
                }),
                now_ms.saturating_add(1),
            )?;
            transaction.execute(
                "UPDATE rollouts
                 SET state = 'completed', completed_at_ms = ?2
                 WHERE rollout_id = ?1 AND state = 'draining'",
                params![rollout_id, now_ms],
            )?;
            insert_event(
                &transaction,
                "rollout.completed",
                rollout_id,
                &json!({ "reason": reason }),
                now_ms.saturating_add(2),
            )?;
        } else {
            transaction.execute(
                "UPDATE rollouts
                 SET state = 'rolled_back', completed_at_ms = ?2,
                     decision_reason = ?3
                 WHERE rollout_id = ?1 AND state IN ('canary', 'observing')",
                params![rollout_id, now_ms, reason],
            )?;
            transaction.execute(
                "UPDATE cohorts SET state = CASE
                    WHEN selected = 1 THEN 'rolled_back' ELSE state END
                 WHERE rollout_id = ?1",
                params![rollout_id],
            )?;
            insert_event(
                &transaction,
                "rollout.rolled_back",
                rollout_id,
                &json!({ "reason": reason }),
                now_ms,
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn rollout_status(&self, rollout_id: &str) -> Result<RolloutStatus> {
        let rollout = self.rollout(rollout_id)?.context("rollout not found")?;
        let connection = self.connect()?;
        let cohort = {
            let mut statement = connection.prepare(
                "SELECT rollout_id, device_id, bucket, selected, state
                 FROM cohorts WHERE rollout_id = ?1 ORDER BY bucket, device_id",
            )?;
            let members = statement
                .query_map(params![rollout_id], |row| {
                    Ok(CohortMember {
                        rollout_id: row.get(0)?,
                        device_id: row.get(1)?,
                        bucket: row.get(2)?,
                        selected: row.get(3)?,
                        state: row.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            members
        };
        let recent_observations = {
            let mut statement = connection.prepare(
                "SELECT observation_id, rollout_id, device_id, sequence, success,
                        latency_us, cycles, stack_bytes, sessions_remaining,
                        reason_mask, observed_at_ms
                 FROM observations WHERE rollout_id = ?1
                 ORDER BY observed_at_ms DESC LIMIT 100",
            )?;
            let observations = statement
                .query_map(params![rollout_id], observation_from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            observations
        };
        Ok(RolloutStatus {
            rollout,
            cohort,
            recent_observations,
        })
    }

    pub fn recent_events(&self, after: i64, limit: usize) -> Result<Vec<Event>> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT event_id, kind, subject_id, detail_json, created_at_ms
             FROM events WHERE event_id > ?1 ORDER BY event_id LIMIT ?2",
        )?;
        let events = statement
            .query_map(params![after, limit.min(1000)], event_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("list events")?;
        Ok(events)
    }

    pub fn latest_event(&self) -> Result<Option<Event>> {
        self.connect()?
            .query_row(
                "SELECT event_id, kind, subject_id, detail_json, created_at_ms
                 FROM events ORDER BY event_id DESC LIMIT 1",
                [],
                event_from_row,
            )
            .optional()
            .context("load latest event")
    }

    pub fn status(&self) -> Result<FleetStatus> {
        self.connect()?
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM devices),
                    (SELECT COUNT(*) FROM devices WHERE state = 'operational'),
                    (SELECT COUNT(*) FROM policies),
                    (SELECT COUNT(*) FROM rollouts
                     WHERE state IN ('draft', 'canary', 'observing', 'promoting', 'draining')),
                    COALESCE((SELECT MAX(event_id) FROM events), 0)",
                [],
                |row| {
                    Ok(FleetStatus {
                        devices: row.get(0)?,
                        operational_devices: row.get(1)?,
                        policies: row.get(2)?,
                        active_rollouts: row.get(3)?,
                        last_event_id: row.get(4)?,
                    })
                },
            )
            .context("load fleet status")
    }
}

fn ensure_column(
    connection: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|value| value == column) {
        connection.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {definition}"
        ))?;
    }
    Ok(())
}

fn insert_event(
    transaction: &Transaction<'_>,
    kind: &str,
    subject_id: &str,
    detail: &serde_json::Value,
    created_at_ms: u64,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO events (kind, subject_id, detail_json, created_at_ms)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            kind,
            subject_id,
            serde_json::to_string(detail)?,
            created_at_ms
        ],
    )?;
    Ok(())
}

fn device_from_row(row: &Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        device_id: row.get(0)?,
        product_class: row.get(1)?,
        firmware_version: row.get(2)?,
        factory_fingerprint_hex: row.get(3)?,
        state: row.get(4)?,
        supported_mlkem_mask: row.get(5)?,
        supported_mldsa_mask: row.get(6)?,
        capabilities: row.get(7)?,
        boot_counter: row.get(8)?,
        policy_epoch: row.get(9)?,
        revocation_epoch: row.get(10)?,
        last_sequence: row.get(11)?,
        last_seen_ms: row.get(12)?,
        active_profile: row.get(13)?,
    })
}

fn policy_from_row(row: &Row<'_>) -> rusqlite::Result<Policy> {
    Ok(Policy {
        policy_id: row.get(0)?,
        epoch: row.get(1)?,
        sequence: row.get(2)?,
        profile: row.get(3)?,
        canary_percent: row.get(4)?,
        minimum_observations: row.get(5)?,
        maximum_failure_permille: row.get(6)?,
        observation_window_ms: row.get(7)?,
        forbid_downgrade: row.get(8)?,
        require_persistent_identity: row.get(9)?,
        artifact_cbor_b64: row.get(10)?,
        created_at_ms: row.get(11)?,
    })
}

fn revocation_from_row(row: &Row<'_>) -> rusqlite::Result<Revocation> {
    let raw_kind: String = row.get(2)?;
    let kind = RevocationKind::parse(&raw_kind).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported revocation kind {raw_kind}"),
            )
            .into(),
        )
    })?;
    Ok(Revocation {
        revocation_id: row.get(0)?,
        target_device_id: row.get(1)?,
        kind,
        subject_id: row.get(3)?,
        previous_epoch: row.get(4)?,
        epoch: row.get(5)?,
        sequence: row.get(6)?,
        reason: row.get(7)?,
        effective_at_ms: row.get(8)?,
        next_refresh_ms: row.get(9)?,
        offline_grace_ms: row.get(10)?,
        artifact_cbor_b64: row.get(11)?,
        created_at_ms: row.get(12)?,
    })
}

fn rollout_from_row(row: &Row<'_>) -> rusqlite::Result<Rollout> {
    Ok(Rollout {
        rollout_id: row.get(0)?,
        policy_id: row.get(1)?,
        policy_epoch: row.get(2)?,
        profile: row.get(3)?,
        state: row.get(4)?,
        cohort_size: row.get::<_, Option<u64>>(5)?.unwrap_or(0),
        observations: row.get(6)?,
        successes: row.get::<_, Option<u64>>(7)?.unwrap_or(0),
        failures: row.get::<_, Option<u64>>(8)?.unwrap_or(0),
        started_at_ms: row.get(9)?,
        observation_deadline_ms: row.get(10)?,
        completed_at_ms: row.get(11)?,
        decision_reason: row.get(12)?,
    })
}

fn observation_from_row(row: &Row<'_>) -> rusqlite::Result<Observation> {
    Ok(Observation {
        observation_id: row.get(0)?,
        rollout_id: row.get(1)?,
        device_id: row.get(2)?,
        sequence: row.get(3)?,
        success: row.get(4)?,
        latency_us: row.get(5)?,
        cycles: row.get(6)?,
        stack_bytes: row.get(7)?,
        sessions_remaining: row.get(8)?,
        reason_mask: row.get(9)?,
        observed_at_ms: row.get(10)?,
    })
}

fn event_from_row(row: &Row<'_>) -> rusqlite::Result<Event> {
    let detail: String = row.get(3)?;
    Ok(Event {
        event_id: row.get(0)?,
        kind: row.get(1)?,
        subject_id: row.get(2)?,
        detail: serde_json::from_str(&detail).unwrap_or_else(|_| json!({ "raw": detail })),
        created_at_ms: row.get(4)?,
    })
}

pub fn observation_from_input(
    rollout_id: &str,
    input: ObservationInput,
    now_ms: u64,
) -> Observation {
    Observation {
        observation_id: uuid::Uuid::new_v4().to_string(),
        rollout_id: rollout_id.to_owned(),
        device_id: input.device_id,
        sequence: input.sequence,
        success: input.success,
        latency_us: input.latency_us,
        cycles: input.cycles,
        stack_bytes: input.stack_bytes,
        sessions_remaining: input.sessions_remaining,
        reason_mask: input.reason_mask,
        observed_at_ms: input.observed_at_ms.unwrap_or(now_ms),
    }
}
