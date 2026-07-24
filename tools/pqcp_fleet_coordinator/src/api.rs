// SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use tokio::sync::broadcast;

use crate::crypto::FleetSigner;
use crate::db::{observation_from_input, Database};
use crate::model::{
    ApiErrorBody, EnrollmentResponse, EnrollmentSubmission, Event, Health, ObservationInput,
    Policy, PolicyInput, Revocation, RevocationInput, Rollout, RolloutInput, RolloutStatus,
};
use crate::rollout::{now_ms, publish_policy, publish_revocation, start_rollout};
use crate::service::issue_enrollment;

pub struct AppState {
    pub db: Database,
    pub signer: FleetSigner,
    pub domain: String,
    pub events: broadcast::Sender<Event>,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/health", get(health))
        .route("/v1/enroll", post(enroll))
        .route("/v1/devices", get(devices))
        .route("/v1/policies", get(policies).post(create_policy))
        .route("/v1/revocations", get(revocations).post(create_revocation))
        .route("/v1/rollouts", post(create_rollout))
        .route("/v1/rollouts/{rollout_id}", get(rollout_status))
        .route(
            "/v1/rollouts/{rollout_id}/observations",
            post(record_observation),
        )
        .route("/v1/events", get(events))
        .route("/v1/events/stream", get(event_stream))
        .with_state(state)
}

async fn health(State(state): State<Arc<AppState>>) -> Result<Json<Health>, ApiError> {
    Ok(Json(Health {
        status: "ok",
        protocol: "PQCP-FLEET-CBOR-V1",
        root_fingerprint_hex: state.signer.fingerprint_hex(),
        database: state.db.status()?,
    }))
}

#[derive(Debug, Deserialize)]
struct DeviceQuery {
    state: Option<String>,
}

async fn devices(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DeviceQuery>,
) -> Result<Json<Vec<crate::model::Device>>, ApiError> {
    Ok(Json(state.db.list_devices(query.state.as_deref())?))
}

async fn enroll(
    State(state): State<Arc<AppState>>,
    Json(submission): Json<EnrollmentSubmission>,
) -> Result<(StatusCode, Json<EnrollmentResponse>), ApiError> {
    let request = STANDARD
        .decode(submission.request_cbor_b64)
        .context("request_cbor_b64 is not valid base64")?;
    let timestamp = now_ms();
    let response = issue_enrollment(&state.db, &state.signer, &state.domain, &request, timestamp)?;
    publish_latest_event(&state);
    Ok((StatusCode::CREATED, Json(response)))
}

async fn policies(State(state): State<Arc<AppState>>) -> Result<Json<Vec<Policy>>, ApiError> {
    Ok(Json(state.db.list_policies()?))
}

async fn create_policy(
    State(state): State<Arc<AppState>>,
    Json(input): Json<PolicyInput>,
) -> Result<(StatusCode, Json<Policy>), ApiError> {
    let policy = publish_policy(&state.db, &state.signer, &state.domain, input)?;
    publish_latest_event(&state);
    Ok((StatusCode::CREATED, Json(policy)))
}

async fn revocations(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<Revocation>>, ApiError> {
    Ok(Json(state.db.list_revocations()?))
}

async fn create_revocation(
    State(state): State<Arc<AppState>>,
    Json(input): Json<RevocationInput>,
) -> Result<(StatusCode, Json<Revocation>), ApiError> {
    let revocation = publish_revocation(&state.db, &state.signer, &state.domain, input)?;
    publish_latest_event(&state);
    Ok((StatusCode::CREATED, Json(revocation)))
}

async fn create_rollout(
    State(state): State<Arc<AppState>>,
    Json(input): Json<RolloutInput>,
) -> Result<(StatusCode, Json<Rollout>), ApiError> {
    let rollout = start_rollout(&state.db, input)?;
    publish_latest_event(&state);
    Ok((StatusCode::CREATED, Json(rollout)))
}

async fn rollout_status(
    State(state): State<Arc<AppState>>,
    Path(rollout_id): Path<String>,
) -> Result<Json<RolloutStatus>, ApiError> {
    Ok(Json(state.db.rollout_status(&rollout_id)?))
}

async fn record_observation(
    State(state): State<Arc<AppState>>,
    Path(rollout_id): Path<String>,
    Json(input): Json<ObservationInput>,
) -> Result<Json<RolloutStatus>, ApiError> {
    validate_observation(&input)?;
    let timestamp = now_ms();
    let observation = observation_from_input(&rollout_id, input, timestamp);
    state.db.record_observation(&rollout_id, &observation)?;
    publish_latest_event(&state);
    state.db.evaluate_rollout(&rollout_id, timestamp)?;
    publish_latest_event(&state);
    Ok(Json(state.db.rollout_status(&rollout_id)?))
}

#[derive(Debug, Deserialize)]
struct EventQuery {
    #[serde(default)]
    after: i64,
    #[serde(default = "default_event_limit")]
    limit: usize,
}

fn default_event_limit() -> usize {
    100
}

async fn events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Vec<Event>>, ApiError> {
    Ok(Json(state.db.recent_events(query.after, query.limit)?))
}

async fn event_stream(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EventQuery>,
) -> Sse<impl futures_core::Stream<Item = Result<SseEvent, Infallible>>> {
    let historical = state
        .db
        .recent_events(query.after, query.limit)
        .unwrap_or_default();
    let mut receiver = state.events.subscribe();
    let stream = async_stream::stream! {
        for event in historical {
            yield Ok(event_to_sse(&event));
        }
        loop {
            match receiver.recv().await {
                Ok(event) => yield Ok(event_to_sse(&event)),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("pqcp-fleet"),
    )
}

fn event_to_sse(event: &Event) -> SseEvent {
    SseEvent::default()
        .id(event.event_id.to_string())
        .event(&event.kind)
        .json_data(event)
        .unwrap_or_else(|_| SseEvent::default().event("serialization-error"))
}

fn publish_latest_event(state: &AppState) {
    if let Ok(Some(event)) = state.db.latest_event() {
        let _ = state.events.send(event);
    }
}

fn validate_identifier(value: &str, capacity: usize, field: &str) -> anyhow::Result<()> {
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

fn validate_observation(observation: &ObservationInput) -> anyhow::Result<()> {
    validate_identifier(&observation.device_id, 48, "device_id")?;
    if observation.sequence == 0 {
        bail!("sequence must be non-zero");
    }
    if observation.success && observation.reason_mask != 0 {
        bail!("successful observations cannot carry a failure reason");
    }
    Ok(())
}

#[derive(Debug)]
pub struct ApiError(anyhow::Error);

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(value: E) -> Self {
        Self(value.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let message = format!("{:#}", self.0);
        let status = if message.contains("not found") {
            StatusCode::NOT_FOUND
        } else if message.contains("already")
            || message.contains("stale")
            || message.contains("not accepting")
        {
            StatusCode::CONFLICT
        } else if message.contains("database")
            || message.contains("SQL")
            || message.contains("disk")
        {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::BAD_REQUEST
        };
        (status, Json(ApiErrorBody { error: message })).into_response()
    }
}

async fn dashboard() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PQCP Trust Fabric</title>
<style>
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui;background:#08111f;color:#e7eef9}
body{margin:0;background:radial-gradient(circle at 20% 0,#163052 0,transparent 35%),#08111f}
main{max-width:1080px;margin:auto;padding:48px 24px}
h1{font-size:clamp(2rem,5vw,4rem);letter-spacing:-.05em;margin:.2em 0}
.eyebrow{color:#68d7ff;text-transform:uppercase;letter-spacing:.16em;font-weight:700}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px;margin-top:32px}
.card{background:#0d1b2dbf;border:1px solid #28415f;border-radius:16px;padding:20px;box-shadow:0 16px 48px #0005}
.value{font-size:2.2rem;font-weight:750;margin-top:8px}.muted{color:#96abc5}
#events{margin-top:24px;max-height:360px;overflow:auto;font-family:ui-monospace,monospace;font-size:.84rem}
.event{padding:10px 0;border-bottom:1px solid #223751}.ok{color:#6df2ad}.warn{color:#ffd166}
</style>
</head>
<body><main>
<div class="eyebrow">Live PQC Trust Fabric</div>
<h1>Cryptographic fleet control<br>with bounded autonomy.</h1>
<p class="muted">ML-DSA-65 signed policy, deterministic canaries, measured promotion, automatic rollback.</p>
<section class="grid">
<div class="card"><div class="muted">Devices</div><div class="value" id="devices">—</div></div>
<div class="card"><div class="muted">Operational</div><div class="value" id="operational">—</div></div>
<div class="card"><div class="muted">Policies</div><div class="value" id="policies">—</div></div>
<div class="card"><div class="muted">Active rollouts</div><div class="value" id="rollouts">—</div></div>
</section>
<section class="card" id="events"><div class="muted">Waiting for fleet events…</div></section>
</main>
<script>
const q=id=>document.getElementById(id);
async function refresh(){
 const h=await fetch('/health').then(r=>r.json());
 q('devices').textContent=h.database.devices;
 q('operational').textContent=h.database.operational_devices;
 q('policies').textContent=h.database.policies;
 q('rollouts').textContent=h.database.active_rollouts;
}
function append(e){
 const row=document.createElement('div'); row.className='event';
 const data=JSON.parse(e.data);
 row.textContent=`${new Date(data.created_at_ms).toISOString()}  ${data.kind}  ${data.subject_id}`;
 q('events').prepend(row); while(q('events').children.length>100) q('events').lastChild.remove();
 refresh();
}
const stream=new EventSource('/v1/events/stream');
['factory.admitted','device.enrolled','policy.published','revocation.published','rollout.draft','rollout.canary','rollout.observation','rollout.promoting','rollout.draining','rollout.completed','rollout.rolled_back']
 .forEach(kind=>stream.addEventListener(kind,append));
refresh(); setInterval(refresh,15000);
</script></body></html>"#,
    )
}
