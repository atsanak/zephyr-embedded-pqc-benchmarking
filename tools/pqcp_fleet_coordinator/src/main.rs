// SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

mod api;
mod cbor;
mod crypto;
mod db;
mod model;
mod rollout;
mod service;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::api::{router, AppState};
use crate::crypto::FleetSigner;
use crate::db::Database;
use crate::model::{FactoryAdmission, PolicyInput, RevocationInput, RevocationKind, RolloutInput};
use crate::rollout::{publish_policy, publish_revocation, start_rollout};

#[derive(Debug, Parser)]
#[command(name = "pqcp-fleet")]
#[command(about = "PQC trust-fabric coordinator and operator CLI")]
struct Cli {
    #[arg(long, env = "PQCP_FLEET_DB", default_value = "pqcp-fleet.sqlite3")]
    database: PathBuf,

    #[arg(long, env = "PQCP_FLEET_KEY", default_value = "pqcp-fleet-root.json")]
    signing_key: PathBuf,

    #[arg(long, env = "PQCP_FLEET_DOMAIN", default_value = "pqcp.local")]
    domain: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init,
    Keygen {
        #[arg(long)]
        force: bool,
    },
    Serve {
        #[arg(long, env = "PQCP_FLEET_LISTEN", default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
    },
    Admit {
        device_id: String,
        product_class: String,
        factory_fingerprint_hex: String,
        hardware_id_digest_hex: String,
        #[arg(long)]
        capabilities: u32,
    },
    Enroll {
        request: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Rollout {
        #[command(subcommand)]
        command: RolloutCommand,
    },
    Revoke {
        target_device_id: String,
        #[arg(value_enum)]
        kind: RevocationKind,
        subject_id: String,
        #[arg(long)]
        reason: u32,
        #[arg(long)]
        effective_at_ms: Option<u64>,
    },
    Revocations,
    Devices {
        #[arg(long)]
        state: Option<String>,
    },
    Status,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Publish {
        #[arg(long)]
        profile: String,
        #[arg(long, default_value_t = 10)]
        canary_percent: u8,
        #[arg(long, default_value_t = 5)]
        minimum_observations: u32,
        #[arg(long, default_value_t = 50)]
        maximum_failure_permille: u32,
        #[arg(long, default_value_t = 300_000)]
        observation_window_ms: u64,
        #[arg(long, default_value_t = true)]
        forbid_downgrade: bool,
        #[arg(long, default_value_t = true)]
        require_persistent_identity: bool,
    },
    List,
}

#[derive(Debug, Subcommand)]
enum RolloutCommand {
    Start { policy_id: String },
    Show { rollout_id: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pqcp_fleet_coordinator=info,tower_http=info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Init => {
            let db = Database::open(&cli.database)?;
            db.migrate()?;
            let signer = FleetSigner::load_or_generate(&cli.signing_key, false)?;
            println!(
                "initialized database={} root_fingerprint={}",
                cli.database.display(),
                signer.fingerprint_hex()
            );
        }
        Command::Keygen { force } => {
            let signer = FleetSigner::load_or_generate(&cli.signing_key, force)?;
            println!("{}", signer.fingerprint_hex());
        }
        Command::Serve { listen } => {
            serve(&cli.database, &cli.signing_key, &cli.domain, listen).await?;
        }
        Command::Admit {
            device_id,
            product_class,
            factory_fingerprint_hex,
            hardware_id_digest_hex,
            capabilities,
        } => {
            let db = ready_database(&cli.database)?;
            let admission = FactoryAdmission {
                device_id,
                product_class,
                factory_fingerprint_hex,
                hardware_id_digest_hex,
                capabilities,
                created_at_ms: rollout::now_ms(),
            };
            db.admit_factory(&admission)?;
            println!("{}", serde_json::to_string_pretty(&admission)?);
        }
        Command::Enroll {
            request,
            output_dir,
        } => {
            let db = ready_database(&cli.database)?;
            let signer = FleetSigner::load_or_generate(&cli.signing_key, false)?;
            let request_cbor = fs::read(&request)
                .with_context(|| format!("read enrollment request {}", request.display()))?;
            let response = service::issue_enrollment(
                &db,
                &signer,
                &cli.domain,
                &request_cbor,
                rollout::now_ms(),
            )?;
            let manifest = write_enrollment_bundle(&output_dir, &response)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Command::Policy { command } => {
            let db = ready_database(&cli.database)?;
            match command {
                PolicyCommand::Publish {
                    profile,
                    canary_percent,
                    minimum_observations,
                    maximum_failure_permille,
                    observation_window_ms,
                    forbid_downgrade,
                    require_persistent_identity,
                } => {
                    let signer = FleetSigner::load_or_generate(&cli.signing_key, false)?;
                    let policy = publish_policy(
                        &db,
                        &signer,
                        &cli.domain,
                        PolicyInput {
                            profile,
                            canary_percent,
                            minimum_observations,
                            maximum_failure_permille,
                            observation_window_ms,
                            forbid_downgrade,
                            require_persistent_identity,
                        },
                    )?;
                    println!("{}", serde_json::to_string_pretty(&policy)?);
                }
                PolicyCommand::List => {
                    println!("{}", serde_json::to_string_pretty(&db.list_policies()?)?);
                }
            }
        }
        Command::Rollout { command } => {
            let db = ready_database(&cli.database)?;
            match command {
                RolloutCommand::Start { policy_id } => {
                    let rollout = start_rollout(&db, RolloutInput { policy_id })?;
                    println!("{}", serde_json::to_string_pretty(&rollout)?);
                }
                RolloutCommand::Show { rollout_id } => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&db.rollout_status(&rollout_id)?)?
                    );
                }
            }
        }
        Command::Revoke {
            target_device_id,
            kind,
            subject_id,
            reason,
            effective_at_ms,
        } => {
            let db = ready_database(&cli.database)?;
            let signer = FleetSigner::load_or_generate(&cli.signing_key, false)?;
            let revocation = publish_revocation(
                &db,
                &signer,
                &cli.domain,
                RevocationInput {
                    target_device_id,
                    kind,
                    subject_id,
                    reason,
                    effective_at_ms,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&revocation)?);
        }
        Command::Revocations => {
            let db = ready_database(&cli.database)?;
            println!("{}", serde_json::to_string_pretty(&db.list_revocations()?)?);
        }
        Command::Devices { state } => {
            let db = ready_database(&cli.database)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&db.list_devices(state.as_deref())?)?
            );
        }
        Command::Status => {
            let db = ready_database(&cli.database)?;
            println!("{}", serde_json::to_string_pretty(&db.status()?)?);
        }
    }
    Ok(())
}

fn ready_database(path: &Path) -> Result<Database> {
    let db = Database::open(path)?;
    db.migrate()?;
    Ok(db)
}

fn write_enrollment_bundle(
    output_dir: &Path,
    response: &crate::model::EnrollmentResponse,
) -> Result<serde_json::Value> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("create enrollment output {}", output_dir.display()))?;
    let voucher = STANDARD
        .decode(&response.voucher_cbor_b64)
        .context("decode generated voucher")?;
    let credential = STANDARD
        .decode(&response.credential_cbor_b64)
        .context("decode generated credential")?;
    let root_public_key = STANDARD
        .decode(&response.root_public_key_b64)
        .context("decode generated root public key")?;
    let voucher_path = output_dir.join("ownership-voucher.cbor");
    let credential_path = output_dir.join("operational-credential.cbor");
    let root_path = output_dir.join("fleet-root-public-key.bin");
    let response_path = output_dir.join("enrollment-response.json");

    write_atomic(&voucher_path, &voucher)?;
    write_atomic(&credential_path, &credential)?;
    write_atomic(&root_path, &root_public_key)?;
    write_atomic(
        &response_path,
        &serde_json::to_vec_pretty(response).context("encode enrollment response")?,
    )?;
    Ok(serde_json::json!({
        "device_id": response.device.device_id,
        "root_fingerprint_hex": response.root_fingerprint_hex,
        "voucher": voucher_path,
        "credential": credential_path,
        "root_public_key": root_path,
        "response": response_path,
    }))
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, contents)
        .with_context(|| format!("write temporary artifact {}", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("install artifact {}", path.display()))
}

async fn serve(
    database: &Path,
    signing_key: &Path,
    domain: &str,
    listen: SocketAddr,
) -> Result<()> {
    let db = ready_database(database)?;
    let signer = FleetSigner::load_or_generate(signing_key, false)?;
    let fingerprint = signer.fingerprint_hex();
    let (events, _) = broadcast::channel(256);
    let state = Arc::new(AppState {
        db,
        signer,
        domain: domain.to_owned(),
        events,
    });
    let app = router(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind coordinator to {listen}"))?;
    info!(%listen, root_fingerprint = %fingerprint, "fleet coordinator listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve coordinator")?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
