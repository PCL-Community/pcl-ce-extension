use std::env;
use std::io::Write;

use crate::error::{AppError, Result};
use crate::state::AppState;

mod error;
mod state;
mod auth;
mod ipc;
mod rpc;
mod smtc;
mod toast;
mod update;
mod daemon;

#[tokio::main]
async fn main() -> Result<()> {
    // ── Initialize logging ──
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pcl_ce_extension=debug".into()),
        )
        .init();

    // ── Read environment variables ──
    let hmac_key = env::var("PCL_CE_HMAC_KEY")
        .map_err(|_| AppError::MissingEnvironmentVariable("PCL_CE_HMAC_KEY"))?;

    let working_dir = env::var("PCL_CE_WORKING_DIR")
        .map_err(|_| AppError::MissingEnvironmentVariable("PCL_CE_WORKING_DIR"))?;

    // ── Pipe ID: use override or generate random UUID ──
    let pipe_id = env::var("PCL_CE_PIPE_ID").unwrap_or_else(|_| {
        uuid::Uuid::new_v4().to_string()
    });

    // ── Generate server HMAC key (daemon → .NET auth) ──
    use base64::Engine as _;
    let server_hmac_key: Vec<u8> = {
        // Derive a 32-byte key from uuid v4 random bytes + system time entropy
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(uuid::Uuid::new_v4().as_bytes());
        hasher.update(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes(),
        );
        hasher.finalize().to_vec()
    };
    let server_key_b64 = base64::engine::general_purpose::STANDARD.encode(&server_hmac_key);

    // ── Print init JSON to stdout (critical: .NET reads this) ──
    // Must flush immediately so .NET can consume it before we block.
    let init_json = serde_json::json!({
        "pipe_id": pipe_id,
        "server_key": server_key_b64,
    });
    println!("{}", serde_json::to_string(&init_json).unwrap());
    std::io::stdout().flush().ok();
    tracing::info!("Init: pipe_id={pipe_id}, server_key={server_key_b64}");

    // ── Create application state ──
    let state = AppState::new(&working_dir, &hmac_key, &pipe_id, server_hmac_key)?;
    tracing::info!("Working directory: {}", state.working_dir.display());

    // ── Validate working directory ──
    if !state.working_dir.exists() {
        tracing::warn!(
            "Working directory does not exist, creating: {}",
            state.working_dir.display()
        );
        std::fs::create_dir_all(&state.working_dir)
            .map_err(|e| AppError::Update(format!("Cannot create working dir: {e}")))?;
    }

    // ── Initialize and run daemon ──
    let daemon = daemon::core::AppDaemon::new(state.shared());
    daemon.run().await?;

    Ok(())
}
