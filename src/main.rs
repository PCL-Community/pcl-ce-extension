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

    // ── Print pipe identifier to stdout (critical: .NET reads this) ──
    // Must flush immediately so .NET can consume it before we block.
    println!("PIPE={pipe_id}");
    std::io::stdout().flush().ok();
    tracing::info!("Pipe ID: {pipe_id}");

    // ── Create application state ──
    let state = AppState::new(&working_dir, &hmac_key, &pipe_id)?;
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
