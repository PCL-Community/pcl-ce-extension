use std::time::Duration;
use tokio::sync::watch;

use crate::error::Result;
use crate::ipc::server::{ActiveConnectionCell, new_connection_cell, run_accept_loop};
use crate::smtc::manager::SmtcManager;
use crate::state::SharedState;
use crate::toast::manager::ToastManager;
use crate::update::manager::UpdateManager;

/// Main daemon orchestrator.
///
/// Initializes all subsystems and runs the event loop until shutdown.
pub struct AppDaemon {
    state: SharedState,
    _smtc: Option<SmtcManager>,
    _toast: ToastManager,
    _update: UpdateManager,
    connection_cell: ActiveConnectionCell,
    shutdown_tx: watch::Sender<bool>,
}

impl AppDaemon {
    /// Create and initialize a new daemon instance.
    pub fn new(state: SharedState) -> Self {
        // Initialize managers
        let smtc = SmtcManager::new().ok();
        if smtc.is_some() {
            tracing::info!("SMTC manager initialized");
        } else {
            tracing::warn!("SMTC manager failed to initialize (non-fatal)");
        }

        let toast = ToastManager::new("PCL.CE.Extension");
        let update = UpdateManager::new(state.working_dir.clone());

        // Shutdown channel
        let (shutdown_tx, _) = watch::channel(false);

        Self {
            state,
            _smtc: smtc,
            _toast: toast,
            _update: update,
            connection_cell: new_connection_cell(),
            shutdown_tx,
        }
    }

    /// Run the daemon event loop.
    ///
    /// Starts the Named Pipe server and blocks until a shutdown signal is received.
    pub async fn run(&self) -> Result<()> {
        let pipe_path = self.state.pipe_path().to_string();
        let state = self.state.clone();
        let cell = self.connection_cell.clone();
        let shutdown_rx = self.shutdown_tx.subscribe();

        tracing::info!("Daemon starting on pipe: {}", pipe_path);
        tracing::info!("Working directory: {}", self.state.working_dir.display());

        // Start the pipe server in a blocking thread
        let pipe_handle = tokio::task::spawn_blocking(move || {
            run_accept_loop(pipe_path, state, cell, shutdown_rx);
        });

        // Wait for shutdown signal
        // Currently waits forever (or until Ctrl+C / system/shutdown RPC).
        // We use tokio::signal for graceful Ctrl+C handling.
        tokio::select! {
            result = pipe_handle => {
                match result {
                    Ok(()) => tracing::info!("Pipe server exited"),
                    Err(e) => tracing::error!("Pipe server panicked: {e}"),
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Ctrl+C received, shutting down...");
                self.shutdown().await;
            }
        }

        Ok(())
    }

    /// Trigger graceful shutdown.
    pub async fn shutdown(&self) {
        tracing::info!("Shutting down daemon...");

        // Signal the pipe server to stop accepting new connections
        self.shutdown_tx.send_replace(true);

        // Give the pipe server time to finish current request
        tokio::time::sleep(Duration::from_millis(500)).await;

        tracing::info!("Daemon shutdown complete");
    }

    /// Access the connection cell for callback registration.
    pub fn connection_cell(&self) -> &ActiveConnectionCell {
        &self.connection_cell
    }
}
