use std::path::{Path, PathBuf};

use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Parameters for applying an update.
#[derive(Debug, Deserialize)]
pub struct UpdatePackage {
    /// Relative paths within working_dir → file contents (base64 encoded).
    pub files: Vec<UpdateFile>,
    /// Optional signature to verify the update package.
    pub signature: Option<String>,
}

/// A single file in the update package.
#[derive(Debug, Deserialize)]
pub struct UpdateFile {
    /// Relative path from working_dir (e.g. "bin/new-version.exe").
    pub path: String,
    /// File content as base64.
    pub data: String,
}

/// Progress information sent back to .NET.
#[derive(Debug, Serialize)]
pub struct UpdateProgress {
    pub current: u32,
    pub total: u32,
    pub stage: String,
}

/// Update Manager — handles update package application and restart staging.
pub struct UpdateManager {
    working_dir: PathBuf,
}

impl UpdateManager {
    /// Create a new UpdateManager with the given working directory.
    pub fn new(working_dir: impl Into<PathBuf>) -> Self {
        Self {
            working_dir: working_dir.into(),
        }
    }

    /// Apply an update package: decode base64 files and write them to disk.
    ///
    /// Currently a skeleton — will add atomic writes + rollback on failure.
    pub fn apply_update(&self, package: &UpdatePackage) -> Result<()> {
        use base64::Engine as _;
        let engine = base64::engine::general_purpose::STANDARD;

        for file in &package.files {
            let target_path = self.working_dir.join(&file.path);

            // Create parent directories
            if let Some(parent) = target_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    AppError::Update(format!(
                        "Failed to create directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }

            // Decode and write file
            let decoded = engine
                .decode(&file.data)
                .map_err(|e| AppError::Update(format!("Base64 decode failed: {e}")))?;

            std::fs::write(&target_path, &decoded).map_err(|e| {
                AppError::Update(format!("Failed to write {}: {e}", target_path.display()))
            })?;

            tracing::debug!("Update wrote: {}", target_path.display());
        }

        tracing::info!("Update applied: {} files", package.files.len());
        Ok(())
    }

    /// Stage a restart: create a batch script that waits for the daemon to exit,
    /// replaces the executable, then restarts.
    ///
    /// Returns the path to the generated script.
    pub fn stage_restart(&self, new_exe_path: &Path) -> Result<PathBuf> {
        let script_path = self.working_dir.join("restart_daemon.bat");

        // Build a script that:
        // 1. Waits for the current process to exit (by PID)
        // 2. Copies the new EXE over the old one
        // 3. Starts the new EXE
        // 4. Cleans up the script
        let current_exe = std::env::current_exe()
            .map_err(|e| AppError::Update(format!("Cannot get current exe path: {e}")))?;

        let script_content = format!(
            r#"@echo off
chcp 65001 > nul
title PCL CE Daemon Restart

:: Wait for current process to exit
:wait
tasklist /FI "PID eq %PPID%" 2>nul | findstr /I "{}" >nul
if not errorlevel 1 (
    timeout /t 1 /nobreak > nul
    goto wait
)

:: Replace executable
copy /Y "{}" "{}" > nul

:: Start new daemon
start "" "{}"

:: Cleanup self
del "%~f0"
"#,
            // Just check PID presence
            "%PPID%",
            new_exe_path.display(),
            current_exe.display(),
            current_exe.display(),
        );

        std::fs::write(&script_path, script_content)
            .map_err(|e| AppError::Update(format!("Failed to write restart script: {e}")))?;

        tracing::info!("Restart script staged: {}", script_path.display());
        Ok(script_path)
    }

    /// Get the working directory path.
    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }
}

/// Parse update params from an RPC request.
pub fn parse_update_params(params: &Value) -> Result<UpdatePackage> {
    serde_json::from_value(params.clone()).map_err(|e| AppError::InvalidRpcParams(e.to_string()))
}
