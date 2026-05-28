use crate::error::{AppError, Result};
use serde::Deserialize;
use serde_json::Value;

/// Playback status for SMTC.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PlaybackStatus {
    Playing,
    Paused,
    Stopped,
}

impl PlaybackStatus {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "playing" | "Playing" => Some(Self::Playing),
            "paused" | "Paused" => Some(Self::Paused),
            "stopped" | "Stopped" => Some(Self::Stopped),
            _ => None,
        }
    }
}

/// Media information payload.
#[derive(Debug, Deserialize)]
pub struct MediaInfo {
    pub title: Option<String>,
    pub artist: Option<String>,
    pub album: Option<String>,
    pub thumbnail_path: Option<String>,
}

/// Timeline information.
#[derive(Debug, Deserialize)]
pub struct Timeline {
    pub position_sec: f64,
    pub duration_sec: f64,
}

/// SMTC commands that the user can trigger (→ forwarded to .NET).
#[derive(Debug, Clone)]
pub enum SmtcCommand {
    Play,
    Pause,
    TogglePlayPause,
    Next,
    Previous,
    Stop,
}

impl SmtcCommand {
    pub fn method_name(&self) -> &'static str {
        match self {
            Self::Play => "smtc/onPlay",
            Self::Pause => "smtc/onPause",
            Self::TogglePlayPause => "smtc/onTogglePlayPause",
            Self::Next => "smtc/onNext",
            Self::Previous => "smtc/onPrevious",
            Self::Stop => "smtc/onStop",
        }
    }
}

/// SMTC Manager — wrapper around Windows SystemMediaTransportControls.
///
/// On non-Windows platforms, this is a no-op stub.
pub struct SmtcManager;

impl SmtcManager {
    /// Create and initialize a new SMTC manager.
    ///
    /// Currently a skeleton — will be filled with `windows::System::Media::*` API calls.
    #[cfg(windows)]
    pub fn new() -> Result<Self> {
        // TODO: Initialize SystemMediaTransportControls
        // let smtc = SystemMediaTransportControls::new()?;
        // smtc.set_is_play_enabled(true)?;
        // smtc.set_is_pause_enabled(true)?;
        // smtc.set_is_next_enabled(true)?;
        // smtc.set_is_previous_enabled(true)?;
        tracing::info!("SMTC manager initialized (Windows)");
        Ok(Self)
    }

    #[cfg(not(windows))]
    pub fn new() -> Result<Self> {
        tracing::warn!("SMTC not available on non-Windows platforms");
        Ok(Self)
    }

    /// Set current media metadata (title, artist, album).
    pub fn set_media_info(&self, _info: &MediaInfo) -> Result<()> {
        // TODO: Update SystemMediaTransportControlsDisplayUpdater
        tracing::debug!("SMTC setMediaInfo: {_info:?}");
        Ok(())
    }

    /// Set playback status.
    pub fn set_playback_status(&self, _status: PlaybackStatus) -> Result<()> {
        // TODO: Set smtc.playback_status
        tracing::debug!("SMTC setPlaybackStatus: {_status:?}");
        Ok(())
    }

    /// Set timeline position and duration.
    pub fn set_timeline(&self, _timeline: &Timeline) -> Result<()> {
        // TODO: Update timeline via SystemMediaTransportControlsTimelineProperties
        tracing::debug!(
            "SMTC setTimeline: position={}s, duration={}s",
            _timeline.position_sec,
            _timeline.duration_sec
        );
        Ok(())
    }

    /// Set thumbnail from a file path.
    pub fn set_thumbnail(&self, _path: &str) -> Result<()> {
        // TODO: Load file and set as thumbnail via RandomAccessStreamReference
        tracing::debug!("SMTC setThumbnail: {_path}");
        Ok(())
    }
}

/// Parse the `params` value from an RPC request into `MediaInfo`.
pub fn parse_media_info(params: &Value) -> Result<MediaInfo> {
    serde_json::from_value(params.clone()).map_err(|e| AppError::InvalidRpcParams(e.to_string()))
}

/// Parse playback status from RPC params.
pub fn parse_playback_status(params: &Value) -> Result<PlaybackStatus> {
    let status_str = params
        .get("status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidRpcParams("missing 'status' field".to_string()))?;

    PlaybackStatus::from_str(status_str)
        .ok_or_else(|| AppError::InvalidRpcParams(format!("invalid status: {status_str}")))
}

/// Parse timeline from RPC params.
pub fn parse_timeline(params: &Value) -> Result<Timeline> {
    serde_json::from_value(params.clone()).map_err(|e| AppError::InvalidRpcParams(e.to_string()))
}
