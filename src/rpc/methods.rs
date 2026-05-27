/// RPC method names as constants.

// ── SMTC ──
/// Set current media information (title, artist, album, thumbnail).
pub const SMTC_SET_MEDIA_INFO: &str = "smtc/setMediaInfo";
/// Set playback status (playing / paused / stopped).
pub const SMTC_SET_PLAYBACK_STATUS: &str = "smtc/setPlaybackStatus";
/// Set timeline position and duration.
pub const SMTC_SET_TIMELINE: &str = "smtc/setTimeline";
/// Set thumbnail image (file path or base64).
pub const SMTC_SET_THUMBNAIL: &str = "smtc/setThumbnail";

// ── Toast ──
/// Show a toast notification.
pub const TOAST_SHOW: &str = "toast/show";
/// Remove a toast by tag.
pub const TOAST_CLEAR: &str = "toast/clear";

// ── Update ──
/// Apply an update package (write files).
pub const UPDATE_APPLY: &str = "update/apply";
/// Stage a restart (write update.bat, schedule restart).
pub const UPDATE_STAGE_RESTART: &str = "update/stageRestart";
/// Report update progress back to .NET.
pub const UPDATE_PROGRESS: &str = "update/progress";

// ── System ──
/// Ping / health check.
pub const SYSTEM_PING: &str = "system/ping";
/// Graceful shutdown.
pub const SYSTEM_SHUTDOWN: &str = "system/shutdown";
/// Server-side delay (ms). Returns after sleeping.
pub const SYSTEM_DELAY: &str = "system/delay";

/// Methods that DO NOT require HMAC authentication.
pub fn is_auth_free_method(method: &str) -> bool {
    matches!(method, SYSTEM_PING)
}
