use std::path::PathBuf;
use thiserror::Error;

pub type Result<TOk> = std::result::Result<TOk, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    // --- General ---
    #[error("Missing environment variable: {0}")]
    MissingEnvironmentVariable(&'static str),

    #[error("Invalid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    #[error("UTF-8 decode error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // --- IPC / Named Pipe ---
    #[error("Pipe server error: {0}")]
    PipeServer(String),

    #[error("Pipe connection error: {0}")]
    PipeConnection(String),

    #[error("Pipe disconnected")]
    PipeDisconnected,

    #[error("Protocol error: {0}")]
    Protocol(String),

    // --- Auth / HMAC ---
    #[error("HMAC verification failed")]
    HmacVerificationFailed,

    #[error("Missing HMAC signature in request")]
    MissingHmac,

    #[error("Invalid HMAC key length")]
    InvalidHmacKeyLength,

    // --- RPC ---
    #[error("Unknown RPC method: {0}")]
    UnknownMethod(String),

    #[error("Invalid RPC params: {0}")]
    InvalidRpcParams(String),

    #[error("RPC error: code={code} msg={msg}")]
    RpcError { code: i32, msg: String },

    // --- SMTC ---
    #[error("SMTC error: {0}")]
    Smtc(String),

    #[error("SMTC not initialized")]
    SmtcNotInitialized,

    // --- Toast ---
    #[error("Toast error: {0}")]
    Toast(String),

    // --- Update ---
    #[error("Update error: {0}")]
    Update(String),

    #[error("Update signature verification failed")]
    UpdateSignatureFailed,

    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    // --- Windows ---
    #[error("Windows API error: {0}")]
    Windows(String),

    #[error("Windows HRESULT: 0x{0:08X}")]
    HResult(i32),
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::InvalidRpcParams(e.to_string())
    }
}

impl From<&str> for AppError {
    fn from(s: &str) -> Self {
        AppError::Windows(s.to_string())
    }
}

#[cfg(windows)]
impl From<windows::core::Error> for AppError {
    fn from(e: windows::core::Error) -> Self {
        AppError::Windows(e.to_string())
    }
}
