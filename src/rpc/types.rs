use serde::{Deserialize, Serialize};
use serde_json::Value;

// ============================================================
// JSON-RPC 2.0 Request
// ============================================================

/// Incoming JSON-RPC 2.0 request from .NET.
#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: Option<String>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    pub id: Option<Value>,

    /// HMAC-SHA256 signature: hex(SHA256(secret, method.canonical(params).nonce))
    #[serde(rename = "_hmac")]
    pub hmac: Option<String>,

    /// Unique nonce to prevent replay attacks.
    #[serde(rename = "_nonce")]
    pub nonce: Option<String>,
}

// ============================================================
// JSON-RPC 2.0 Response
// ============================================================

/// Outgoing JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcErrorData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
}

impl RpcResponse {
    /// Create a success response.
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Create an error response.
    pub fn error(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(RpcErrorData {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }

    /// Create an error response with additional data.
    pub fn error_with_data(
        id: Option<Value>,
        code: i32,
        message: impl Into<String>,
        data: Value,
    ) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(RpcErrorData {
                code,
                message: message.into(),
                data: Some(data),
            }),
            id,
        }
    }
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Serialize)]
pub struct RpcErrorData {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// ============================================================
// Standard JSON-RPC error codes
// ============================================================

pub mod error_codes {
    /// Parse error: invalid JSON
    pub const PARSE_ERROR: i32 = -32700;
    /// Invalid Request: the JSON is valid but not a valid Request object
    pub const INVALID_REQUEST: i32 = -32600;
    /// Method not found
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// Invalid method parameter(s)
    pub const INVALID_PARAMS: i32 = -32602;
    /// Internal JSON-RPC error
    pub const INTERNAL_ERROR: i32 = -32603;

    /// Custom: HMAC authentication failed
    pub const AUTH_FAILED: i32 = -32001;
    /// Custom: HMAC nonce missing
    pub const AUTH_NONCE_MISSING: i32 = -32002;
    /// Custom: Resource not initialized (e.g. SMTC)
    pub const NOT_INITIALIZED: i32 = -32010;
}

// ============================================================
// JSON-RPC 2.0 Notification (from daemon → .NET)
// ============================================================

/// A message sent from the daemon to .NET (not a response, but a method call).
/// Used for SMTC callbacks and progress updates.
#[derive(Debug, Serialize)]
pub struct RpcNotification {
    pub jsonrpc: String,
    pub method: String,
    pub params: Value,
}

impl RpcNotification {
    pub fn new(method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
        }
    }
}
