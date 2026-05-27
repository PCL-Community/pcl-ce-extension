use crate::auth::hmac;
use crate::error::{AppError, Result};
use crate::ipc::server::ActiveConnectionCell;
use crate::rpc::methods;
use crate::rpc::types::{
    error_codes, RpcRequest, RpcResponse,
};
use crate::state::SharedState;
use serde_json::Value;

/// Dispatch an RPC request to the appropriate handler.
///
/// This function always returns a valid `RpcResponse` — errors are encoded
/// as JSON-RPC error responses, not Rust panics.
pub fn dispatch(
    state: &SharedState,
    request: RpcRequest,
    _connection_cell: &ActiveConnectionCell,
) -> RpcResponse {
    let method = &request.method;
    let id = request.id.clone();

    // --- 1. HMAC verification (skip for auth-free methods) ---
    if !methods::is_auth_free_method(method) {
        if let Err(e) = verify_request_hmac(state, &request) {
            return match e {
                AppError::MissingHmac => {
                    RpcResponse::error(id, error_codes::AUTH_NONCE_MISSING, "Missing HMAC signature")
                }
                AppError::HmacVerificationFailed => {
                    RpcResponse::error(id, error_codes::AUTH_FAILED, "HMAC verification failed")
                }
                _ => RpcResponse::error(id, error_codes::AUTH_FAILED, "Authentication error"),
            };
        }
    }

    // --- 2. Route to handler ---
    let params = &request.params;

    match method.as_str() {
        // ── SMTC ──
        methods::SMTC_SET_MEDIA_INFO => {
            handle_result(id, handle_smtc_set_media_info(state, params))
        }
        methods::SMTC_SET_PLAYBACK_STATUS => {
            handle_result(id, handle_smtc_set_playback_status(state, params))
        }
        methods::SMTC_SET_TIMELINE => {
            handle_result(id, handle_smtc_set_timeline(state, params))
        }
        methods::SMTC_SET_THUMBNAIL => {
            handle_result(id, handle_smtc_set_thumbnail(state, params))
        }

        // ── Toast ──
        methods::TOAST_SHOW => {
            handle_result(id, handle_toast_show(state, params))
        }
        methods::TOAST_CLEAR => {
            handle_result(id, handle_toast_clear(state, params))
        }

        // ── Update ──
        methods::UPDATE_APPLY => {
            handle_result(id, handle_update_apply(state, params))
        }
        methods::UPDATE_STAGE_RESTART => {
            handle_result(id, handle_update_stage_restart(state, params))
        }

        // ── System ──
        methods::SYSTEM_PING => RpcResponse::success(id, Value::String("pong".to_string())),
        methods::SYSTEM_DELAY => {
            let ms = params
                .get("ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            std::thread::sleep(std::time::Duration::from_millis(ms));
            handle_result(id, Ok(serde_json::json!({"slept_ms": ms})))
        }
        methods::SYSTEM_SHUTDOWN => {
            // Signal shutdown — the caller should check this
            handle_result(id, Ok(Value::String("shutting_down".to_string())))
        }

        _ => RpcResponse::error(
            id,
            error_codes::METHOD_NOT_FOUND,
            format!("Unknown method: {method}"),
        ),
    }
}

/// Wrap a `Result<Value>` into a JSON-RPC response.
fn handle_result(id: Option<Value>, result: Result<Value>) -> RpcResponse {
    match result {
        Ok(value) => RpcResponse::success(id, value),
        Err(e) => RpcResponse::error(id, error_codes::INTERNAL_ERROR, e.to_string()),
    }
}

/// Verify the HMAC signature on a request.
fn verify_request_hmac(state: &SharedState, request: &RpcRequest) -> Result<()> {
    let hmac_val = request
        .hmac
        .as_deref()
        .ok_or(AppError::MissingHmac)?;
    let nonce = request
        .nonce
        .as_deref()
        .ok_or(AppError::MissingHmac)?;

    let valid = hmac::verify_hmac(
        &state.hmac_key,
        &request.method,
        &request.params,
        nonce,
        hmac_val,
    );

    if valid {
        Ok(())
    } else {
        Err(AppError::HmacVerificationFailed)
    }
}

// ============================================================
// Handler stubs — these will be implemented in the respective modules
// ============================================================

fn handle_smtc_set_media_info(_state: &SharedState, _params: &Value) -> Result<Value> {
    // TODO: Call smtc::manager::SmtcManager::set_media_info()
    tracing::debug!("smtc/setMediaInfo: {_params}");
    Ok(Value::Null)
}

fn handle_smtc_set_playback_status(_state: &SharedState, _params: &Value) -> Result<Value> {
    tracing::debug!("smtc/setPlaybackStatus: {_params}");
    Ok(Value::Null)
}

fn handle_smtc_set_timeline(_state: &SharedState, _params: &Value) -> Result<Value> {
    tracing::debug!("smtc/setTimeline: {_params}");
    Ok(Value::Null)
}

fn handle_smtc_set_thumbnail(_state: &SharedState, _params: &Value) -> Result<Value> {
    tracing::debug!("smtc/setThumbnail: {_params}");
    Ok(Value::Null)
}

fn handle_toast_show(_state: &SharedState, params: &Value) -> Result<Value> {
    let notification = crate::toast::manager::parse_toast_params(params)?;
    let manager = crate::toast::manager::ToastManager::new("PCL.CE.Extension");
    manager.show(&notification)?;
    Ok(serde_json::json!({"ok": true}))
}

fn handle_toast_clear(_state: &SharedState, params: &Value) -> Result<Value> {
    let tag = params
        .get("tag")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidRpcParams("missing 'tag' field".to_string()))?;
    let manager = crate::toast::manager::ToastManager::new("PCL.CE.Extension");
    manager.clear_by_tag(tag)?;
    Ok(serde_json::json!({"ok": true}))
}

fn handle_update_apply(_state: &SharedState, _params: &Value) -> Result<Value> {
    // TODO: Call update::manager::UpdateManager::apply_update()
    tracing::debug!("update/apply: {_params}");
    Ok(Value::Null)
}

fn handle_update_stage_restart(_state: &SharedState, _params: &Value) -> Result<Value> {
    tracing::debug!("update/stageRestart: {_params}");
    Ok(Value::Null)
}
