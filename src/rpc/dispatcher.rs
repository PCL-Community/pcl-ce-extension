use crate::auth::hmac;
use crate::error::{AppError, Result};
use crate::ipc::server::ActiveConnectionCell;
use crate::rpc::methods;
use crate::rpc::types::{RpcRequest, RpcResponse, error_codes};
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
    if !methods::is_auth_free_method(method)
        && let Err(e) = verify_request_hmac(state, &request)
    {
        return match e {
            AppError::MissingHmac => RpcResponse::error(
                id,
                error_codes::AUTH_TS_MISSING,
                "Missing HMAC signature or timestamp",
            ),
            AppError::HmacVerificationFailed => {
                RpcResponse::error(id, error_codes::AUTH_FAILED, "HMAC verification failed")
            }
            _ => RpcResponse::error(id, error_codes::AUTH_FAILED, "Authentication error"),
        };
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
        methods::SMTC_SET_TIMELINE => handle_result(id, handle_smtc_set_timeline(state, params)),
        methods::SMTC_SET_THUMBNAIL => handle_result(id, handle_smtc_set_thumbnail(state, params)),

        // ── Toast ──
        methods::TOAST_SHOW => handle_result(id, handle_toast_show(state, params)),
        methods::TOAST_CLEAR => handle_result(id, handle_toast_clear(state, params)),

        // ── Update ──
        methods::UPDATE_APPLY => handle_result(id, handle_update_apply(state, params)),
        methods::UPDATE_STAGE_RESTART => {
            handle_result(id, handle_update_stage_restart(state, params))
        }

        // ── System ──
        methods::SYSTEM_PING => RpcResponse::success(id, Value::String("pong".to_string())),
        methods::SYSTEM_DELAY => {
            let ms = params.get("ms").and_then(|v| v.as_u64()).unwrap_or(0);
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

/// Sign a response with the daemon's server HMAC key.
///
/// Adds `_hmac` and `_ts` fields so .NET can verify the response
/// came from the genuine daemon (bidirectional auth with replay protection).
pub fn sign_response(response: &mut RpcResponse, server_key: &[u8]) {
    use crate::auth::hmac::{canonical_json, compute_hmac_raw, now_ms};

    let ts = now_ms();
    let content = match (&response.result, &response.error) {
        (Some(r), _) => canonical_json(r),
        (_, Some(e)) => canonical_json(&serde_json::to_value(e).unwrap_or_default()),
        (None, None) => "null".to_string(),
    };
    let payload = format!("$response.{}.{}", content, ts);
    response.hmac = Some(compute_hmac_raw(server_key, &payload));
    response.ts = Some(ts);
}

/// Wrap a `Result<Value>` into a JSON-RPC response.
fn handle_result(id: Option<Value>, result: Result<Value>) -> RpcResponse {
    match result {
        Ok(value) => RpcResponse::success(id, value),
        Err(e) => RpcResponse::error(id, error_codes::INTERNAL_ERROR, e.to_string()),
    }
}

/// Verify the HMAC signature on a request (with timestamp replay check).
fn verify_request_hmac(state: &SharedState, request: &RpcRequest) -> Result<()> {
    let hmac_val = request.hmac.as_deref().ok_or(AppError::MissingHmac)?;
    let ts = request.ts.ok_or(AppError::MissingHmac)?;

    let valid = hmac::verify_hmac(
        &state.hmac_key,
        &request.method,
        &request.params,
        ts,
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
    let manager = crate::toast::manager::ToastManager::new("PCL-Community.PCL");
    manager.show(&notification)?;
    Ok(serde_json::json!({"ok": true}))
}

fn handle_toast_clear(_state: &SharedState, params: &Value) -> Result<Value> {
    let tag = params
        .get("tag")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidRpcParams("missing 'tag' field".to_string()))?;
    let manager = crate::toast::manager::ToastManager::new("PCL-Community.PCL");
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
