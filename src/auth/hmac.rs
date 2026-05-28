use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Maximum allowed clock skew / replay window: 30 seconds.
pub const TS_WINDOW_MS: u64 = 30_000;

/// Get current Unix timestamp in milliseconds.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Check whether a timestamp is within the allowed replay window.
pub fn ts_in_window(ts_ms: u64) -> bool {
    let now = now_ms();
    let diff = now.abs_diff(ts_ms);
    diff <= TS_WINDOW_MS
}

// ── HMAC computation ──

/// Compute HMAC-SHA256 of `method`.`canonical_params`.`ts_ms` and return hex.
pub fn compute_hmac(secret: &[u8], method: &str, params: &Value, ts_ms: u64) -> String {
    let payload = build_hmac_payload(method, params, ts_ms);
    compute_hmac_raw(secret, &payload)
}

/// Compute HMAC for an arbitrary payload string (already formatted).
pub fn compute_hmac_raw(secret: &[u8], payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key length should be valid");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Build the canonical HMAC payload: `method`.`canonical_params`.`ts_ms`
fn build_hmac_payload(method: &str, params: &Value, ts_ms: u64) -> String {
    let params_str = canonical_json(params);
    format!("{}.{}.{}", method, params_str, ts_ms)
}

// ── Verification ──

/// Verify a HMAC signature, including timestamp replay-window check.
/// Returns `true` only if both timestamp and HMAC are valid.
pub fn verify_hmac(
    secret: &[u8],
    method: &str,
    params: &Value,
    ts_ms: u64,
    expected_hex: &str,
) -> bool {
    if !ts_in_window(ts_ms) {
        return false;
    }
    let computed = compute_hmac(secret, method, params, ts_ms);
    constant_time_eq(computed.as_bytes(), expected_hex.as_bytes())
}

// ── Constant-time comparison ──

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

// ── Canonical JSON ──

/// Deterministic JSON serialization with sorted keys.
///
/// Produces the same output for semantically identical inputs,
/// which is essential for HMAC verification.
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s)),
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let items: Vec<String> = keys
                .iter()
                .map(|k| {
                    let k_escaped =
                        serde_json::to_string(k).unwrap_or_else(|_| format!("\"{}\"", k));
                    let v = canonical_json(&obj[*k]);
                    format!("{}:{}", k_escaped, v)
                })
                .collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_json_object_sorts_keys() {
        let v = json!({"z": 1, "a": 2, "m": 3});
        assert_eq!(canonical_json(&v), r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_canonical_json_nested() {
        let v = json!({"b": {"y": 1, "x": 2}, "a": 1});
        assert_eq!(canonical_json(&v), r#"{"a":1,"b":{"x":2,"y":1}}"#);
    }

    #[test]
    fn test_hmac_roundtrip() {
        let secret = b"super-secret-key-32-bytes-long!!";
        let params = json!({"title": "Song", "artist": "Me"});
        let ts = now_ms();
        let sig = compute_hmac(secret, "smtc/setMediaInfo", &params, ts);
        assert!(verify_hmac(secret, "smtc/setMediaInfo", &params, ts, &sig));
        // Different ts → different sig → fails
        assert!(!verify_hmac(
            secret,
            "smtc/setMediaInfo",
            &params,
            ts + 1,
            &sig
        ));
    }

    #[test]
    fn test_ts_outside_window() {
        let secret = b"test-key-16-bytes!";
        let params = json!({"a": 1});
        let old_ts = now_ms() - TS_WINDOW_MS - 1;
        let sig = compute_hmac(secret, "m", &params, old_ts);
        // Even with correct HMAC, stale timestamp should fail
        assert!(!verify_hmac(secret, "m", &params, old_ts, &sig));
    }
}
