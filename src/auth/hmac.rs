use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde_json::Value;

type HmacSha256 = Hmac<Sha256>;

/// Build the canonical HMAC payload: `method`.`canonical_params`.`nonce`
fn build_hmac_payload(method: &str, params: &Value, nonce: &str) -> String {
    let params_str = canonical_json(params);
    format!("{}.{}.{}", method, params_str, nonce)
}

/// Compute HMAC-SHA256 and return hex string.
pub fn compute_hmac(secret: &[u8], method: &str, params: &Value, nonce: &str) -> String {
    let payload = build_hmac_payload(method, params, nonce);
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC key length should be valid");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time byte comparison to prevent timing side-channel attacks.
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

/// Verify a HMAC signature against the request fields.
/// Returns `true` if the signature matches (constant-time comparison).
pub fn verify_hmac(
    secret: &[u8],
    method: &str,
    params: &Value,
    nonce: &str,
    expected_hex: &str,
) -> bool {
    let computed = compute_hmac(secret, method, params, nonce);
    constant_time_eq(computed.as_bytes(), expected_hex.as_bytes())
}

/// Deterministic JSON serialization with sorted keys.
///
/// Produces the same output for semantically identical inputs,
/// which is essential for HMAC verification.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => {
            // Escape JSON string properly
            serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s))
        }
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
                    let k_escaped = serde_json::to_string(k).unwrap_or_else(|_| format!("\"{}\"", k));
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
        let sig = compute_hmac(secret, "smtc/setMediaInfo", &params, "nonce-1");
        assert!(verify_hmac(secret, "smtc/setMediaInfo", &params, "nonce-1", &sig));
        assert!(!verify_hmac(secret, "smtc/setMediaInfo", &params, "nonce-2", &sig));
    }
}
