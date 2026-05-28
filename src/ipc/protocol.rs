use crate::error::{AppError, Result};

/// Maximum frame payload size: 1 MiB.
const MAX_PAYLOAD_SIZE: u32 = 1024 * 1024;

/// Frame header size (4-byte LE length prefix).
const HEADER_SIZE: usize = 4;

/// Encode a JSON payload into a binary frame.
///
/// Format: `[4-byte LE payload_length][N-byte payload]`
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>> {
    let len = payload.len();
    if len > MAX_PAYLOAD_SIZE as usize {
        return Err(AppError::Protocol(format!(
            "Payload too large: {len} bytes (max {MAX_PAYLOAD_SIZE})"
        )));
    }

    let mut frame = Vec::with_capacity(HEADER_SIZE + len);
    frame.extend_from_slice(&(len as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Decode the payload length from a frame header.
/// Returns `None` if not enough data is available.
pub fn decode_frame_header(data: &[u8]) -> Option<(u32, usize)> {
    if data.len() < HEADER_SIZE {
        return None;
    }
    let len_bytes: [u8; 4] = data[..HEADER_SIZE].try_into().ok()?;
    let payload_len = u32::from_le_bytes(len_bytes);

    if payload_len > MAX_PAYLOAD_SIZE {
        return None;
    }

    Some((payload_len, HEADER_SIZE))
}

/// Extract the payload from a complete frame.
/// Returns `None` if the full payload isn't available yet.
pub fn decode_frame_payload(data: &[u8], payload_len: u32) -> Option<&[u8]> {
    let total = HEADER_SIZE + payload_len as usize;
    if data.len() < total {
        return None;
    }
    Some(&data[HEADER_SIZE..total])
}

/// Read one complete frame from a blocking reader.
///
/// Returns the raw payload bytes (without the length prefix).
pub fn read_frame<R: std::io::Read>(reader: &mut R) -> Result<Vec<u8>> {
    // Read 4-byte length header
    let mut header = [0u8; HEADER_SIZE];
    reader.read_exact(&mut header)?;
    let payload_len = u32::from_le_bytes(header);

    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(AppError::Protocol(format!(
            "Frame payload too large: {payload_len} bytes"
        )));
    }

    // Read the payload
    let mut payload = vec![0u8; payload_len as usize];
    reader.read_exact(&mut payload)?;

    Ok(payload)
}

/// Write a complete frame to a blocking writer.
pub fn write_frame<W: std::io::Write>(writer: &mut W, payload: &[u8]) -> Result<()> {
    let frame = encode_frame(payload)?;
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let payload = b"Hello, world!";
        let frame = encode_frame(payload).unwrap();

        let (payload_len, header_size) = decode_frame_header(&frame).unwrap();
        assert_eq!(header_size, 4);
        assert_eq!(payload_len, payload.len() as u32);

        let decoded = decode_frame_payload(&frame, payload_len).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_incomplete_header_returns_none() {
        assert!(decode_frame_header(&[0x00, 0x01]).is_none());
    }

    #[test]
    fn test_incomplete_payload_returns_none() {
        let payload = b"data";
        let frame = encode_frame(payload).unwrap();
        // Truncate the frame to only have header + partial payload
        let truncated = &frame[..6];
        let (payload_len, _) = decode_frame_header(truncated).unwrap();
        assert!(decode_frame_payload(truncated, payload_len).is_none());
    }
}
