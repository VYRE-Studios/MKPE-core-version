//! RFC 3161 timestamping for MKPE provenance anchoring.
//!
//! Builds TimeStampReq DER, posts to a TSA, and returns the token.

use crate::{MkpeError, Result};
use base64::Engine;
use chrono::Utc;
use rand::RngCore;
use std::time::Duration;

pub const DEFAULT_TSA_URL: &str = "https://freetsa.org/tsr";

/// Request sent to a TSA.
pub struct TimestampRequest {
    pub data_hash: String,
    pub tsa_url: String,
}

/// Response received from a TSA.
pub struct TimestampResponse {
    /// Raw DER-encoded TimeStampToken
    pub token_der: Vec<u8>,
    /// Base64-encoded token for transport
    pub token_b64: String,
    /// The TSA URL that serviced the request
    pub tsa_url: String,
    /// When the token was acquired
    pub acquired_at: chrono::DateTime<chrono::Utc>,
}

/// Request an RFC 3161 timestamp for `data_hash` from `tsa_url`.
///
/// `data_hash` must be a hex-encoded SHA-256 digest (64 hex chars).
/// Uses a 10-second timeout.
pub fn request_timestamp(data_hash: &str, tsa_url: &str) -> Result<TimestampResponse> {
    let req_der = build_timestamp_request(data_hash)?;

    let response = ureq::post(tsa_url)
        .set("Content-Type", "application/timestamp-query")
        .timeout(Duration::from_secs(10))
        .send_bytes(&req_der)
        .map_err(|e| MkpeError::InvalidProof(format!("TSA request failed: {e}")))?;

    let mut token_der = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut token_der)
        .map_err(|e| MkpeError::InvalidProof(format!("Failed to read TSA response: {e}")))?;

    if token_der.is_empty() {
        return Err(MkpeError::InvalidProof("TSA returned empty response".into()));
    }

    let token_b64 = base64::engine::general_purpose::STANDARD.encode(&token_der);

    Ok(TimestampResponse {
        token_der,
        token_b64,
        tsa_url: tsa_url.to_string(),
        acquired_at: Utc::now(),
    })
}

/// Build a minimal DER-encoded TimeStampReq.
///
/// Includes version=1, SHA-256 messageImprint, random 8-byte nonce, certReq=FALSE.
fn build_timestamp_request(data_hash_hex: &str) -> Result<Vec<u8>> {
    if data_hash_hex.len() != 64 {
        return Err(MkpeError::InvalidProof(format!(
            "Expected 64-char hex SHA-256 hash, got {len}",
            len = data_hash_hex.len()
        )));
    }

    let hash = hex::decode(data_hash_hex)
        .map_err(|e| MkpeError::InvalidProof(format!("Hex decode error: {e}")))?;

    if hash.len() != 32 {
        return Err(MkpeError::InvalidProof(format!(
            "Expected 32-byte hash, got {len}",
            len = hash.len()
        )));
    }

    // AlgorithmIdentifier: SHA-256 OID (2.16.840.1.101.3.4.2.1) with NULL params
    // DER: 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00
    let alg_id = build_der_sequence(&[
        &build_der_oid(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]),
        // NULL parameters: 05 00
        &[0x05, 0x00],
    ]);

    // messageImprint = SEQUENCE { algId, OCTET STRING(hash) }
    let message_imprint = build_der_sequence(&[&alg_id, &build_der_octet_string(&hash)]);

    // version: INTEGER { v1(1) } → 02 01 01
    let version = build_der_integer(&[1]);

    // nonce: random 8-byte INTEGER
    let mut nonce_bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = build_der_integer(&nonce_bytes);

    // certReq: BOOLEAN FALSE → 01 01 00
    let cert_req: &[u8] = &[0x01, 0x01, 0x00];

    // TimeStampReq = SEQUENCE { version, messageImprint, nonce, certReq }
    Ok(build_der_sequence(&[&version, &message_imprint, &nonce, cert_req]))
}

// ── DER helpers ──────────────────────────────────────────────────────────

fn build_der_sequence(parts: &[&[u8]]) -> Vec<u8> {
    let content: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    let len = write_der_length(content.len());
    let mut out = Vec::with_capacity(1 + len.len() + content.len());
    out.push(0x30);
    out.extend(&len);
    out.extend(&content);
    out
}

fn build_der_octet_string(data: &[u8]) -> Vec<u8> {
    let len = write_der_length(data.len());
    let mut out = Vec::with_capacity(1 + len.len() + data.len());
    out.push(0x04);
    out.extend(&len);
    out.extend(data);
    out
}

fn build_der_integer(bytes: &[u8]) -> Vec<u8> {
    let needs_pad = !bytes.is_empty() && (bytes[0] & 0x80) != 0;
    let len = write_der_length(bytes.len() + if needs_pad { 1 } else { 0 });
    let mut out = Vec::with_capacity(1 + len.len() + bytes.len() + if needs_pad { 1 } else { 0 });
    out.push(0x02);
    out.extend(&len);
    if needs_pad {
        out.push(0x00);
    }
    out.extend(bytes);
    out
}

fn build_der_oid(encoded: &[u8]) -> Vec<u8> {
    let len = write_der_length(encoded.len());
    let mut out = Vec::with_capacity(1 + len.len() + encoded.len());
    out.push(0x06);
    out.extend(&len);
    out.extend(encoded);
    out
}

fn write_der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let bytes_needed = bytes_to_encode(len);
        let mut out = Vec::with_capacity(1 + bytes_needed);
        out.push(0x80 | bytes_needed as u8);
        for i in (0..bytes_needed).rev() {
            out.push(((len >> (8 * i)) & 0xFF) as u8);
        }
        out
    }
}

fn bytes_to_encode(value: usize) -> usize {
    if value == 0 {
        return 1;
    }
    let bits = usize::BITS - value.leading_zeros();
    ((bits + 7) / 8) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_timestamp_request() {
        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let req = build_timestamp_request(hash).expect("should build request");
        assert!(!req.is_empty());
        assert!(req.len() > 50);
        assert_eq!(req[0], 0x30, "must start with SEQUENCE tag");
    }

    #[test]
    fn test_reject_invalid_hash() {
        let result = build_timestamp_request("too_short");
        assert!(result.is_err());
    }
}
