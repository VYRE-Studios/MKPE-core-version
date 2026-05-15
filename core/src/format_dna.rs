//! Format-aware DNA provenance embedding.
//!
//! The public API is `embed_format_aware` / `extract_format_aware`, which
//! dispatches to a format-specific adapter based on the MIME type.
//!
//! ## Supported formats
//!
//! | MIME type                | Adapter | Technique |
//! |--------------------------|---------|-----------|
//! | `application/octet-stream` | `OctetStreamAdapter` | Raw byte-level LSB (backward-compatible with `dna.rs`) |
//! | `image/png`              | `PngAdapter` | LSB in RGB(A) pixel channels with DNA framing |
//! | `application/json`       | `JsonAdapter` | Hidden root key with base64-encoded DNA frame |
//!
//! ## Extending for new formats
//!
//! 1. Create a new `<Name>Adapter` that implements `DnaFormatAdapter`.
//! 2. Register it in `mime_type_to_adapter`.
//! 3. The `embed_format_aware` / `extract_format_aware` signatures do not change.

use crate::{
    DnaTag, MkpeError, Result, crc64, embed_dna_raw, extract_dna_raw,
};
use sha2::{Digest, Sha256};

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Embed a DNA tag whose payload is deterministically derived from `secret`.
///
/// The payload is `SHA-256(secret || "mkpe.dna.payload.v1")`, so every file
/// tagged with the same secret carries the same payload.  For content-specific
/// tagging use [`embed_format_aware_with_payload`].
///
/// # Arguments
///
/// * `input` — original file bytes (unmodified; a new `Vec<u8>` is returned).
/// * `mime_type` — IANA media type, e.g. `"image/png"`.
/// * `secret` — 32-byte secret key (e.g. Ed25519 secret key or HKDF output).
///
/// # Returns
///
/// The modified file bytes with the embedded DNA tag.
pub fn embed_format_aware(input: &[u8], mime_type: &str, secret: &[u8; 32]) -> Result<Vec<u8>> {
    let tag = derive_tag_from_secret(secret);
    embed_format_aware_with_payload(input, mime_type, secret, &tag.payload)
}

/// Embed a DNA tag with an explicit 32-byte payload.
///
/// The payload is typically a SHA-256 hash of the provenance manifest,
/// attestation, or ownership chain root.
///
/// # Arguments
///
/// * `input` — original file bytes.
/// * `mime_type` — IANA media type.
/// * `secret` — 32-byte secret key.
/// * `payload` — 32-byte payload (e.g. manifest hash).
///
/// # Returns
///
/// The modified file bytes with the embedded DNA tag.
pub fn embed_format_aware_with_payload(
    input: &[u8],
    mime_type: &str,
    secret: &[u8; 32],
    payload: &[u8; 32],
) -> Result<Vec<u8>> {
    let tag = DnaTag::from_payload(*payload);
    let adapter = mime_type_to_adapter(mime_type)?;
    adapter.embed(input, &tag, secret)
}

/// Extract a DNA tag from format-aware embedded bytes.
///
/// # Arguments
///
/// * `input` — file bytes that were previously passed to `embed_format_aware`.
/// * `mime_type` — the same IANA media type used during embedding.
/// * `secret` — the same 32-byte secret key used during embedding.
///
/// # Returns
///
/// The recovered [`DnaTag`] (payload, CRC, version).
pub fn extract_format_aware(input: &[u8], mime_type: &str, secret: &[u8; 32]) -> Result<DnaTag> {
    let adapter = mime_type_to_adapter(mime_type)?;
    adapter.extract(input, secret)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: deterministic payload from secret
// ─────────────────────────────────────────────────────────────────────────────

fn derive_tag_from_secret(secret: &[u8; 32]) -> DnaTag {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(b"mkpe.dna.payload.v1");
    DnaTag::from_payload(hasher.finalize().into())
}

// ─────────────────────────────────────────────────────────────────────────────
// Format-adapter trait
// ─────────────────────────────────────────────────────────────────────────────

trait DnaFormatAdapter {
    /// Embed `tag` into `input` and return modified bytes.
    fn embed(&self, input: &[u8], tag: &DnaTag, secret: &[u8; 32]) -> Result<Vec<u8>>;

    /// Extract the DNA tag from `input`.
    fn extract(&self, input: &[u8], secret: &[u8; 32]) -> Result<DnaTag>;
}

// ─────────────────────────────────────────────────────────────────────────────
// MIME-type dispatch
// ─────────────────────────────────────────────────────────────────────────────

fn mime_type_to_adapter(mime_type: &str) -> Result<Box<dyn DnaFormatAdapter>> {
    match mime_type {
        "application/octet-stream"
        | "application/x-executable"
        | "application/x-sharedlib"
        | "application/pdf"
        | "application/zip" => Ok(Box::new(OctetStreamAdapter)),
        "image/png" => Ok(Box::new(PngAdapter)),
        "application/json" | "text/json" => Ok(Box::new(JsonAdapter)),
        _ => Err(MkpeError::InvalidProof(format!(
            "Unsupported MIME type for DNA tagging: {mime_type}"
        ))),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Octet-stream adapter — raw byte-level LSB (backward-compatible)
// ─────────────────────────────────────────────────────────────────────────────

struct OctetStreamAdapter;

impl DnaFormatAdapter for OctetStreamAdapter {
    fn embed(&self, input: &[u8], tag: &DnaTag, secret: &[u8; 32]) -> Result<Vec<u8>> {
        let mut buf = input.to_vec();
        crate::embed_dna(&mut buf, tag, secret)?;
        Ok(buf)
    }

    fn extract(&self, input: &[u8], secret: &[u8; 32]) -> Result<DnaTag> {
        crate::extract_dna(input, secret)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PNG adapter — LSB in RGB(A) channels with DNA redundancy framing
// ─────────────────────────────────────────────────────────────────────────────

struct PngAdapter;

impl DnaFormatAdapter for PngAdapter {
    fn embed(&self, input: &[u8], tag: &DnaTag, secret: &[u8; 32]) -> Result<Vec<u8>> {
        let decoder = png::Decoder::new(std::io::Cursor::new(input));
        let mut reader = decoder
            .read_info()
            .map_err(|e| MkpeError::InvalidProof(format!("PNG decode error: {e}")))?;

        // Capture format info before we consume the reader.
        let (width, height, color_type, bit_depth) = {
            let info = reader.info();
            (info.width, info.height, info.color_type, info.bit_depth)
        };

        let mut buf = vec![0u8; reader.output_buffer_size()];
        let frame_info = reader
            .next_frame(&mut buf)
            .map_err(|e| MkpeError::InvalidProof(format!("PNG read error: {e}")))?;
        buf.truncate(frame_info.buffer_size());

        // Embed into pixel bytes using a PNG-specific seed.
        let seed = derive_png_seed(secret, width, height, color_type);
        crate::embed_dna_raw(&mut buf, tag, &seed)?;

        // Re-encode PNG.
        let mut output = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut output, width, height);
            encoder.set_color(color_type);
            encoder.set_depth(bit_depth);
            let mut writer = encoder
                .write_header()
                .map_err(|e| MkpeError::InvalidProof(format!("PNG encode error: {e}")))?;
            writer
                .write_image_data(&buf)
                .map_err(|e| MkpeError::InvalidProof(format!("PNG write error: {e}")))?;
        }

        Ok(output)
    }

    fn extract(&self, input: &[u8], secret: &[u8; 32]) -> Result<DnaTag> {
        let decoder = png::Decoder::new(std::io::Cursor::new(input));
        let mut reader = decoder
            .read_info()
            .map_err(|e| MkpeError::InvalidProof(format!("PNG decode error: {e}")))?;

        let (width, height, color_type) = {
            let info = reader.info();
            (info.width, info.height, info.color_type)
        };

        let mut buf = vec![0u8; reader.output_buffer_size()];
        let frame_info = reader
            .next_frame(&mut buf)
            .map_err(|e| MkpeError::InvalidProof(format!("PNG read error: {e}")))?;
        buf.truncate(frame_info.buffer_size());

        let seed = derive_png_seed(secret, width, height, color_type);
        crate::extract_dna_raw(&buf, &seed)
    }
}

/// Derive a PNG-specific seed that is stable across encode/decode cycles.
fn derive_png_seed(secret: &[u8; 32], width: u32, height: u32, color_type: png::ColorType) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"mkpe.dna.png.v1");
    hasher.update(secret);
    hasher.update(&width.to_le_bytes());
    hasher.update(&height.to_le_bytes());
    hasher.update(&[color_type as u8]);
    hasher.finalize().into()
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON adapter — hidden root key with base64-encoded DNA frame
// ─────────────────────────────────────────────────────────────────────────────

const JSON_DNA_KEY: &str = "_mkpe_dna";

struct JsonAdapter;

impl DnaFormatAdapter for JsonAdapter {
    fn embed(&self, input: &[u8], tag: &DnaTag, _secret: &[u8; 32]) -> Result<Vec<u8>> {
        let mut json: serde_json::Value = serde_json::from_slice(input)
            .map_err(|e| MkpeError::InvalidProof(format!("Invalid JSON: {e}")))?;

        let obj = json.as_object_mut().ok_or_else(|| {
            MkpeError::InvalidProof("JSON DNA tagging requires a top-level object".into())
        })?;

        // Base64-encode the 41-byte frame.
        let frame_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            tag.to_frame(),
        );
        obj.insert(JSON_DNA_KEY.to_string(), serde_json::Value::String(frame_b64));

        // Compact serialization to minimise accidental whitespace drift.
        serde_json::to_vec(&json).map_err(|e| MkpeError::InvalidProof(format!("JSON serialize: {e}")).into())
    }

    fn extract(&self, input: &[u8], _secret: &[u8; 32]) -> Result<DnaTag> {
        let json: serde_json::Value = serde_json::from_slice(input)
            .map_err(|e| MkpeError::InvalidProof(format!("Invalid JSON: {e}")))?;

        let frame_b64 = json
            .get(JSON_DNA_KEY)
            .and_then(|v| v.as_str())
            .ok_or_else(|| MkpeError::InvalidProof(
                format!("Missing '{JSON_DNA_KEY}' field — DNA tag not present or removed")
            ))?;

        let frame_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            frame_b64,
        )
        .map_err(|e| MkpeError::InvalidProof(format!("Base64 decode error: {e}")))?;
        if frame_bytes.len() != crate::dna::FRAME_BYTES {
            return Err(MkpeError::InvalidProof(format!(
                "DNA frame size mismatch: expected {}, got {}",
                crate::dna::FRAME_BYTES,
                frame_bytes.len()
            )));
        }
        let mut frame = [0u8; crate::dna::FRAME_BYTES];
        frame.copy_from_slice(&frame_bytes);
        DnaTag::from_frame(&frame)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        for i in 0..32 {
            s[i] = i as u8;
        }
        s
    }

    fn test_payload() -> [u8; 32] {
        [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        ]
    }

    // ─── Octet-stream ───

    #[test]
    fn test_format_aware_octet_stream_roundtrip() {
        let secret = test_secret();
        let payload = test_payload();
        let mut original = vec![0u8; 4096];
        for i in 0..original.len() {
            original[i] = ((i * 7 + 13) % 256) as u8;
        }

        let embedded = embed_format_aware_with_payload(&original, "application/octet-stream", &secret, &payload)
            .unwrap();
        let extracted = extract_format_aware(&embedded, "application/octet-stream", &secret).unwrap();
        assert_eq!(extracted.payload, payload);
    }

    #[test]
    fn test_format_aware_octet_stream_derived_payload() {
        let secret = test_secret();
        let original = vec![0u8; 4096];

        let embedded = embed_format_aware(&original, "application/octet-stream", &secret).unwrap();
        let extracted = extract_format_aware(&embedded, "application/octet-stream", &secret).unwrap();
        let expected = derive_tag_from_secret(&secret);
        assert_eq!(extracted.payload, expected.payload);
    }

    // ─── PNG ───

    fn create_test_png(width: u32, height: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut buf, width, height);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            let pixels: Vec<u8> = (0..(width * height * 4)).map(|i| i as u8).collect();
            writer.write_image_data(&pixels).unwrap();
        }
        buf
    }

    #[test]
    fn test_format_aware_png_roundtrip() {
        let secret = test_secret();
        let payload = test_payload();
        let png = create_test_png(32, 32);

        let embedded = embed_format_aware_with_payload(&png, "image/png", &secret, &payload).unwrap();
        let extracted = extract_format_aware(&embedded, "image/png", &secret).unwrap();
        assert_eq!(extracted.payload, payload);
    }

    #[test]
    fn test_format_aware_png_survives_reencode() {
        let secret = test_secret();
        let payload = test_payload();
        let png = create_test_png(32, 32);

        // Embed DNA.
        let embedded = embed_format_aware_with_payload(&png, "image/png", &secret, &payload).unwrap();

        // Re-decode and re-encode the PNG to simulate a "save-as" cycle.
        let decoder = png::Decoder::new(std::io::Cursor::new(&embedded));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0u8; reader.output_buffer_size()];
        let frame = reader.next_frame(&mut buf).unwrap();
        buf.truncate(frame.buffer_size());
        let (w, h) = {
            let info = reader.info();
            (info.width, info.height)
        };
        let mut reencoded = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut reencoded, w, h);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(&buf).unwrap();
        }

        let extracted = extract_format_aware(&reencoded, "image/png", &secret).unwrap();
        assert_eq!(extracted.payload, payload);
    }

    #[test]
    fn test_format_aware_png_wrong_secret_fails() {
        let secret = test_secret();
        let mut wrong_secret = secret;
        wrong_secret[0] ^= 0xFF;
        let payload = test_payload();
        let png = create_test_png(32, 32);

        let embedded = embed_format_aware_with_payload(&png, "image/png", &secret, &payload).unwrap();
        assert!(extract_format_aware(&embedded, "image/png", &wrong_secret).is_err());
    }

    // ─── JSON ───

    #[test]
    fn test_format_aware_json_roundtrip() {
        let secret = test_secret();
        let payload = test_payload();
        let json = br#"{"name":"Test","version":"1.0"}"#;

        let embedded = embed_format_aware_with_payload(json, "application/json", &secret, &payload).unwrap();
        let extracted = extract_format_aware(&embedded, "application/json", &secret).unwrap();
        assert_eq!(extracted.payload, payload);
    }

    #[test]
    fn test_format_aware_json_survives_pretty_print() {
        let secret = test_secret();
        let payload = test_payload();
        let json = br#"{"name":"Test","nested":{"a":1}}"#;

        let embedded = embed_format_aware_with_payload(json, "application/json", &secret, &payload).unwrap();

        // Parse and pretty-print (simulates re-serialisation by a different tool).
        let parsed: serde_json::Value = serde_json::from_slice(&embedded).unwrap();
        let pretty = serde_json::to_string_pretty(&parsed).unwrap().into_bytes();

        // Still extractable because the hidden key is preserved by parse/serialise.
        let extracted = extract_format_aware(&pretty, "application/json", &secret).unwrap();
        assert_eq!(extracted.payload, payload);
    }

    #[test]
    fn test_format_aware_json_missing_key_fails() {
        let secret = test_secret();
        let json = br#"{"name":"Untagged"}"#;
        assert!(extract_format_aware(json, "application/json", &secret).is_err());
    }

    #[test]
    fn test_format_aware_json_rejects_non_object() {
        let secret = test_secret();
        let payload = test_payload();
        let json = br#"["not","an","object"]"#;
        assert!(embed_format_aware_with_payload(json, "application/json", &secret, &payload).is_err());
    }

    #[test]
    fn test_format_aware_wrong_mime_type() {
        let secret = test_secret();
        assert!(embed_format_aware(b"hello", "audio/mp3", &secret).is_err());
    }

    #[test]
    fn test_format_aware_png_requires_minimum_pixels() {
        let secret = test_secret();
        let payload = test_payload();
        // 8x8 RGBA = 256 bytes — below 1024 byte DNA minimum.
        let tiny_png = create_test_png(8, 8);
        let result = embed_format_aware_with_payload(&tiny_png, "image/png", &secret, &payload);
        assert!(result.is_err(), "Tiny PNG should fail DNA minimum size");
    }
}
