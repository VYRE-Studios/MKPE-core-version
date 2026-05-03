//! PNG LSB steganography for MKPE provenance embedding
//!
//! Embeds arbitrary data into PNG pixel least-significant bits
//! with a 4-byte little-endian u32 length header.

use crate::{MkpeError, Result};
use png::Decoder;
use std::io::Cursor;

/// Maximum data size we can embed, given the 4-byte length header overhead.
fn lsb_capacity(width: u32, height: u32, channels: usize) -> usize {
    let total_bits = (width as usize) * (height as usize) * channels;
    if total_bits < 32 {
        0 // not enough bits even for the length header
    } else {
        (total_bits / 8).saturating_sub(4) // reserve 4 bytes for the length header
    }
}

/// Embed `data` into the LSBs of PNG pixel values.
///
/// The embedded payload is prefixed with a 4-byte little-endian u32 length header.
/// Returns the re-encoded PNG as `Vec<u8>`.
pub fn embed_lsb(input_png: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let decoder = Decoder::new(Cursor::new(input_png));
    let mut reader = decoder
        .read_info()
        .map_err(|e| MkpeError::InvalidProof(format!("PNG decode error: {e}")))?;

    // Extract info values first — reader.info() borrow prevents mutable next_frame()
    let (width, height, color_type, channels) = {
        let info = reader.info();
        (info.width, info.height, info.color_type, info.color_type.samples())
    };

    let capacity = lsb_capacity(width, height, channels);
    if data.len() > capacity {
        return Err(MkpeError::InvalidProof(format!(
            "Data too large: {data_len} bytes exceeds capacity of {capacity} bytes",
            data_len = data.len()
        )));
    }

    let data_len = data.len() as u32;

    // Read all pixel bytes
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let frame_info = reader
        .next_frame(&mut buf)
        .map_err(|e| MkpeError::InvalidProof(format!("PNG read error: {e}")))?;
    buf.truncate(frame_info.buffer_size());

    // Build bit stream: 4-byte LE length header + data
    let total_bits = ((4 + data.len()) * 8) as usize;
    let mut bits = Vec::with_capacity(total_bits);

    // Length header (4 bytes, little-endian)
    for b in data_len.to_le_bytes() {
        for bit in 0..8 {
            bits.push(((b >> bit) & 1) == 1);
        }
    }

    // Data
    for &byte in data {
        for bit in 0..8 {
            bits.push(((byte >> bit) & 1) == 1);
        }
    }

    // Embed into pixel LSBs
    for (i, bit) in bits.iter().enumerate() {
        if *bit {
            buf[i] |= 1;
        } else {
            buf[i] &= !1;
        }
    }

    // Re-encode PNG
    let mut output = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut output, width, height);
        encoder.set_color(color_type);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .map_err(|e| MkpeError::InvalidProof(format!("PNG encode error: {e}")))?;
        writer
            .write_image_data(&buf)
            .map_err(|e| MkpeError::InvalidProof(format!("PNG write error: {e}")))?;
    }

    Ok(output)
}

/// Extract LSB-embedded data from a PNG.
///
/// Reads the 4-byte little-endian u32 length header, then extracts that many payload bytes.
pub fn extract_lsb(input_png: &[u8]) -> Result<Vec<u8>> {
    let decoder = Decoder::new(Cursor::new(input_png));
    let mut reader = decoder
        .read_info()
        .map_err(|e| MkpeError::InvalidProof(format!("PNG decode error: {e}")))?;


    let (width, height, channels) = {
        let info = reader.info();
        (info.width, info.height, info.color_type.samples())
    };

    let capacity = lsb_capacity(width, height, channels);
    if capacity == 0 {
        return Err(MkpeError::InvalidProof(
            "PNG too small to contain embedded data".into(),
        ));
    }

    let mut buf = vec![0u8; reader.output_buffer_size()];
    let frame_info = reader
        .next_frame(&mut buf)
        .map_err(|e| MkpeError::InvalidProof(format!("PNG read error: {e}")))?;
    buf.truncate(frame_info.buffer_size());

    // Extract LSBs into a bit stream
    let max_bits = buf.len().min(((capacity + 4) * 8) as usize);
    let mut bits = Vec::with_capacity(max_bits);
    for &byte in buf.iter().take(max_bits) {
        bits.push((byte & 1) == 1);
    }

    if bits.len() < 32 {
        return Err(MkpeError::InvalidProof(
            "Not enough bits for length header".into(),
        ));
    }

    // Read 4-byte LE length header
    let mut len_bytes = [0u8; 4];
    for (byte_idx, b) in len_bytes.iter_mut().enumerate() {
        for bit in 0..8 {
            if bits[byte_idx * 8 + bit] {
                *b |= 1 << bit;
            }
        }
    }
    let data_len = u32::from_le_bytes(len_bytes) as usize;

    let total_needed_bits = 32 + data_len * 8;
    if bits.len() < total_needed_bits {
        return Err(MkpeError::InvalidProof(format!(
            "Truncated data: need {total_needed_bits} bits, have {have}",
            have = bits.len()
        )));
    }

    let mut data = vec![0u8; data_len];
    for byte_idx in 0..data_len {
        let base = 32 + byte_idx * 8;
        for bit in 0..8 {
            if bits[base + bit] {
                data[byte_idx] |= 1 << bit;
            }
        }
    }

    Ok(data)
}

/// Convenience wrapper: hex-decode `root_hash_hex` and embed it into the PNG.
pub fn embed_provenance(input_png: &[u8], root_hash_hex: &str) -> Result<Vec<u8>> {
    let data = hex::decode(root_hash_hex)
        .map_err(|e| MkpeError::InvalidProof(format!("Hex decode error: {e}")))?;
    embed_lsb(input_png, &data)
}

/// Convenience wrapper: extract embedded data and hex-encode it.
pub fn extract_provenance(input_png: &[u8]) -> Result<String> {
    let data = extract_lsb(input_png)?;
    Ok(hex::encode(data))
}

#[cfg(test)]
mod tests {
    use super::*;


    fn create_test_png() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            // 16x16 RGBA — 1024 pixel bytes, plenty of LSB capacity
            let mut encoder = png::Encoder::new(&mut buf, 16, 16);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            let pixels: Vec<u8> = (0..16 * 16 * 4).map(|i| i as u8).collect();
            writer.write_image_data(&pixels).unwrap();
        }
        buf
    }

    #[test]
    fn test_lsb_roundtrip() {
        let png = create_test_png();
        let msg = b"MKPE provenance fingerprint v1.0";
        let embedded = embed_lsb(&png, msg).expect("embed should succeed");
        let extracted = extract_lsb(&embedded).expect("extract should succeed");
        assert_eq!(&extracted, msg);
    }

    #[test]
    fn test_provenance_roundtrip() {
        let png = create_test_png();
        let root_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let embedded = embed_provenance(&png, root_hash).expect("embed should succeed");
        let extracted = extract_provenance(&embedded).expect("extract should succeed");
        assert_eq!(extracted, root_hash);
    }

    #[test]
    fn test_data_too_large() {
        let png = create_test_png();
        // 16x16 RGBA = 1024 pixels * 4 channels = 4096 bits / 8 = 512 bytes, minus 4 header = 508 bytes capacity
        let huge = vec![0u8; 1024];
        let result = embed_lsb(&png, &huge);
        assert!(result.is_err());
    }
}
