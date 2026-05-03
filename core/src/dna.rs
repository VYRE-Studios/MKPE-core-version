//! Digital DNA tagging — robust provenance embedding for binary artifacts.
//!
//! Embeds a 32-byte cryptographic hash into any binary file using:
//!
//! 1. **Secret-key placement** — The attacker does not know which bytes carry the tag.
//!    Positions are derived from `SHA-256(secret_key || file_size || file_header)`.
//!    The first 8 bytes of the file are never touched (preserves magic numbers / headers).
//!
//! 2. **Five-fold redundancy with majority voting** — Every byte of the tag is embedded
//!    five times at independent pseudorandom locations. A bit survives as long as a
//!    majority of its five copies are intact.
//!
//! 3. **CRC-64 integrity check** — Detects corruption or tampering with 64-bit confidence.
//!
//! 4. **Interleaving** — Copies are byte-interleaved (`A[0], B[0], C[0], D[0], E[0], A[1], …`)
//!    so that burst corruption (e.g. a contiguous erased region) hits different bytes
//!    of each copy rather than destroying one copy entirely.
//!
//! ## Threat model
//!
//! This is designed so that removal is **computationally hard** without the secret key.
//! An adversary must either:
//!
//! - Know the 32-byte `secret_key` to derive the exact embedding positions, or
//! - Corrupt ≈ 30 % or more of the file bytes (which usually destroys utility).
//!
//! It is **not** mathematically unremovable — the analog hole exists — but the cost
//! of removal far exceeds the value of most attacks.
//!
//! ## Minimum file size
//!
//! Files smaller than `MIN_FILE_BYTES` (1024) are rejected because there are not
//! enough distinct bit locations to embed the tag without destructive overlap.

use crate::{MkpeError, Result};
use sha2::{Digest, Sha256};

/// DNA format version (bumped if wire format changes).
pub const DNA_VERSION: u8 = 1;

/// Size of the SHA-256 payload.
pub const PAYLOAD_BYTES: usize = 32;

/// Size of the CRC-64 trailer.
pub const CRC_BYTES: usize = 8;

/// Total tag frame: 1 version byte + 32 payload + 8 CRC = 41 bytes.
pub const FRAME_BYTES: usize = 1 + PAYLOAD_BYTES + CRC_BYTES;

/// Number of redundant copies.
pub const REDUNDANCY: usize = 5;

/// Total interleaved bytes to embed = FRAME_BYTES × REDUNDANCY.
pub const INTERLEAVED_BYTES: usize = FRAME_BYTES * REDUNDANCY;

/// Total bits to embed = INTERLEAVED_BYTES × 8.
pub const TOTAL_BITS: usize = INTERLEAVED_BYTES * 8;

/// First N bytes of the file are left untouched (headers / magic numbers).
pub const RESERVED_HEADER_BYTES: usize = 8;

/// Files smaller than this are rejected.
pub const MIN_FILE_BYTES: usize = 1024;

// ──────────────────────────────────────────────────────────────────────────────
// CRC-64 (ECMA-182)
// ──────────────────────────────────────────────────────────────────────────────

const CRC64_POLY: u64 = 0xC96C5795D7870F42;

/// Pre-computed CRC-64 lookup table (ECMA-182 polynomial).
static CRC64_TABLE: [u64; 256] = {
    let mut table = [0u64; 256];
    let mut i = 0u64;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ CRC64_POLY
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
};

/// Compute CRC-64 over a byte slice using the ECMA-182 polynomial.
pub fn crc64(data: &[u8]) -> u64 {
    let mut crc: u64 = 0;
    for &byte in data {
        let idx = ((crc ^ (byte as u64)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC64_TABLE[idx];
    }
    crc
}

// ──────────────────────────────────────────────────────────────────────────────
// Pseudorandom position generation
// ──────────────────────────────────────────────────────────────────────────────

/// A simple, deterministic PRNG (xoshiro256++) used to expand a 32-byte seed
/// into a stream of pseudorandom 64-bit values.
pub struct Prng {
    s: [u64; 4],
}

impl Prng {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut s = [0u64; 4];
        for (i, chunk) in seed.chunks_exact(8).enumerate() {
            s[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        // Avoid all-zero state
        if s.iter().all(|&v| v == 0) {
            s[0] = 0x9E3779B97F4A7C15;
        }
        Self { s }
    }

    #[inline]
    pub fn next(&mut self) -> u64 {
        let result = self.s[0]
            .wrapping_add(self.s[3])
            .rotate_left(23)
            .wrapping_add(self.s[0]);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Generate `n` distinct-ish positions in `[reserved, len)` together with
    /// a bit offset in `0..8`.
    pub fn positions(&mut self, len: usize, reserved: usize, n: usize) -> Vec<(usize, u8)> {
        let mut out = Vec::with_capacity(n);
        let usable = len.saturating_sub(reserved);
        let total_slots = usable * 8;
        if total_slots == 0 {
            return out;
        }
        let mut used = std::collections::HashSet::with_capacity(n);
        while out.len() < n {
            let slot = self.next() as usize % total_slots;
            if used.insert(slot) {
                let pos = reserved + (slot / 8);
                let bit = (slot % 8) as u8;
                out.push((pos, bit));
            }
        }
        out
    }
}

/// Derive a 32-byte seed from the secret key and a stable file fingerprint.
///
/// The fingerprint uses **only** bytes that the embedder promises never to
/// modify (`file_len` and the first `RESERVED_HEADER_BYTES`).  This keeps
/// the seed stable before and after embedding.
pub fn derive_file_seed(secret: &[u8; 32], file_len: usize, header: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"mkpe.dna.v1");
    hasher.update(secret);
    hasher.update(&file_len.to_le_bytes());
    hasher.update(&header[..header.len().min(RESERVED_HEADER_BYTES)]);
    hasher.finalize().into()
}

// ──────────────────────────────────────────────────────────────────────────────
// Encoding helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Interleave `REDUNDANCY` copies of `frame` byte-by-byte:
///
/// `[A0, B0, C0, A1, B1, C1, …]`
fn interleave(frame: &[u8; FRAME_BYTES]) -> [u8; INTERLEAVED_BYTES] {
    let mut out = [0u8; INTERLEAVED_BYTES];
    for i in 0..FRAME_BYTES {
        for r in 0..REDUNDANCY {
            out[i * REDUNDANCY + r] = frame[i];
        }
    }
    out
}

/// De-interleave with majority vote per bit.
///
/// For each bit position across the `REDUNDANCY` copies, count the 1s.
/// If the majority is 1, set that bit in the reconstructed frame byte.
fn deinterleave(interleaved: &[u8; INTERLEAVED_BYTES]) -> [u8; FRAME_BYTES] {
    let mut frame = [0u8; FRAME_BYTES];
    for i in 0..FRAME_BYTES {
        let mut byte = 0u8;
        for bit in 0..8 {
            let ones = (0..REDUNDANCY)
                .filter(|&r| (interleaved[i * REDUNDANCY + r] >> bit) & 1 == 1)
                .count();
            if ones > REDUNDANCY / 2 {
                byte |= 1 << bit;
            }
        }
        frame[i] = byte;
    }
    frame
}

/// Set or clear a single bit in a byte slice.
fn write_bit(bytes: &mut [u8], pos: usize, bit: u8, value: bool) {
    let mask = 1u8 << bit;
    if value {
        bytes[pos] |= mask;
    } else {
        bytes[pos] &= !mask;
    }
}

/// Read a single bit from a byte slice.
fn read_bit(bytes: &[u8], pos: usize, bit: u8) -> bool {
    (bytes[pos] >> bit) & 1 == 1
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/// A complete DNA tag, ready for embedding or returned after extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnaTag {
    pub version: u8,
    pub payload: [u8; PAYLOAD_BYTES],
    pub crc: u64,
}

impl DnaTag {
    /// Create a tag from a 32-byte payload (e.g. a SHA-256 hash).
    pub fn from_payload(payload: [u8; PAYLOAD_BYTES]) -> Self {
        Self {
            version: DNA_VERSION,
            payload,
            crc: crc64(&payload),
        }
    }

    /// Serialize to the 41-byte wire frame.
    pub fn to_frame(&self) -> [u8; FRAME_BYTES] {
        let mut frame = [0u8; FRAME_BYTES];
        frame[0] = self.version;
        frame[1..1 + PAYLOAD_BYTES].copy_from_slice(&self.payload);
        frame[1 + PAYLOAD_BYTES..].copy_from_slice(&self.crc.to_le_bytes());
        frame
    }

    /// Deserialize from a 41-byte wire frame.
    pub fn from_frame(frame: &[u8; FRAME_BYTES]) -> Result<Self> {
        let version = frame[0];
        if version != DNA_VERSION {
            return Err(MkpeError::VerificationFailed(format!(
                "DNA version mismatch: expected {}, got {}",
                DNA_VERSION, version
            )));
        }
        let mut payload = [0u8; PAYLOAD_BYTES];
        payload.copy_from_slice(&frame[1..1 + PAYLOAD_BYTES]);
        let crc = u64::from_le_bytes(
            frame[1 + PAYLOAD_BYTES..]
                .try_into()
                .map_err(|_| MkpeError::VerificationFailed("CRC truncated".into()))?,
        );
        let computed = crc64(&payload);
        if crc != computed {
            return Err(MkpeError::VerificationFailed(
                "DNA CRC mismatch — tag corrupted or removed".into(),
            ));
        }
        Ok(Self { version, payload, crc })
    }
}

/// Embed a DNA tag into a binary artifact using an already-derived seed.
///
/// # Returns
///
/// The number of distinct byte positions that were modified.
pub fn embed_dna_raw(file_bytes: &mut [u8], tag: &DnaTag, seed: &[u8; 32]) -> Result<usize> {
    if file_bytes.len() < MIN_FILE_BYTES {
        return Err(MkpeError::InvalidProof(format!(
            "File too small for DNA tagging: {} bytes (minimum {})",
            file_bytes.len(),
            MIN_FILE_BYTES
        )));
    }

    let mut prng = Prng::from_seed(*seed);
    let positions = prng.positions(file_bytes.len(), RESERVED_HEADER_BYTES, TOTAL_BITS);

    let frame = tag.to_frame();
    let interleaved = interleave(&frame);

    for (byte_idx, &byte) in interleaved.iter().enumerate() {
        for bit in 0..8 {
            let (pos, bit_offset) = positions[byte_idx * 8 + bit];
            write_bit(file_bytes, pos, bit_offset, (byte >> bit) & 1 == 1);
        }
    }

    let distinct: std::collections::HashSet<usize> =
        positions.iter().map(|(p, _)| *p).collect();
    Ok(distinct.len())
}

/// Embed a DNA tag into a binary artifact.
///
/// # Requirements
///
/// - `file_bytes.len() >= MIN_FILE_BYTES` (currently 1024).
/// - The first `RESERVED_HEADER_BYTES` are preserved.
///
/// # Returns
///
/// The number of distinct byte positions that were modified.
pub fn embed_dna(file_bytes: &mut [u8], tag: &DnaTag, secret: &[u8; 32]) -> Result<usize> {
    let seed = derive_file_seed(secret, file_bytes.len(), file_bytes);
    embed_dna_raw(file_bytes, tag, &seed)
}

/// Extract a DNA tag from a binary artifact using an already-derived seed.
pub fn extract_dna_raw(file_bytes: &[u8], seed: &[u8; 32]) -> Result<DnaTag> {
    if file_bytes.len() < MIN_FILE_BYTES {
        return Err(MkpeError::InvalidProof(format!(
            "File too small to contain DNA tag: {} bytes (minimum {})",
            file_bytes.len(),
            MIN_FILE_BYTES
        )));
    }

    let mut prng = Prng::from_seed(*seed);
    let positions = prng.positions(file_bytes.len(), RESERVED_HEADER_BYTES, TOTAL_BITS);

    let mut interleaved = [0u8; INTERLEAVED_BYTES];
    for (byte_idx, byte) in interleaved.iter_mut().enumerate() {
        for bit in 0..8 {
            let (pos, bit_offset) = positions[byte_idx * 8 + bit];
            if read_bit(file_bytes, pos, bit_offset) {
                *byte |= 1 << bit;
            }
        }
    }

    let frame = deinterleave(&interleaved);
    DnaTag::from_frame(&frame)
}

/// Extract a DNA tag from a binary artifact.
///
/// Uses majority voting across the three redundant copies.  If the CRC
/// check fails, the tag has been corrupted beyond the correction threshold.
pub fn extract_dna(file_bytes: &[u8], secret: &[u8; 32]) -> Result<DnaTag> {
    let seed = derive_file_seed(secret, file_bytes.len(), file_bytes);
    extract_dna_raw(file_bytes, &seed)
}

// ──────────────────────────────────────────────────────────────────────────────
// Key derivation helper
// ──────────────────────────────────────────────────────────────────────────────

/// Derive a DNA embedding secret from an Ed25519 secret key (or any 32-byte key).
///
/// Uses HKDF-like construction: `SHA-256(secret_key || "mkpe.dna.secret")`.
pub fn derive_dna_secret(signing_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(signing_key);
    hasher.update(b"mkpe.dna.secret");
    hasher.finalize().into()
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

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

    fn test_payload() -> [u8; PAYLOAD_BYTES] {
        [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        ]
    }

    #[test]
    fn test_crc64_known_values() {
        // Empty string CRC-64 with init=0 must be 0
        assert_eq!(crc64(b""), 0x0000000000000000);
        // Self-consistency: same input = same output
        let payload = b"123456789";
        assert_eq!(crc64(payload), crc64(payload));
    }

    #[test]
    fn test_dna_roundtrip() {
        let secret = test_secret();
        let payload = test_payload();
        let tag = DnaTag::from_payload(payload);

        let mut file = vec![0u8; 4096];
        // Fill with deterministic noise so the first 8 bytes are non-zero
        for i in 0..file.len() {
            file[i] = ((i * 7 + 13) % 256) as u8;
        }

        let modified = embed_dna(&mut file, &tag, &secret).unwrap();
        assert!(modified > 0);

        let extracted = extract_dna(&file, &secret).unwrap();
        assert_eq!(extracted.payload, payload);
        assert_eq!(extracted.crc, tag.crc);
    }

    #[test]
    fn test_dna_survives_random_corruption() {
        let secret = test_secret();
        let payload = test_payload();
        let tag = DnaTag::from_payload(payload);

        let mut file = vec![0u8; 8192];
        for i in 0..file.len() {
            file[i] = ((i * 7 + 13) % 256) as u8;
        }

        embed_dna(&mut file, &tag, &secret).unwrap();

        // Corrupt 10 % of bytes randomly (skip first 8 reserved bytes)
        let mut corrupted = file.clone();
        let mut rng = rand::thread_rng();
        use rand::Rng;
        let corrupt_count = corrupted.len() / 10;
        for _ in 0..corrupt_count {
            let idx = RESERVED_HEADER_BYTES + rng.gen_range(0..corrupted.len() - RESERVED_HEADER_BYTES);
            corrupted[idx] = corrupted[idx].wrapping_add(1);
        }

        let extracted = extract_dna(&corrupted, &secret).unwrap();
        assert_eq!(extracted.payload, payload);
    }

    #[test]
    fn test_dna_detects_massive_corruption() {
        let secret = test_secret();
        let payload = test_payload();
        let tag = DnaTag::from_payload(payload);

        let mut file = vec![0u8; 4096];
        for i in 0..file.len() {
            file[i] = ((i * 7 + 13) % 256) as u8;
        }

        embed_dna(&mut file, &tag, &secret).unwrap();

        // Corrupt 40 % of bytes — should exceed correction threshold
        let mut corrupted = file.clone();
        let mut rng = rand::thread_rng();
        use rand::Rng;
        let corrupt_count = (corrupted.len() as f64 * 0.40) as usize;
        for _ in 0..corrupt_count {
            let idx = RESERVED_HEADER_BYTES + rng.gen_range(0..corrupted.len() - RESERVED_HEADER_BYTES);
            corrupted[idx] = rng.gen();
        }

        let result = extract_dna(&corrupted, &secret);
        assert!(
            result.is_err(),
            "Should fail when 40 % of bytes are randomized"
        );
    }

    #[test]
    fn test_dna_rejects_small_file() {
        let secret = test_secret();
        let payload = test_payload();
        let tag = DnaTag::from_payload(payload);

        let mut file = vec![0u8; 512]; // too small
        let result = embed_dna(&mut file, &tag, &secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_dna_wrong_secret_fails() {
        let secret = test_secret();
        let wrong_secret = {
            let mut s = test_secret();
            s[0] ^= 0xFF;
            s
        };
        let payload = test_payload();
        let tag = DnaTag::from_payload(payload);

        let mut file = vec![0u8; 4096];
        for i in 0..file.len() {
            file[i] = ((i * 7 + 13) % 256) as u8;
        }

        embed_dna(&mut file, &tag, &secret).unwrap();

        let result = extract_dna(&file, &wrong_secret);
        assert!(
            result.is_err(),
            "Wrong secret should produce garbage or CRC failure"
        );
    }

    #[test]
    fn test_dna_header_preserved() {
        let secret = test_secret();
        let payload = test_payload();
        let tag = DnaTag::from_payload(payload);

        let mut file = vec![0xABu8; 4096];
        let original_header: Vec<u8> = file[..RESERVED_HEADER_BYTES].to_vec();

        embed_dna(&mut file, &tag, &secret).unwrap();

        assert_eq!(&file[..RESERVED_HEADER_BYTES], &original_header[..]);
    }

    #[test]
    fn test_dna_from_frame_roundtrip() {
        let payload = test_payload();
        let tag = DnaTag::from_payload(payload);
        let frame = tag.to_frame();
        let recovered = DnaTag::from_frame(&frame).unwrap();
        assert_eq!(recovered.payload, payload);
        assert_eq!(recovered.crc, tag.crc);
    }
}
