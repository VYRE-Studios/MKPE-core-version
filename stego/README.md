# MKPE Steganography Layer

**Status**: 📋 DEFINED – Implementation Pending  
**Version**: Planned for v1.2.0  
**Location**: `C:\mkpe\stego\`

---

## Purpose

The steganography layer embeds provenance fingerprints into media files so the proof survives copying, sharing, and distribution outside your control.

---

## Architecture

```
Original Asset (image.png)
     +
.mkpe Bundle (project.mkpe)
     ↓
Embed root_hash
     ↓
Asset with Embedded Proof (image_provenanced.png)
```

**Key Principle**: Never modify `.mkpe` files. Always read the root hash from the bundle and embed it separately.

---

## Proposed CLI (Future)

### Embed Proof
```bash
mkpe_stego embed image.png \
  --from-bundle project.mkpe \
  --output image_provenanced.png
```

### Extract Proof
```bash
mkpe_stego extract image_provenanced.png
# Output: root_hash=9b5041f701ba5279...
```

### Verify
```bash
mkpe_stego verify image_provenanced.png \
  --against-bundle project.mkpe
# Output: ✓ Embedded proof matches bundle
```

---

## Supported Formats (Planned)

| Format | Embedding Method | Reversible | Quality Loss |
|--------|-----------------|------------|--------------|
| **PNG** | LSB or tEXt chunk | Yes | None |
| **JPEG** | EXIF or COM segment | Yes | Minimal |
| **MP3** | ID3v2 tags | Yes | None |
| **MP4** | User data atom | Yes | None |
| **Binary** | Custom segment | Yes | None |

---

## Design Principles

### 1. Non-Destructive
- Original asset quality preserved
- Embedding is reversible
- No perceptual degradation

### 2. Read-Only `.mkpe`
- Never modify bundle files
- Always extract root hash from manifest
- Stego operates post-bundling

### 3. Verifiable
- Extracted hash must match bundle
- Signature verification still via MKPE core
- Stego layer only handles embedding/extraction

### 4. Optional
- Assets work without embedded proofs
- `.mkpe` bundle is the source of truth
- Embedding adds convenience, not security

---

## Embedding Strategies

### PNG (Recommended: tEXt Chunk)

```
PNG file structure:
  [IHDR] Image header
  [tEXt] ← Add "MKPE-Proof: <root_hash>"
  [IDAT] Image data
  [IEND] End marker
```

**Advantages**:
- No quality loss
- Standard PNG chunk
- Easy extraction
- Compatible with all viewers

### JPEG (Recommended: COM Segment)

```
JPEG file structure:
  [SOI] Start of image
  [APP1] EXIF data
  [COM] ← Add "MKPE:<root_hash>"
  [SOF] Start of frame
  [SOS] Start of scan
  [EOI] End of image
```

**Advantages**:
- Standard JPEG segment
- No re-encoding needed
- Minimal overhead

### Binary Files (Custom Segment)

```
Binary structure:
  [Original file]
  [MKPE_MARKER: "MKPE\x00\x01"]
  [Length: u32]
  [Root hash: 32 bytes]
  [Signature: 64 bytes]
```

---

## Example Workflow

### Embed Provenance into Image

```bash
# 1. Create bundle from project
mkpe bundle myproject/ -k project.key -o myproject.mkpe

# 2. Create marketing image
create_image.sh → hero_image.png

# 3. Embed proof into image
mkpe_stego embed hero_image.png \
  --from-bundle myproject.mkpe \
  --output hero_image_proven.png

# 4. Distribute proven image
publish hero_image_proven.png
```

### Verify Downloaded Image

```bash
# 1. Download image from untrusted source
wget https://example.com/hero_image_proven.png

# 2. Extract embedded proof
mkpe_stego extract hero_image_proven.png > extracted_hash.txt

# 3. Verify against known bundle
mkpe verify myproject.mkpe
mkpe inspect myproject.mkpe | grep root_hash

# 4. Compare hashes
diff <(cat extracted_hash.txt) <(mkpe inspect myproject.mkpe | grep root_hash)
```

---

## Security Considerations

### What Stego Provides
- ✅ Proof survives file copying
- ✅ Can verify provenance of media
- ✅ Embedded data authenticated

### What Stego Does NOT Provide
- ❌ Content authenticity (pixel-level)
- ❌ Tamper evidence (image can be re-encoded)
- ❌ Primary proof (`.mkpe` is still required)

**Steganography is convenience, not security**

Use the `.mkpe` bundle for authoritative verification.

---

## Proposed File Structure

```
C:\mkpe\stego\
├── mkpe_stego.exe          # CLI tool (future)
├── libmkpe_stego.dll       # Library (future)
├── src\
│   ├── png_embed.rs        # PNG implementation
│   ├── jpeg_embed.rs       # JPEG implementation
│   ├── mp3_embed.rs        # MP3 implementation
│   ├── mp4_embed.rs        # MP4 implementation
│   └── binary_embed.rs     # Generic binary
├── schemas\
│   └── stego_manifest_v1.json
├── tests\
│   ├── test_images\
│   └── test_audio\
└── docs\
    ├── README.md           # This file
    └── stego_usage.md      # Detailed usage guide
```

---

## Implementation Checklist

### Phase 1: PNG Support
- [ ] Implement PNG tEXt chunk embedding
- [ ] Implement extraction
- [ ] Add verification
- [ ] Write tests
- [ ] Document usage

### Phase 2: JPEG Support
- [ ] Implement COM segment embedding
- [ ] Implement extraction
- [ ] Add verification
- [ ] Write tests

### Phase 3: Audio/Video
- [ ] Implement MP3 ID3v2 embedding
- [ ] Implement MP4 user data atom
- [ ] Add tests

### Phase 4: Binary Support
- [ ] Design binary segment format
- [ ] Implement embedding/extraction
- [ ] Add tests

---

## Example API (Future)

```rust
use mkpe_stego::*;

// Embed proof into image
let bundle = MkpeArchive::load("project.mkpe")?;
let root_hash = bundle.manifest.bundle_root_hash;

embed_png(
    "hero_image.png",
    &root_hash,
    "hero_image_proven.png"
)?;

// Extract and verify
let extracted_hash = extract_png("hero_image_proven.png")?;
assert_eq!(extracted_hash, root_hash);

// Full verification
verify_stego(
    "hero_image_proven.png",
    "project.mkpe"
)?;
```

---

## Standards Compliance

- **PNG**: Follow PNG specification (ISO/IEC 15948)
- **JPEG**: Follow JPEG spec (ISO/IEC 10918)
- **MP3**: Follow ID3v2.4 specification
- **MP4**: Follow ISO/IEC 14496-12

All embedding methods use standard, documented mechanisms to ensure maximum compatibility.

---

**Status**: Ready for design and implementation in v1.2.0

**Note**: This layer is entirely optional. The core `.mkpe` format remains the authoritative proof source.



