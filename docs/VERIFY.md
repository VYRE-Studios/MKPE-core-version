# Verifying MKPE release artifacts and attestations

MKPE Windows release binaries ship with a **DSSE** envelope (`*.intoto.jsonl`)
containing an **in-toto Statement v1** whose predicate is **SLSA Provenance
v1.0**. The signing identity for GitHub-built releases is **Sigstore keyless**
(Fulcio certificate bound to the GitHub Actions OIDC subject for
`.github/workflows/release.yml`).

This document is the operator-facing verification guide referenced from
`docs/SLSA_PLAN.md` Phase 2.4.

## What you need

- The **artifact** (for example `mkpe.exe` from the workflow bundle).
- The **attestation file** next to it (for example `mkpe.exe.intoto.jsonl`).
- For **Sigstore keyless** envelopes: the expected **certificate identity**
  (must match `builder.id` / `builder_id` in the build context JSON) and the
  GitHub Actions OIDC issuer URL.

Local-key (Ed25519) envelopes instead carry a public key; use
`mkpe verify-attestation --pubkey …` as documented in the main README.

## Primary path: `mkpe verify-attestation`

This is the supported, schema-aware verifier; it checks DSSE `payloadType`,
signature material, optional Sigstore bundle via `cosign`, and the embedded
JSON Schema for the SLSA predicate.

```powershell
# Windows: identity must match builder_id baked into the attestation / context JSON
$builderId = (Get-Content .\build_context.json | ConvertFrom-Json).builder_id
mkpe verify-attestation `
  .\mkpe.exe.intoto.jsonl `
  --certificate-identity $builderId `
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" `
  --artifact .\mkpe.exe `
  --json
```

Exit codes are a stable contract (see `AGENTS.md` / CLI help): `0` success,
`2` signature, `3` schema, `4` digest mismatch, `5` malformed envelope, etc.

## Cross-check: `cosign verify-blob` on the DSSE PAE

MKPE signs the **DSSE Pre-Authentication Encoding (PAE)** of
(`payloadType`, decoded `payload`), not the raw base64 payload string.
`cosign sign-blob` / `cosign verify-blob` therefore operate on those exact PAE
bytes. The release workflow recomputes PAE and calls `cosign verify-blob` in
CI (`scripts/ci/verify_cosign_dsse_bundle.sh`) so we stay aligned with the
upstream Sigstore CLI.

If you reproduce this by hand: decode the envelope JSON, base64-decode
`payload`, build PAE per the [DSSE spec](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md),
write the bytes to a file, extract `.signatures[0].sigstore_bundle` to a JSON
file, then:

```bash
cosign verify-blob \
  --bundle sigstore-bundle.json \
  --certificate-identity "$BUILDER_ID" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  dsse-pae.bin
```

## `slsa-verifier verify-artifact` (upstream tool)

`slsa-verifier` is the OpenSSF reference implementation for verifying SLSA
provenance from **curated** CI builders (notably the **SLSA GitHub generator**
workflows and a small set of other registered builder IDs and `buildType`
pairs). Its v1.0 parser matches `(builder ID path,
predicate.buildDefinition.buildType)` against an internal allowlist before it
evaluates your predicate.

MKPE’s release pipeline uses a **first-party** workflow
(`.github/workflows/release.yml`) and a **custom** provenance `buildType`
(`https://github.com/VyreVault/mkpe/build/v1` in the schema example). That
combination is **not** registered inside `slsa-verifier` today, so
`slsa-verifier verify-artifact` will reject MKPE envelopes with an
**invalid builder id / build type** class error even when the Sigstore
signature and SLSA payload are otherwise correct.

**Practical guidance**

- Treat **`mkpe verify-attestation`** (and the **`cosign verify-blob`** PAE
  check above) as the supported verification path for MKPE-produced DSSE.
- Use **`slsa-verifier`** when you consume artifacts from builders it
  explicitly supports (for example repositories using `slsa-github-generator`).
- If you need `slsa-verifier` interoperability for MKPE itself, that is a
  roadmap item: either adopt a registered GitHub Actions `buildType` (for
  example `https://actions.github.io/buildtypes/workflow/v1`) and align
  `externalParameters` with that contract, or pursue upstream support for
  additional builder registrations.

## `cosign verify-attestation` (optional)

Cosign can verify attestations stored in OCI or other Cosign-native layouts.
MKPE’s on-disk format is a **single JSON DSSE envelope** (pretty-printed),
which is the same logical object Cosign uses internally; for file-based
artifacts released next to the binary, `mkpe verify-attestation` remains the
straightforward entry point.

## Further reading

- `docs/SLSA_PLAN.md` — roadmap and phase status.
- `docs/security/KEY_ROTATION.md` — custody; keyless release identity section.
- `SECURITY.md` — disclosure and threat model summary.
