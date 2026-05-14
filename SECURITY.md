# Security Policy

MKPE is the Morse-Kirby Provenance Engine -- a cryptographic notary for files
and build artifacts. Security regressions in MKPE silently weaken every system
that trusts its attestations. We treat it as critical infrastructure for
VyreVault Studios and its downstream consumers.

## Reporting a Vulnerability

**Do not open a public GitHub issue.**

Email: `security@vyrevault.studio`

Include:

- Affected component (`core`, `cli`, `service`, `ui*`, build pipeline, or
  released artifact).
- Affected version or commit SHA.
- Reproduction steps.
- Whether you have already disclosed publicly (and if so, where).

We will:

1. Acknowledge within **72 hours**.
2. Confirm or refute within **7 days** with a CVSS triage.
3. Ship a fix or mitigation within **30 days** for High/Critical, **90 days**
   for Medium, on a best-effort schedule for Low.
4. Credit you in the advisory unless you request otherwise.

Coordinated disclosure: we will not name you until a fix is available and
deployed. We will not threaten or pursue legal action against good-faith
researchers operating within this policy.

## Supported Versions

| Version | Status | Security fixes |
|---|---|---|
| 1.x (post-SLSA-L3, future) | TBD | Yes |
| 1.0.0 (frozen, 2025-10-08) | Maintenance | Critical only, on request |
| pre-1.0 | Unsupported | None |

The transition from 1.0.0 (self-attested) to the first SLSA-L3-attested
release will be announced via a signed advisory and a fresh root certificate.

## Key Custody

See [`docs/security/KEY_ROTATION.md`](docs/security/KEY_ROTATION.md) for the
full custody model. Summary:

- **Content keys** (per-machine, sign user vault entries): rotated every 90
  days, bound to OS keychain or TPM.
- **Release keys**: ephemeral, OIDC-bound, minted per build by Sigstore Fulcio.
  No long-lived release key exists on any device.
- **Root identity**: hardware-only (FIDO2), 2-of-3 threshold, offline, rotated
  annually or on custodian change.

## Build Integrity

Releases are built on a hardened CI runner (currently: GitHub Actions, target
state: SLSA Build Level 3 via [`slsa-framework/slsa-github-generator`]). Each
release ships with:

- The binary artifact (per target triple).
- A CycloneDX SBOM (`.cdx.json`).
- An in-toto SLSA Provenance v1.0 attestation (`.intoto.jsonl`).
- A cosign bundle with Rekor transparency-log inclusion proof.

Verify a downloaded release with:

```bash
mkpe verify-release ./mkpe-<version>-<target>.zip
```

This subcommand will be available starting with the first SLSA-L3 release.
Until then, verify manually with:

```bash
cosign verify-blob \
    --bundle  ./mkpe-<version>-<target>.zip.bundle \
    --certificate-identity "https://github.com/VyreVault/mkpe/.github/workflows/release.yml@refs/tags/v<version>" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    ./mkpe-<version>-<target>.zip

slsa-verifier verify-artifact \
    --provenance-path ./mkpe-<version>-<target>.intoto.jsonl \
    --source-uri github.com/VyreVault/mkpe \
    --source-tag v<version> \
    ./mkpe-<version>-<target>.zip
```

## Threat Model (Summary)

MKPE defends against:

| Adversary capability | Defense |
|---|---|
| Tampered upstream dependency | `cargo-vet` audit ledger + `cargo-deny` advisory gate + pinned `Cargo.lock` |
| Malicious build script in CI | SLSA L3 isolated provenance generator; signing happens outside the build job |
| Stolen long-lived release key | No long-lived release keys exist (Sigstore keyless) |
| Backdated artifact | RFC 3161 trusted timestamp + Rekor transparency log |
| Compromised maintainer account | 2-person review on `main`; signed commits required; root identity is 2-of-3 hardware |
| Compromised root identity | `revoked_keys.json` ships with verifier; trust policy can be rotated by emergency root ceremony |

MKPE does **not** defend against:

- Compromise of the user's machine while a content key is unlocked (the
  content key signs whatever the OS hands it).
- Steganographic embedding being mistaken for content authenticity (we are
  explicit that stego is convenience, not security -- the `.mkpe` bundle is
  always the source of truth).
- Side-channel attacks against ed25519 implementations (we depend on upstream
  `ed25519-dalek` to maintain constant-time guarantees; advisories there
  trigger immediate rotation).
