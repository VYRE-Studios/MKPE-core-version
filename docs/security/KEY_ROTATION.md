# MKPE Key Rotation & Custody Procedure

> **Status:** Phase 0 baseline. Replaces the implicit policy from the
> v1.0 freeze era. Reviewed every 90 days or after any suspected incident.

## TL;DR

The pre-Phase-0 keys at `secrets/keypair.json` and `examples/mkpe_private.key`
were generated and stored on a workstation filesystem without HSM, TPM, or
OS-keychain backing. They are treated as **possibly exposed** until rotated.
Any artifact signed by them retains evidentiary value only as a historical
fact -- not as a forward security guarantee.

## Threat Model for Signing Keys

MKPE has at least three distinct signing identities, each with its own threat
model. Conflating them is the single most common way provenance systems get
weaker than the algorithms they advertise.

| Identity | Purpose | Lifetime | Custody |
|---|---|---|---|
| **Content key** | Signs `.mkpe` vault entries created on a user machine | Long-lived (years) | DPAPI / kernel keyring / TPM, bound to the machine |
| **Engine release key** | Signs MKPE binary releases | **Ephemeral, per-build** | Sigstore/Fulcio OIDC, never on disk -- *or* hardware-backed KMS if self-managed |
| **Root identity** | Signs the certificate of trust enumerating valid Engine release keys | Hardware-only (YubiKey / Nitrokey / SoloKey FIDO2) | Offline, two-of-three custodians |

These keys must **never** be the same key, the same key material, or even the
same algorithm parameters where avoidable. SLSA L3 requires that the build
platform's signing identity be inaccessible to the build script, which is only
true if the release key is distinct from any developer or content key.

## Immediate Action -- Pre-Phase-0 Key Quarantine

MKPE's primary dev workstation is Windows. The procedure below is
Windows-first; the Linux block is included for any cross-platform CI host or
secondary dev machine.

### Windows (primary)

Run in an **elevated** PowerShell on every Windows machine that has ever held
an MKPE signing key:

```powershell
# Step 1 -- create a quarantine directory outside the repo working tree.
$quarantine = "$env:LOCALAPPDATA\MKPE\keys.quarantine"
New-Item -ItemType Directory -Path $quarantine -Force | Out-Null

# Step 2 -- lock its ACL down to the current user only. Break inheritance
# first so a future Group Policy change can't re-open it.
icacls $quarantine /inheritance:r /grant:r "${env:USERNAME}:(F)" | Out-Null

# Step 3 -- move every known pre-Phase-0 key file out of the working tree.
$paths = @(
    'H:\MKPE\secrets\keypair.json',
    'H:\MKPE\secrets\vault.json',
    'H:\MKPE\examples\mkpe_private.key',
    'H:\MKPE\examples\mkpe_public.key',
    "$env:APPDATA\MKPE\keys"
)
foreach ($p in $paths) {
    if (Test-Path $p) {
        Move-Item -LiteralPath $p -Destination $quarantine -Force
        Write-Host "Quarantined: $p"
    }
}

# Step 4 -- verify the working tree is clean of key material.
Get-ChildItem H:\MKPE -Recurse -Include '*.key','*.pem','keypair.json' `
    -ErrorAction SilentlyContinue
# Expected output: nothing.
```

Then confirm git won't accept them even if explicitly added:

```powershell
git -C H:\MKPE check-ignore -v `
    secrets\keypair.json `
    secrets\vault.json `
    examples\mkpe_private.key `
    examples\mkpe_public.key
# Expected: four lines, each pointing at a .gitignore rule. The files
# themselves are now gone from disk -- this just proves git's policy holds
# in case any of those names ever recur.
```

### Linux / macOS (secondary -- CI hosts, occasional dev)

```bash
mkdir -p ~/.config/mkpe/keys.quarantine
mv ~/.config/mkpe/keys/* ~/.config/mkpe/keys.quarantine/ 2>/dev/null || true
chmod 700 ~/.config/mkpe/keys.quarantine
chmod 600 ~/.config/mkpe/keys.quarantine/*
```

## Phase 1 Rotation -- Generating Fresh Keys

### Content Key (per-machine)

Done by the MKPE engine itself, not by hand. After Phase 1 ships:

```powershell
# Windows (primary): wrap the private key with DPAPI (per-user, machine-bound)
mkpe key generate --kind content --backed-by dpapi

# Windows with TPM 2.0 available: prefer the platform crypto provider
mkpe key generate --kind content --backed-by ncrypt --provider "Microsoft Platform Crypto Provider"
```

```bash
# Linux / macOS
mkpe key generate --kind content --backed-by keyring   # Secret Service / Keychain
mkpe key generate --kind content --backed-by tpm        # any with TPM2 / Secure Enclave
```

The private key never appears on disk in cleartext. The public key is emitted
in PEM to stdout for distribution.

**Windows custody specifics:**

- **DPAPI** binds the key to the current user account on the current machine.
  Migrating the user profile re-wraps it transparently; cloning a VHD does
  not. Sufficient for the content-signing threat model.
- **CNG / `ncrypt` with TPM-backed provider** raises the bar so a stolen
  disk image cannot recover the key even with the user's password. Required
  if MKPE is processing third-party material under contract.
- **Windows Certificate Store** (`Cert:\CurrentUser\My`) is acceptable for
  the public half of release keys; do **not** use it for ed25519 private
  keys (CAPI/CNG support for ed25519 is uneven across Windows versions).

### Engine Release Key

Do **not** generate one. Once Phase 2 lands, releases are signed via Sigstore
keyless flow: the GitHub Actions OIDC token mints a short-lived Fulcio cert
bound to the workflow identity. The "key" is the workflow's identity at
`repo:VyreVault/mkpe@refs/tags/v*`. This is the SLSA L3 win.

If political/legal constraints later require a self-managed release key,
generate it inside an HSM (YubiHSM 2, AWS CloudHSM, GCP Cloud KMS w/ HSM-backed
keyring) -- never on a general-purpose machine -- and rotate annually.

#### What “rotation” means for keyless release signing

There is **no long-lived private key** to rotate in the traditional sense. The
cryptographic identity is a **short-lived Fulcio certificate** minted per build
from the GitHub Actions OIDC token. What you maintain instead:

1. **Workflow ref binding.** Trust is anchored in the workflow path and ref
   embedded in the certificate (for example
   `https://github.com/<org>/<repo>/.github/workflows/release.yml@refs/tags/vX.Y.Z`).
   Verifiers must pin an acceptable ref (tags for production; `main` only if
   you explicitly accept that policy risk).

2. **Policy updates when the workflow moves.** If you rename the workflow file,
   split jobs, or change the OIDC `builder_id` string you embed in
   `build_context.json`, downstream verification policies (`mkpe
   verify-attestation --certificate-identity`, `cosign verify-blob`, etc.) must
   move in lockstep.

3. **Fulcio / Sigstore / Rekor roots.** Public-good Sigstore rotates trust
   material on its own schedule; `cosign` / `mkpe` consume TUF roots bundled
   with the tooling. Keep release CI images and developer CLIs on supported
   versions so root updates do not strand verification.

4. **Incident response.** If a workflow or repository is compromised, you
   revoke trust by **yanking tags**, **disabling the workflow**, and
   **publishing an advisory** that lists affected artifact digests -- not by
   rotating a static Ed25519 keypair tied to the builder.

### Root Identity

Generate on an air-gapped machine, on hardware tokens:

```bash
# On the air-gapped machine, with three fresh FIDO2 tokens plugged in
mkpe root ceremony --custodians 3 --threshold 2 \
    --token /dev/hidraw0 \
    --token /dev/hidraw1 \
    --token /dev/hidraw2 \
    --output root-cert.pem
```

The root identity signs a `trust_policy.json` that enumerates which Sigstore
workflow identities are accepted as Engine release signers. This file ships
with `mkpe verify-release` so end users can verify without trusting Sigstore's
root of trust unconditionally.

## Rotation Triggers

Rotate immediately on any of:

- A custodian leaves the org or loses physical control of their FIDO2 token.
- Compromise of any machine that has held the quarantined pre-Phase-0 keys.
- Public disclosure of a vulnerability in ed25519-dalek or its transitive deps
  with rating >= 7.0 CVSS.
- 12 months elapsed since the last root ceremony.
- 90 days elapsed since the last content key rotation on any production
  machine (release keys rotate automatically per build).

## Revocation

When a key is rotated out, add its fingerprint to `revoked_keys.json` shipped
alongside the verifier. `mkpe verify-release` must:

1. Fail closed on any signature chaining to a revoked key, **regardless** of
   the artifact's signature timestamp -- the revocation is a hard refusal, not
   a "valid before revocation" softening, because we have no trustworthy clock
   for the attacker's signature.
2. Surface the revoked key fingerprint and the rotation reason in the error.

## Audit Log

Every key operation -- generation, rotation, revocation, custodian change --
appends a signed entry to `attestation/key_log.jsonl`. The log itself is
append-only and signed by the previous head's signer. Loss of log continuity
is a P0 incident.

| Date | Operation | Key fingerprint | Operator | Reason |
|---|---|---|---|---|
| _populate after first rotation_ | | | | |

## Cross-References

- [`docs/SLSA_PLAN.md`](../SLSA_PLAN.md) -- where this fits in the broader supply-chain plan.
- [`SECURITY.md`](../../SECURITY.md) -- disclosure policy and root identity public key.
