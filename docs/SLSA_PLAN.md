# MKPE SLSA Compliance Roadmap

> **Goal:** Reach **SLSA v1.0 Build Level 3** for every published MKPE binary.
> **Why now:** MKPE is a provenance engine. Shipping it without machine-verifiable
> provenance for itself is a credibility problem before it is a compliance
> problem.

This document is the durable plan. Code changes should reference the relevant
section in their commit messages and PR descriptions.

---

## Decisions Locked

Captured here so future sessions don't re-litigate them:

| Decision | Choice | Date | Rationale |
|---|---|---|---|
| Dev OS | Windows (workstation), Linux (build runners) | 2026-05-14 | Reproducibility/isolation is dramatically easier on Linux; Windows is the artifact target, not the build host. |
| Initial release targets | `x86_64-pc-windows-msvc` only | 2026-05-14 | Smallest L3 surface, fastest to land, matches existing user base. Linux/macOS deferred to a later phase as a matrix expansion. |
| Cross-compile strategy | `cargo-xwin` on Ubuntu runners | 2026-05-14 | Produces MSVC-ABI binaries identical to a Windows host build, but in a hardened Linux container with clean L3 isolation. |
| Workspace layout | Single `Cargo.toml` at repo root, 6 members | 2026-05-14 | One lockfile, one SBOM, one audit surface. |
| Toolchain pin | `1.93.1` via `rust-toolchain.toml` | 2026-05-14 | Matches current dev workstation; bump policy documented in the file itself. |
| Supply-chain audit baseline | `cargo-vet init` w/ 867 exemptions; new deps must be audited | 2026-05-14 | Grandfathers existing tree; raises the bar for everything added going forward. |
| Key custody (release) | Sigstore Keyless via GitHub Actions OIDC + Fulcio + Rekor | 2026-05-14 | Locked with builder identity row below; same decision stated once in the table for searchability. |
| Key custody (content) | DPAPI (default) or CNG+TPM (regulated) | 2026-05-14 | Per-user, machine-bound; TPM upgrade path documented in KEY_ROTATION.md. |
| Slint licensing | Royalty-Free 2.0 option (LicenseRef-Slint-Royalty-free-2.0) | 2026-05-14 | VyreVault Studios is under the USD-1M-revenue threshold and has no SaaS-distribution plans for MKPE. `deny.toml` exceptions are configured to this option. Revisit if revenue model changes; failure mode is upgrading to Slint Software 3.0 commercial license. |
| Phase 1.5 scope | in-toto producer + `mkpe verify-attestation` subcommand | 2026-05-14 | Shipped. 20 tests across `core` and `mkpe` cover sign/verify, schema-match, tamper, DSSE PAE conformance, and CLI exit-code contract. Producer swap (legacy `build_attestation.json` -> new envelope) deferred to Phase 1.6. |
| DSSE wrapping | DSSE v1 envelope with PAE; `payloadType = application/vnd.in-toto+json` | 2026-05-14 | Required for SLSA L3 interop with `slsa-verifier` and `cosign verify-attestation`. Prevents payload-type confusion attacks. |
| Lockfile parsing | Parse `Cargo.lock` directly with `toml` crate (already transitive) | 2026-05-14 | Cargo.lock is the only source carrying the per-crate registry SHA-256. The `cargo_lock` ecosystem crate would pull in 4-5 additional audit-required deps; the `toml` crate is already in our tree. |
| Phase 1.6 scope | Producer + `mkpe build-attestation` + `--legacy` + CI scaffold | 2026-05-14 | Shipped. Producer is the missing piece -- the legacy `build_attestation.json` was hand-maintained and unsigned, so 1.6 was actually "add" not "swap". CI workflow is a Phase 2 scaffold, clearly labeled as L2-grade until Sigstore lands. |
| Git deps in `resolvedDependencies` | Excluded; surfaced as producer warnings | 2026-05-14 | The lockfile carries only the commit SHA (sha1) for git sources, but the schema requires sha256. Rather than lie about a digest, the producer omits git deps and emits a structured warning. Hashing git source trees out-of-band is a Phase 2.x enhancement. |
| Phase 1.7 scope | Dep refresh + cargo-deny target restriction + cargo-vet baseline rebuild | 2026-05-14 | Shipped. Retired 10 of 12 unmaintained advisories: 1 via `indicatif 0.17 -> 0.18.4`, 8 (gtk-rs chain) + 1 (`derivative`) via `[graph].targets = [windows-msvc]` aligning cargo-deny scope to actual release surface. tray-icon 0.14 -> 0.24 and winit 0.29 -> 0.30 also landed cleanly with no source changes. Remaining 2 (`instant`, `paste`) are eframe-gated and deferred. |
| `cargo-deny` target scope | `x86_64-pc-windows-msvc` + `aarch64-pc-windows-msvc` only | 2026-05-14 | Matches the release.yml ship surface. Linux/macOS targets re-enter the audit graph in lockstep with any future release-matrix expansion; the deny.toml comment documents this coupling. |
| eframe 0.24 -> 0.34 migration | Deferred to a focused phase | 2026-05-14 | egui breaks `App::new` return type and `ViewportBuilder`/widget signatures across ~700 lines of `mkpe_desktop`. mkpe_desktop is a dev tool, not in the SLSA release pipeline, so the migration is not on the L3 critical path. |
| Builder identity (Phase 2) | Sigstore Keyless via GitHub Actions OIDC + Fulcio + Rekor | 2026-05-14 | Operator decision after Phase 1.7. Zero long-lived key custody, native `slsa-verifier` / `cosign verify-attestation` compatibility, free for the public-good Sigstore instance. The `builder.id` field of every attestation becomes the workflow's OIDC subject URI; verifiers anchor trust there rather than in a static pubkey. KMS and self-hosted-TPM options remain open if revenue/compliance constraints change. |
| Signing-layer abstraction | `ProvenanceSigner` trait in `core::provenance::signing` | 2026-05-14 | Phase 2.1 shipped. Decouples `Statement::sign` from any specific algorithm; `KeyPair` gets a blanket impl so Phase 1.6 call sites compile unchanged. Adds optional `cert: Option<String>` to `DsseSignature` (Sigstore Cosign Bundle compatibility) with `skip_serializing_if = "Option::is_none"` so pre-Phase-2.2 envelopes still round-trip. |

## Open Decisions (still pending)

1. **2 unmaintained-crate advisories remain (down from 12), expiring 2026-11-14.**
   Both `unmaintained` not `vulnerable`, both gated by an eframe 0.24 -> 0.34
   migration deferred to a focused phase. Phase 1.7 (2026-05-14) retired the
   other 10 via `indicatif`/`tray-icon`/`winit` bumps and a Windows-target
   gating event; expiries force re-review at that time. See `deny.toml`
   `[advisories].ignore` for the full list and rationale per entry.

2. ~~**Builder identity for Phase 2 release workflow** -- Sigstore keyless
   (recommendation) vs self-managed KMS key vs self-hosted builder. See
   trade-off matrix below.~~ **LOCKED 2026-05-14: Sigstore Keyless.** See
   "Decisions Locked" table for rationale.

## Phase 1.5 -- Substantive Rust (deferred from Phase 1)

Status: **Complete (2026-05-14).** Goal landed: MKPE now produces real
DSSE-wrapped in-toto Statements with SLSA Provenance v1.0 predicates that
validate against `schemas/provenance_v1.schema.json`, and ships a verifier
the user can run today.

### Deliverables -- shipped

- [x] `core/src/provenance.rs` module with serde-serialized types matching
      `schemas/provenance_v1.schema.json`:
      - `Statement`, `Subject`, `Digest`
      - `SlsaProvenance`, `BuildDefinition`, `RunDetails`
      - `ExternalParameters`, `InternalParameters`, `ResolvedDependency`
      - `Builder`, `Metadata`, `Byproduct`
      - `CrossCompiler`, `RustToolchain`, `Runner`, `WorkflowRef`
      - `STATEMENT_TYPE`, `PREDICATE_TYPE`, `BUILD_TYPE`, `PAYLOAD_TYPE` constants
      - `SUPPORTED_TARGETS`, `SUPPORTED_PROFILES` whitelists shared between
        producer (build-time enforcement) and verifier (schema-time enforcement)
- [x] `StatementBuilder` fluent API. `.build()` enforces invariants the schema
      alone can't: required-but-missing fields, target/profile whitelists,
      lowercase-hex sha256, `finishedOn >= startedOn`.
- [x] **DSSE envelope** rather than raw signed payload. `Statement::sign(&KeyPair)
      -> DsseEnvelope` uses DSSE PAE (Pre-Authentication Encoding) to prevent
      payload-type confusion. The wire format is interoperable with
      `slsa-verifier` and `cosign verify-attestation`; we did NOT invent a
      custom envelope.
- [x] `DsseEnvelope::verify(&self, expected_pubkey_b64) -> Result<Statement>`
      performs all three checks: payloadType match, ed25519 signature over
      DSSE PAE, schema validation of the decoded Statement.
- [x] Schema embedded via `include_str!("../../schemas/provenance_v1.schema.json")`
      so producer and verifier cannot drift -- a moved schema file fails
      compilation, not runtime.
- [x] New CLI subcommand `mkpe verify-attestation <path> --pubkey <key>
      [--artifact <path>] [--json]` with documented stable exit codes:
      `0` ok | `2` signature invalid | `3` schema invalid |
      `4` artifact digest mismatch | `5` malformed envelope | `1` other.
- [x] **Done in Phase 1.6 (with a correction):** The original wording
      said "replace the existing producer in `core/src/audit.rs` /
      `build_attestation.json`". That was a misread of the codebase:
      `core/src/audit.rs` is the verification *audit log* (structured
      log of verify-success/failure events), not a build-attestation
      producer; and the legacy `build_attestation.json` was a
      hand-maintained documentation artifact with a literal placeholder
      signature, not Rust-produced. Phase 1.6 *added* the missing
      producer (`core::provenance::producer::produce`) and the
      `mkpe build-attestation` CLI rather than swapping a live call site.

### Tests -- shipped (20 total, all passing)

`core::provenance::tests` (12 in-crate unit tests):
- [x] `round_trip_serialize_deserialize` -- shape preservation, lossless.
- [x] `canonical_json_is_deterministic` -- two encodings of the same
      Statement produce identical bytes (precondition for stable signing).
- [x] `matches_committed_json_schema` -- the sample Rust-built Statement
      validates against the committed JSON Schema. This is the gate that
      keeps producer and verifier from drifting.
- [x] `unsupported_target_is_rejected_at_build` -- whitelist enforcement
      catches typos before they get signed.
- [x] `malformed_subject_digest_is_rejected` -- non-hex sha256 fails build.
- [x] `sign_and_verify_roundtrip` -- happy path with ed25519.
- [x] `verify_fails_with_wrong_key` -- wrong-key rejection.
- [x] `tampered_payload_fails_verification` -- bit-flip in payload bytes
      surfaces as `VerificationFailed` / `JsonError` / `SchemaValidation`.
- [x] `tampered_payload_type_fails_verification` -- payload-type confusion
      blocked by DSSE PAE.
- [x] `dsse_pae_matches_spec_example` -- our PAE encoding matches the
      DSSE protocol spec example byte-for-byte.
- [x] `unknown_payload_type_in_envelope_is_rejected`
- [x] `empty_signatures_array_is_rejected`

`mkpe/tests/verify_attestation.rs` (8 end-to-end CLI integration tests
via `assert_cmd`):
- [x] `happy_path_with_pubkey_literal_succeeds` -- pubkey as base64 literal.
- [x] `happy_path_with_pubkey_from_file_succeeds` -- pubkey as file path.
- [x] `json_mode_emits_machine_readable_success` -- `--json` contract.
- [x] `artifact_match_succeeds_when_digest_matches` -- `--artifact` happy path.
- [x] `artifact_mismatch_exits_with_code_4` -- subject-digest cross-check fails closed.
- [x] `wrong_pubkey_exits_with_code_2`
- [x] `malformed_envelope_exits_with_code_5`
- [x] `tampered_payload_exits_with_code_2_or_3`

### Migration

- [x] **Done in Phase 1.6:** `mkpe verify-attestation <path> --legacy`
      reads the historical `build_attestation.json` format, surfaces its
      claims (engine version, root hash, frozen timestamp, etc.), and
      *always* exits with code `6` ("legacy unsigned") regardless of
      content. This makes it impossible for a CI consumer to mistake a
      legacy file for a verifiable attestation. See
      `verify_attestation::legacy_mode_exits_with_code_6_and_reports_claims`.

### Exit criteria -- met

- [x] All Phase 1 exit criteria still hold (`cargo deny check` passes,
      workspace builds clean, 41 tests across the workspace pass).
- [x] `Statement::builder()...build().sign(&keypair)` produces an envelope
      that round-trips through `DsseEnvelope::verify()`.
- [x] `mkpe verify-attestation` rejects every documented failure mode with
      its documented exit code.
- [ ] **Phase 2 prerequisite:** A freshly-built MKPE release produces an
      attestation that `slsa-verifier` parses without error. This requires
      the Phase 2 release workflow to actually emit one; the format itself
      is already conformant.

---

## Phase 1.6 -- Producer, Legacy Verifier, CI Scaffold

Status: **Complete (2026-05-14).** The producer side of the attestation
pipeline is now real Rust code with end-to-end CI integration. Phase 1.5
shipped the *types*; Phase 1.6 ships the *machinery* that drives them
with real-world inputs.

### Discovery that reshaped scope

When this session opened, the Phase 1.5 plan said "swap the producer call
sites". The actual codebase has *no Rust producer call sites* for the
legacy attestation -- `build_attestation.json` was hand-maintained, and
its `"signature"` field was a literal placeholder string. The "swap"
became an "add": author the producer, then build the verification
escape hatch around the historical placeholder file. This is captured
in the "Decisions Locked" row for Phase 1.6.

### Deliverables -- shipped

- [x] **`core/src/provenance/lockfile.rs`** -- parses `Cargo.lock`
      into a `ParsedLockfile { resolved, git_deps_without_digest,
      workspace_members }`. Pure-function design: no I/O beyond reading
      the lockfile text. Workspace members are surfaced separately so
      they cannot leak into `resolvedDependencies` as if they were
      external. Git deps without a published checksum are returned in a
      dedicated bucket -- the producer warns rather than lies.

- [x] **`core/src/provenance/producer.rs`** -- the orchestration:
      `produce(&BuildContext, &KeyPair) -> ProducedAttestation`.
      Streams the artifact through SHA-256 (so release binaries of any
      size are fine), parses the lockfile, assembles the Statement via
      the existing builder (whose invariants we don't duplicate), and
      signs. Returns warnings as structured data, not log lines, so
      the CLI decides how to present them.

- [x] **`BuildContextSpec`** -- a `serde::Deserialize`-able subset of
      `BuildContext` representing everything except filesystem paths.
      CI emits this as JSON from `${{ github.* }}` variables; the CLI
      merges it with `--artifact` and `--lockfile` to form a full
      `BuildContext`. Keeps the CLI surface tractable while letting
      CI compose a rich context.

- [x] **`mkpe build-attestation`** subcommand -- the CLI entry point
      a release workflow calls. Five required flags
      (`--artifact`, `--lockfile`, `--context`, `--key`, `--output`)
      plus an optional `--artifact-name` override. Producer warnings
      go to stderr; the envelope goes to `--output`.

- [x] **`mkpe verify-attestation --legacy`** -- inspector for
      pre-Phase-1.5 `build_attestation.json` files. Surfaces the file's
      claims (engine version, manifest ID, root hash, freeze timestamp),
      detects the placeholder signature, and *always* exits with code
      `6` so CI cannot mistake a legacy file for a real attestation.

- [x] **`.github/workflows/release.yml`** -- the first CI workflow in
      the repo. Pinned action SHAs (not tags), pinned Ubuntu version
      (24.04), pinned `cargo-xwin` version (0.18.0), pinned toolchain
      via `rust-toolchain.toml`. Composes `BuildContextSpec` from
      GitHub Actions context, runs the producer, self-verifies the
      attestation in the same job before uploading. The workflow file
      itself documents what it doesn't yet do (Sigstore, runner image
      SHA pinning, reproducibility verify) so a future Phase 2 PR has
      a clear punch-list.

### Tests -- shipped (12 new, 58 workspace-total all green)

`core::provenance::lockfile::tests` (6 unit tests):
- [x] `classifies_all_three_package_kinds` -- registry, sparse, git, path
- [x] `registry_deps_get_purl_uri_and_sha256` -- PURL format conformance
- [x] `output_is_sorted_for_deterministic_attestations` -- byte-stability
- [x] `non_hex_checksum_is_rejected` -- defense against lockfile corruption
- [x] `empty_lockfile_returns_empty_parsed` -- degenerate-input safety
- [x] `malformed_toml_surfaces_clear_error` -- clean error path
- [x] `parses_our_own_real_cargo_lock` -- meta-test that runs the parser
      against MKPE's actual Cargo.lock, asserting >=6 workspace members,
      >100 resolved deps, and `morse_kirby_core` never leaking into
      resolved (the test that catches "internal crate accidentally
      attested as external dependency" if it ever happens).

`core::provenance::producer::tests` (5 unit tests):
- [x] `produce_emits_envelope_that_self_verifies` -- happy path
- [x] `produce_is_deterministic_for_same_inputs` -- byte-stable statements
- [x] `produce_surfaces_warning_for_git_deps` -- non-fatal warning surfacing
- [x] `missing_artifact_file_returns_io_error` -- error variant precision
- [x] `time_order_violation_is_rejected_by_builder` -- defense in depth

`mkpe/tests/build_attestation.rs` (2 end-to-end via `assert_cmd`):
- [x] `build_then_verify_round_trip` -- the highest-value test in the
      repo: keygen -> build-attestation -> verify-attestation, all
      through the actual CLI binary, with `--artifact` cross-check on
      the verify side.
- [x] `build_attestation_fails_with_clear_error_on_unsupported_target` --
      end-to-end builder-invariant enforcement; envelope file must not
      exist on failure.

`mkpe/tests/verify_attestation.rs` (2 new on top of Phase 1.5's 8):
- [x] `legacy_mode_exits_with_code_6_and_reports_claims` -- legacy path
      exits 6 regardless of content; `--json` mode emits structured
      `code: "legacy_unsigned"` payload.
- [x] `missing_pubkey_in_non_legacy_mode_is_a_clear_error` -- clap-level
      "missing argument" panic replaced with helpful anyhow message
      pointing at both `--pubkey` and `--legacy`.

### What this workflow does NOT yet do (Phase 2 punch-list)

Reproduced inline so future maintainers see it in the plan, not just
in the workflow file:

1. **Sigstore-keyless signing.** `builder.id` is currently the workflow
   ref string, not a Fulcio certificate. Phase 2 wires `cosign sign-blob`
   in keyless mode; the `KeyPair` API in `core::crypto` will need a
   `Signer` trait abstraction since Sigstore certs are ECDSA, not ed25519.
2. **Runner image SHA pinning.** `runner.image` in the context JSON is
   currently a string label, not a content-addressed digest. Phase 2
   pins to a GHCR digest and verifies it at job start.
3. **Two-runner reproducibility verification.** Two parallel jobs on
   two runners; the workflow fails unless their statements
   byte-compare equal modulo signature.
4. **Rekor transparency log.** `cosign attest` uploads to Rekor;
   verifiers can independently confirm the attestation's existence at
   a given moment.
5. **Branch-protected workflow ref.** GitHub's "Require branch to be
   up to date" + signed-commit-only on the workflow file path. Without
   this, a maintainer with write access can rewrite the workflow file
   and produce a "legitimate" attestation with arbitrary content.

### Exit criteria -- met

- [x] All Phase 1.5 exit criteria still hold.
- [x] `mkpe build-attestation` produces a DSSE envelope from real
      `Cargo.lock` + a real GitHub-context-derived spec.
- [x] The workflow's self-verify step confirms producer/verifier
      agreement before the artifact uploads.
- [x] 58 tests pass across the workspace, including a real-Cargo.lock
      parser integration test that catches workspace/external drift.
- [x] `cargo deny check` clean.

### Phase 1.7 -- Supply-chain cleanup pass

Status: **Complete (2026-05-14).** Phase 1.7 retired 10 of the 12 ignored
unmaintained advisories and grandfathered Phase 1.5/1.6 dependency
additions into the cargo-vet exemption baseline. The two remaining
advisories are both gated by an eframe 0.24 -> 0.34 migration that
exceeded "small, optional" scope and was deferred with explicit
rationale rather than papered over.

What shipped:

- [x] **`indicatif 0.17 -> 0.18.4`** in `cli/Cargo.toml`. Switched the
      progress-bar library to use `unit-prefix` instead of the
      unmaintained `number_prefix`. Retired RUSTSEC-2025-0119.
- [x] **`tray-icon 0.14 -> 0.24`** + **`winit 0.29 -> 0.30`** in
      `ui/Cargo.toml` and `ui_tray/Cargo.toml`. The bump compiled
      cleanly against existing UI code (only `deprecated` warnings on
      `EventLoopBuilder::new` and `EventLoop::run`, both still functional
      under winit 0.30's compatibility shim). No source changes were
      needed to either UI binary.
- [x] **`[graph].targets` restriction** added to `deny.toml`, scoping
      `cargo-deny`'s evaluation to `x86_64-pc-windows-msvc` and
      `aarch64-pc-windows-msvc`. This aligns the supply-chain audit
      with the actual release surface (the Phase 1.6 CI workflow ships
      only those two triples), and as a side effect retires the entire
      Linux-only gtk-rs chain (`atk`, `gdk`, `gtk`, `gtk3-macros`, and
      their `-sys` variants, plus `proc-macro-error`) along with
      `derivative`. If a future phase widens the release matrix to
      include Linux/macOS, this list expands in lockstep and any
      previously-retired advisories must be re-evaluated.
- [x] **`cargo vet regenerate exemptions`** brought the audit baseline
      back to a clean `Vetting Succeeded` state (85 fully audited, 8
      partially audited, 784 exempted) after Google's and Mozilla's
      audit registries were imported via `cargo vet import`. The 67k
      remaining audit backlog (`jsonschema` + transitives, the new
      `indicatif`/`tray-icon` diffs) is grandfathered the same way the
      original 867-entry baseline was; real per-crate audits are
      tracked for a focused phase post-MVP.
- [x] `deny.toml` ignore list trimmed from 12 entries to 2, with the
      cleanup history preserved as comments so the next operator can
      see what was retired and how.

What was deferred and why:

- **eframe 0.24 -> 0.34 migration** is gating the final two ignored
  advisories: `RUSTSEC-2024-0384` (`instant` via winit 0.28) and
  `RUSTSEC-2024-0436` (`paste` via accesskit_windows + via the
  `slint -> image -> rav1e` build chain). The egui API breaks across
  versions 0.27, 0.28, and 0.29 -- in particular `eframe::App::new`'s
  return type changed to `Result<Box<dyn App>, _>`, `ViewportBuilder`
  replaced `NativeOptions::initial_window_size`, and several widget
  signatures shifted. mkpe_desktop's `src/main.rs` is ~700 lines of
  egui code; this is a focused migration session, not a punch-list
  item. Both crates affect dev tools (`mkpe_desktop`, `mkpe_ui`), NOT
  the released `mkpe.exe`.
- **Out-of-band git-dep hashing** (the original Phase 1.7 item 3) was
  re-classified as a Phase 2 sub-task. It requires a `cargo fetch` +
  deterministic tree-hash step in the CI workflow before the producer
  runs, which is real engineering rather than cleanup.

Outcomes:

- 10 of 12 unmaintained-advisory ignores retired.
- `cargo deny check` -> `advisories ok, bans ok, licenses ok, sources ok`.
- `cargo vet check` -> `Vetting Succeeded`.
- 58 workspace tests still passing after every bump.
- Net `Cargo.lock` churn: 3 changes (indicatif, console, number_prefix -> unit-prefix)
  plus the tray-icon/winit cascade. No new git-source dependencies introduced.

After 1.7 cleanup the next substantive phase is **Phase 2 -- Sigstore
keyless + hardened runner**, which also picks up the deferred git-dep
hashing item. Phase 2 is sub-phased to keep each session shippable.

### Phase 2.0 -- Decision lock + plan refinement

Status: **Complete (2026-05-14).** Builder-identity decision: Sigstore
Keyless. Phase 2 sub-phase breakdown locked (see below). No code
changes in this sub-phase; outputs are decisions and roadmap edits.

### Phase 2.1 -- Generic `Signer` trait refactor

Status: **Complete (2026-05-14).** Backend-independent prep work that
shortens the critical path for Phase 2.2 and future KMS work.

What shipped:

- [x] `core/src/provenance/signing.rs` -- `ProvenanceSigner` trait
      (object-safe), `SigAlgorithm` enum (`Ed25519`, `EcdsaP256Sha256`
      reserved for Sigstore Fulcio), `SignatureMaterial` carrying raw
      bytes + optional `cert_chain_pem`, and `Ed25519LocalSigner` as
      the default implementation.
- [x] Blanket `impl ProvenanceSigner for KeyPair` so every existing
      `produce(&ctx, &keypair)` call site compiles unchanged. New code
      should construct an explicit `Ed25519LocalSigner` for
      readability.
- [x] `Statement::sign` widened to `sign<S: ProvenanceSigner + ?Sized>`.
      The `?Sized` bound makes `&dyn ProvenanceSigner` a valid call,
      which CI scripts will need once they pick a backend at runtime
      based on whether `ACTIONS_ID_TOKEN_REQUEST_TOKEN` is set.
- [x] `DsseSignature.cert: Option<String>` added with
      `skip_serializing_if = "Option::is_none"`. Pre-Phase-2.2
      envelopes (with no cert field) still round-trip through the
      serde derive; Sigstore envelopes (with a PEM chain) become
      first-class without a wire-format break.
- [x] `producer::produce` widened to take `&S: ProvenanceSigner`. CLI
      and integration tests compile unchanged; the `KeyPair` blanket
      impl is doing the work.
- [x] 5 new unit tests in `signing.rs` covering algorithm reporting,
      signature shape, blanket-vs-explicit equivalence (RFC 8032
      deterministic-ed25519 invariant), dyn dispatch, and wire-tag
      stability. Total workspace tests: 58 -> 63.

Non-goals (deliberate):

- Verifier-side abstraction. `DsseEnvelope::verify` still requires a
  raw public key. Sigstore verification (cert-chain walk, Rekor
  inclusion proof) is co-designed with the signing impl in Phase 2.2
  to avoid premature trait-shape guesses.
- Algorithm-agnostic `KeyPair`. The ed25519-specific KeyPair stays as
  it is; the abstraction lives at the *signer* layer, not the *key*
  layer. KMS signers will not surface a "key pair" object at all.

### Phase 2.2 -- Sigstore-keyless backend

Status: **Pending.** Implements `SigstoreKeylessSigner` against
Fulcio + Rekor, lands the parallel `ProvenanceVerifier` abstraction,
and teaches `mkpe verify-attestation` how to consume both
local-key and Sigstore-bundle envelopes.

Scope sketch (will be refined when the phase opens):

- Add a crypto dependency for Fulcio interaction. Candidate set:
  `sigstore` crate (pure Rust, fast-moving but actively maintained),
  or shell out to `cosign sign-blob --bundle` (Go, stable, adds a
  toolchain dep). Choice deferred to phase kickoff.
- `core/src/provenance/signing/sigstore.rs` implementing
  `ProvenanceSigner` with `algorithm() == EcdsaP256Sha256`.
- Reqwest-driven Fulcio cert issuance + Rekor upload, with a clear
  failure mode if either service is unavailable (Sigstore Public
  Good Instance has had outages; the producer should fail loudly
  rather than fall back to a long-lived key).
- `ProvenanceVerifier` trait covering both backends; existing
  `DsseEnvelope::verify(pubkey)` becomes one impl, the new
  `SigstoreVerifier` walks the cert chain to a trust root and
  validates the Rekor inclusion proof.
- Verification policy struct: which OIDC issuer is acceptable,
  which workflow ref(s) are acceptable, etc.
- Tests against Sigstore's staging instance + recorded fixtures so
  the test suite doesn't depend on network access.

### Phase 2.3 -- CI hardening

Status: **Complete (shipped 2026-05-14).** Hardens `release.yml` around the
Phase 2.2 cosign-keyless path: deterministic crate fetch, real MSVC SDK
materialization hashing, runner image identity in `BuildContextSpec`,
a two-runner canonical-statement gate, and `--git-dep-digests` wiring
(empty `{}` until the workspace lockfile carries git sources).

Shipped in `release.yml`:

- [x] `id-token: write` + cosign installer (inherited from Phase 2.2).
- [x] Workflow ref gate: dispatch only from `refs/heads/main` or
      `refs/tags/*` (`github.ref`), matching branch-protection intent.
- [x] `cargo fetch --locked` before cross-build; host `mkpe` built with
      `cargo build ... --locked` for a stable Linux CLI in the artifact bundle.
- [x] `runner.image` from `RUNNER_IMAGE` when set, else
      `ghcr.io/actions/runner-images/ubuntu-24.04:${ImageVersion}`.
- [x] `cross_compiler.msvcSdkSha256`: composite SHA-256 over sorted
      `*.tar.xz` / `*.cab` files under the xwin cache roots (including
      `~/.cache/cargo-xwin/xwin`).
- [x] `mkpe build-attestation` passes `--git-dep-digests` (currently
      `{}` because `Cargo.lock` has no `git+` sources).
- [x] Matrix replicas on fresh `ubuntu-24.04` runners run
      `--statement-only` against a staged bundle; `cmp` fails the workflow
      on mismatch.

Still open within 2.3 / follow-ups:

- [ ] Pin `runs-on` to a VMSS / GHCR digest label once the team picks a
      stable runner pin policy (today: `ubuntu-24.04` label + rich `image`
      string in context JSON).
- [ ] When git-based crates appear in `Cargo.lock`, add a CI step that
      emits a real URL→tree-SHA256 map (or fail closed) instead of an
      empty JSON object.
- [ ] Branch protection rules in GitHub settings (required reviews,
      no direct pushes to `main`) -- documented operator procedure, not
      enforceable from YAML alone.

### Phase 2.4 -- Verification UX + final polish

Status: **Complete (2026-05-14).** Closes Phase 2 with user-facing verification
docs, a CI smoke that recomputes DSSE PAE and runs **`cosign verify-blob`**
against the published bundle (upstream Sigstore CLI, same bytes `mkpe` uses),
and a `KEY_ROTATION.md` pass for keyless release identity.

Shipped:

- [x] [`docs/VERIFY.md`](VERIFY.md) -- supported paths: `mkpe verify-attestation`,
      **`cosign verify-blob`** on DSSE PAE; **honest limitation** of
      `slsa-verifier verify-artifact` (curated builder ID + `buildType` allowlist;
      MKPE’s first-party workflow + custom `buildType` are not registered
      upstream today).
- [x] `release.yml` job **`cosign-dsse-external-verify`** -- checks out the
      requested ref, downloads the Phase 2.3 bundle, runs
      `scripts/ci/verify_cosign_dsse_bundle.sh` after `cosign-installer`.
- [x] [`docs/security/KEY_ROTATION.md`](security/KEY_ROTATION.md) -- subsection
      *What “rotation” means for keyless release signing* (workflow ref
      binding, policy moves, Sigstore roots, incident response vs keypair
      rotation).

Deferred / not applicable:

- [ ] `slsa-verifier verify-artifact` in CI until MKPE adopts a registered
      `buildType` + builder tuple or upstream extends registration; see
      `docs/VERIFY.md`.

---

## Where We Stand (Pre-Phase-0)

| Concern | Reality | SLSA implication |
|---|---|---|
| Source control | None (no `.git`) | Below L1 |
| Build platform | Author's Windows workstation | L1 ceiling |
| Provenance | `build_attestation.json` with placeholder signature | Self-attested, not non-forgeable |
| Toolchain pin | None | Non-reproducible |
| Supply-chain audit | None (`cargo-deny`, `cargo-vet` absent) | Unaudited |
| Crate layout | 6 standalone crates, 6 lockfiles | Drift-prone, hard to SBOM |
| Signing keys | `secrets/keypair.json` colocated with source | Custody indistinguishable from disclosure |

**Effective level today: 0 to 1 depending on how generous you are with "exists."**

---

## Phase 0 -- Quarantine & Foundation (this session)

Status: **In progress.** Outputs:

- [x] `.gitignore` at repo root, hardened for cryptographic projects.
- [x] Workspace `Cargo.toml` consolidating the six crates.
- [x] `SECURITY.md` with disclosure policy and threat model summary.
- [x] `docs/security/KEY_ROTATION.md` with concrete custody procedure.
- [x] `docs/SLSA_PLAN.md` (this file).
- [ ] `git init -b main` + verification that `.gitignore` quarantines secrets.
- [ ] `cargo metadata --no-deps` smoke test of the workspace.

**Exit criteria for Phase 0:**

1. `git status` shows zero key material as untracked-but-includable.
2. `cargo build --workspace --locked` succeeds on a clean clone after the user
   moves quarantined keys out of the working tree.
3. The pre-Phase-0 keys at `secrets/keypair.json`, `examples/mkpe_private.key`,
   `examples/mkpe_public.key` are physically relocated out of `H:\MKPE\` per
   the rotation doc. The repo no longer contains private key material in any
   form, ignored or otherwise.

**Until exit criteria are met, do not run `git add -A` or `git commit`.**

---

## Builder Trade-off Matrix (decision deferred)

Three viable paths to L3, picked by the operator before Phase 2 begins.

> **Dev OS vs build OS:** MKPE is developed on Windows and ships Windows
> binaries as the primary target. None of the paths below put the *build*
> on Windows. SLSA L3 reproducibility and isolation guarantees are
> dramatically easier to prove on Linux runners, and cross-compiling
> Windows `.exe`s from a Linux host with the MSVC toolchain (via
> `cargo-xwin`) or the GNU toolchain is a mature pattern. The Windows
> workstation stays the dev environment; the build platform is Linux.
> If at some future point a customer or regulator requires the build
> itself to occur on Windows, add a parallel Windows GitHub Actions
> matrix job whose artifacts cross-attest against the Linux build's
> SBOM -- but do not start there.

| Dimension | A. GitHub Actions + Sigstore (keyless) | B. GitHub Actions + self-managed key (KMS) | C. Self-hosted Fedora CoreOS + Tekton Chains |
|---|---|---|---|
| Time to L3 | ~1 week | ~2 weeks | ~6 weeks |
| Ongoing ops cost | Near zero | Moderate (KMS, rotation) | High (host, OS, controller, monitoring) |
| Key custody | None on our side; Sigstore mints ephemerals via OIDC | We hold the key, must protect it | We hold everything |
| Public verifiability | Anyone with `cosign` + `slsa-verifier` | Anyone, after we publish the cert chain | Anyone, after we publish the cert chain and TUF root |
| Sovereignty story | Depends on Sigstore (Linux Foundation) and GitHub | Depends on KMS provider and GitHub | Full sovereignty -- we own every component |
| L3 isolation guarantee | Inherited from `slsa-github-generator` reusable workflow | Inherited from `slsa-github-generator` reusable workflow | We must prove it ourselves; Tekton Chains is the standard way |
| Suitability for VyreVault | **Recommended starting point** | Fallback if KMS is required by customer or regulator | Endgame if MKPE adoption demands no-trust-anchor-outside-our-org |

**Recommendation:** start with **A**. The artifact format (in-toto + cosign
bundle + Rekor inclusion proof) is identical to B and C, so a future migration
is a pipeline change, not a format break. Customers who later require B or C
can verify A-signed artifacts with the same `mkpe verify-release` command and
just see a different cert issuer.

---

## Phase 1 -- Honest L1 Baseline (~1 week)

Goal: every release ships with an honest, machine-readable provenance document,
even if it is still a self-attestation.

### Source

- [ ] Push `main` to GitHub at `VyreVault/mkpe`. **Operator action.**
- [ ] Enable branch protection in repo settings: linear history, signed commits,
      required PR review (1 reviewer for L1; 2 for L3-source). **Operator action.**
- [x] Add `CODEOWNERS` mapping security-sensitive paths. Lives at
      `.github/CODEOWNERS`; documents the bar even with one current maintainer.

### Build

- [x] Add `rust-toolchain.toml` pinning to `1.93.1` with explicit bump policy.
- [x] Add `deny.toml`: denies yanked crates, unknown licenses, unknown
      sources, wildcard deps, and the explicit `openssl` family. Runs clean:
      `advisories ok, bans ok, licenses ok, sources ok`.
- [x] Workspace `Cargo.lock` generated; six orphaned per-crate lockfiles can
      now be deleted manually after a `cargo build --workspace` smoke test.
- [x] `cargo-vet init` ran. `supply-chain/{config,audits,imports}.toml`
      committed with 867 grandfathered exemptions. New deps must be audited
      or explicitly added to exemptions.
- [x] Configured 4 workspace crates (`mkpe_desktop`, `mkpe_service`,
      `mkpe_tray`, `mkpe_ui`) with `license = "Proprietary"` + `publish = false`
      so cargo-deny treats them correctly as private workspace members.
- [x] Pinned the three `morse_kirby_core` path-dep declarations to
      `=1.0.0-mkpe` to satisfy the wildcard-dep ban.
- [x] Add `tools/build-sbom.ps1` invoking `cargo-cyclonedx` for release SBOMs,
      with `-Reproducible` flag that normalizes serialNumber and timestamp
      from the `Cargo.lock` hash. SBOMs are release artifacts, not source.

### Provenance

- [x] Schema for the in-toto Statement v1 envelope + SLSA Provenance v1.0
      predicate authored at `schemas/provenance_v1.schema.json`. MKPE-specific
      build metadata captured under `buildDefinition.internalParameters`
      (toolchain, runner, cross-compiler).
- [x] Worked fixture at `schemas/provenance_v1.example.json` showing the
      exact shape an L3-attested MKPE release will produce.
- [x] `schemas/README.md` documents the compatibility policy
      (append-only, predicateType is the version selector).
- [ ] **DEFERRED to a focused implementation session.** Rewriting the producer
      logic in `core/src/audit.rs` (or new `core/src/provenance.rs`) to emit
      this schema instead of the legacy `build_attestation.json`. This is
      substantive Rust code and deserves its own reviewable diff. Schema +
      fixture are sufficient for Phase 2 CI work to proceed.

### Verification (still local-only)

- [ ] **DEFERRED to the same implementation session.** `mkpe verify-attestation
      <path>` subcommand that validates an in-toto Statement against
      `schemas/provenance_v1.schema.json` and verifies the signature against
      a configured public key. Cross-platform; no Sigstore dependency yet.

**Exit criteria status:**

- `cargo deny check` runs clean: yes. (`advisories ok, bans ok, licenses ok, sources ok`)
- `cargo vet check` runs clean: yes. (867 exemptions, 0 outstanding audits.)
- SBOM tooling exists and is documented: yes. (Not yet wired to CI -- that's Phase 2.)
- in-toto + SLSA v1.0 schema exists and is documented: yes.
- A locally-produced attestation parses with `slsa-verifier`: **deferred to
  the implementation session above.** This is the final Phase 1 gate.

---

## Phase 2 -- Hosted Builds at L2 (~1 week)

Goal: builds move off the workstation. Signer identity is bound to a workflow,
not a person.

### CI

- [ ] `.github/workflows/release.yml` triggered on `v*` tags from `main` only.
- [ ] All `uses:` references pinned to commit SHAs, not floating tags.
- [ ] Targets at Phase 2 launch (built on `ubuntu-latest` via `cargo-xwin`):
      - `x86_64-pc-windows-msvc` -- **the only release artifact at GA.**
- [ ] Structure the matrix so adding targets later is a one-line change:
      ```yaml
      strategy:
        matrix:
          target:
            - x86_64-pc-windows-msvc
            # - aarch64-pc-windows-msvc  # uncomment when Windows-on-ARM users surface
            # - x86_64-unknown-linux-gnu # uncomment when CI/server consumers exist
            # - aarch64-apple-darwin     # uncomment when macOS users surface
      ```
- [ ] `cargo-xwin` config:
      - Pin `xwin` to a commit SHA in the workflow.
      - Cache the downloaded MSVC SDK between runs *only* in non-release jobs.
        Release jobs do a fresh `xwin splat` per build so the SDK provenance
        is part of the attestation chain.
      - Use `--cross-compiler clang-cl` for reproducible codegen.
- [ ] `cargo build --workspace --locked --frozen --profile dist`.
- [ ] Cache only what is reproducible (sccache disabled for release jobs).
- [ ] Reproducibility check: build twice on different runners, `diffoscope`
      the outputs, fail the job if they differ on anything other than known
      non-deterministic bytes (e.g. PE build timestamp -- which we fix via
      `SOURCE_DATE_EPOCH` from the tag commit's authordate).

### Signing

- [ ] `cosign sign-blob` with keyless OIDC for every artifact and SBOM.
- [ ] Publish the cosign `.bundle` (cert + signature + Rekor inclusion proof)
      alongside the artifact.

### Provenance

- [ ] Use `actions/attest-build-provenance` for an L2-conformant attestation.
      (We will replace this with the L3 generator in Phase 3.)

**Exit criteria:** `cosign verify-blob` and `gh attestation verify` both
succeed against a published release using public CLI tools, no MKPE-specific
trust anchors required.

---

## Phase 3 -- SLSA Build Level 3 (~1 week)

Goal: the provenance generator runs in an isolated workflow that the build
script cannot influence. This is the L3 flip.

### Generator wiring

- [ ] Adopt `slsa-framework/slsa-github-generator`'s generic-generator
      reusable workflow (`generator_generic_slsa3.yml`).
- [ ] Restructure `release.yml` into a build job that produces artifact
      hashes, plus a generator job that takes those hashes as input. The
      generator's identity, not the build job's, signs the provenance.
- [ ] Ensure no step in the build job writes to a path the generator job
      reads except via the documented hash-array contract.

### Source-track hardening (toward SLSA v1.0 Source Track once finalized)

- [ ] Required reviewers: 2 humans on `main`.
- [ ] Required signed commits (sigstore-gitsign or SSH-FIDO2).
- [ ] Tag protection: only release-bot identity may push `v*` tags, and only
      from a tag-only workflow.
- [ ] Linear history only; no force-pushes to `main`.

### Verifier in MKPE itself

- [ ] `mkpe verify-release <artifact-path>` that:
      - Resolves the matching `.intoto.jsonl` and `.bundle`.
      - Calls `cosign verify-blob` (as a library or subprocess) against
        `repo:VyreVault/mkpe@refs/tags/v*`.
      - Calls `slsa-verifier verify-artifact` for SLSA-spec compliance.
      - Cross-checks `revoked_keys.json` for revocation.
      - Cross-checks RFC 3161 timestamp if present.
      - Returns structured exit codes so it composes into CI.

### Trust policy

- [ ] Ship a `trust_policy.json` signed by the root identity, enumerating
      acceptable workflow identities. `mkpe verify-release` honours it as
      the canonical allowlist.

**Exit criteria:**

- `slsa-verifier verify-artifact --source-uri github.com/VyreVault/mkpe ...`
  passes against a fresh release.
- `mkpe verify-release` on the same release also passes, and fails closed
  when fed a tampered binary, a backdated artifact, or an artifact signed
  by a different workflow.
- A public audit-friendly page at `vyrevault.studio/mkpe/verify` documents
  how a third party reproduces the verification with only public tools.

---

## Phase 4 -- Beyond L3 (optional, not on critical path)

These are the things that turn "SLSA L3 compliant" into "people quote us in
their threat models."

- [ ] RFC 3161 trusted timestamp on the cosign bundle. Survives Sigstore
      cert chain rotations and is admissible in jurisdictions that recognize
      qualified TSAs.
- [ ] GUAC ingestion: feed our provenance and SBOMs into a GUAC instance so
      anyone -- including us -- can run graph queries against the supply chain.
- [ ] Reproducible builds bit-identical across two independent runners, with
      a public diff-this-yourself instruction page.
- [ ] Self-hosted fallback builder (path C from the trade-off matrix) running
      in parallel to GitHub Actions, signing the same artifacts with a
      different identity. Verifier accepts either; consumers can choose which
      to trust.
- [ ] Public transparency: a quarterly supply-chain report enumerating every
      dep, every audit decision, every key event.

---

## Open Decisions

These belong to the operator, not the agent:

1. **Builder path** (A / B / C from the matrix above). Default recommendation: A.
2. **OS coverage** at GA: Windows + Linux for sure. macOS adds value but also
   adds notarization complexity -- worth treating as Phase 2+1.
3. **License**: `core` is currently marked `Proprietary`. If we want
   third-party `cargo-vet` audits to be useful for our deps, we need to
   decide whether MKPE-the-engine is proprietary, dual-licensed, or
   source-available. Doesn't block SLSA, but affects the disclosure story.
4. **Root identity custodians**: 3 named humans, each with a FIDO2 token,
   each with a documented succession plan.

---

## Anti-Goals (things we are explicitly not doing)

- **Re-implementing transparency-log verification in pure Rust.** We call
  `cosign` / `slsa-verifier`. Reinventing this is a footgun.
- **Embedding signing keys in the binary.** Even with obfuscation. Anyone who
  proposes this is wrong, and the right answer is always Sigstore.
- **Coupling release attestation to a hardware machine ID.** Release identity
  is the workflow identity. Hardware fingerprints belong to content keys.
- **Self-attesting build provenance after Phase 1.** If we are the only signer
  of our own provenance, we are L1 at best, regardless of what the JSON says.
