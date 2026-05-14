# MKPE Schemas

This directory holds the **stable, public** schemas for every MKPE attestation
format. Anything that ships outside the repository -- to a customer, to a
verifier, to a court -- must match a schema in this directory.

## Schemas

### `provenance_v1.schema.json`

Build-time attestation. Wraps an [in-toto Statement v1] envelope around a
[SLSA Provenance v1.0] predicate, with MKPE-specific extensions under
`buildDefinition.internalParameters` and `runDetails.byproducts`.

This is the artifact produced by the GitHub Actions release workflow once
Phase 2 lands. Until then, the existing `build_attestation.json` at the repo
root is **transitional only** and will be replaced by output conforming to
this schema.

A worked, fully-populated example lives at
[`provenance_v1.example.json`](./provenance_v1.example.json). All hashes in
the example are placeholders (long runs of `0`-`f` characters); a real
attestation has real digests.

[in-toto Statement v1]: https://in-toto.io/Statement/v1.0
[SLSA Provenance v1.0]: https://slsa.dev/spec/v1.0/provenance

## Compatibility Policy

- Schemas are **append-only**. Adding optional fields is allowed at any time.
- Removing or renaming a field is a breaking change and requires a new
  `_v2` schema file alongside the existing one. The verifier must keep
  reading `_v1` attestations indefinitely.
- The `predicateType` URI is the version selector. Verifiers reject any
  predicate type they do not recognize.

## Validating an Attestation Locally

```powershell
# Install once
cargo install --locked jsonschema-cli

# Validate a real attestation against the schema
jsonschema-cli validate `
    --schema schemas/provenance_v1.schema.json `
    --instance path/to/attestation.intoto.json
```

In CI, the same validation runs against every release artifact before signing.
A non-conforming attestation is a P0 incident -- it means the generator
disagrees with the verifier on what we are even claiming.
