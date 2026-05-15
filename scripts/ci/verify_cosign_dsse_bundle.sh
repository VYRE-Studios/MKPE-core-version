#!/usr/bin/env bash
# Recompute DSSE PAE for an MKPE *.intoto.jsonl envelope and verify the
# embedded Sigstore bundle with the cosign CLI (same bytes mkpe uses).
# Usage: verify_cosign_dsse_bundle.sh <bundle-directory>
# Expects: <dir>/mkpe.exe.intoto.jsonl, <dir>/build_context.json
set -euo pipefail

ROOT="${1:?usage: verify_cosign_dsse_bundle.sh <bundle-directory>}"
ENV_FILE="$ROOT/mkpe.exe.intoto.jsonl"
BUILD_CTX="$ROOT/build_context.json"
SIGSTORE_BUNDLE="$ROOT/sigstore-bundle.ci.json"
PAE_FILE="$ROOT/dsse-pae.ci.bin"

if ! command -v cosign >/dev/null 2>&1; then
  echo "error: cosign is not on PATH" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is not on PATH" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is not on PATH" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "error: missing $ENV_FILE" >&2
  exit 1
fi
if [[ ! -f "$BUILD_CTX" ]]; then
  echo "error: missing $BUILD_CTX" >&2
  exit 1
fi

BUILDER_ID="$(jq -r .builder_id "$BUILD_CTX")"
if [[ -z "$BUILDER_ID" || "$BUILDER_ID" == "null" ]]; then
  echo "error: could not read builder_id from $BUILD_CTX" >&2
  exit 1
fi

jq -e '.signatures[0].sigstore_bundle' "$ENV_FILE" >"$SIGSTORE_BUNDLE"

python3 - "$ENV_FILE" "$PAE_FILE" <<'PY'
import base64
import json
import pathlib
import sys


def dsse_pae(payload_type: bytes, payload: bytes) -> bytes:
    return (
        b"DSSEv1 "
        + str(len(payload_type)).encode("ascii")
        + b" "
        + payload_type
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


src = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
env = json.loads(src.read_text(encoding="utf-8"))
pt = env["payloadType"].encode("utf-8")
payload = base64.standard_b64decode(env["payload"])
out.write_bytes(dsse_pae(pt, payload))
PY

cosign verify-blob \
  --bundle "$SIGSTORE_BUNDLE" \
  --certificate-identity "$BUILDER_ID" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$PAE_FILE"

echo "ok: cosign verify-blob succeeded for DSSE PAE"
