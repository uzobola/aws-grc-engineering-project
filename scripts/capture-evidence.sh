#!/usr/bin/env bash

set -euo pipefail

PROFILE_ARG=""
WORKSPACE=""
RUN_ID=""
VAULT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace)
      WORKSPACE="$2"
      shift 2
      ;;
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --vault)
      VAULT="$2"
      shift 2
      ;;
    --profile)
      PROFILE_ARG="--profile $2"
      shift 2
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$WORKSPACE" || -z "$RUN_ID" || -z "$VAULT" ]]; then
  echo "Usage: $0 --workspace <path> --run-id <id> --vault <bucket> [--profile <profile>]" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if command -v sha256sum >/dev/null 2>&1; then
  SHASUM="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHASUM="shasum -a 256"
else
  echo "Need sha256sum or shasum on PATH" >&2
  exit 2
fi

CAPTURED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BUNDLE_DIR="$WORK/bundle-$RUN_ID"

mkdir -p "$BUNDLE_DIR"

if [[ -f "$WORKSPACE/evidence-collector/output/evidence-results.json" ]]; then
  cp "$WORKSPACE/evidence-collector/output/evidence-results.json" "$BUNDLE_DIR/evidence-results.json"
fi

if [[ -f "$WORKSPACE/evidence-collector/output/evidence-results.csv" ]]; then
  cp "$WORKSPACE/evidence-collector/output/evidence-results.csv" "$BUNDLE_DIR/evidence-results.csv"
fi

if [[ -f "$WORKSPACE/risk-scoring/output/risk-summary.json" ]]; then
  cp "$WORKSPACE/risk-scoring/output/risk-summary.json" "$BUNDLE_DIR/risk-summary.json"
fi

if [[ -d "$WORKSPACE/terraform/primitives/compliant-s3" ]]; then
  find "$WORKSPACE/terraform/primitives/compliant-s3" \
    -maxdepth 1 \
    -type f \
    \( -name "*.tf" -o -name "README.md" \) \
    -exec cp {} "$BUNDLE_DIR/" \;
fi

git -C "$WORKSPACE" log -1 --pretty=full > "$BUNDLE_DIR/commit.txt" 2>/dev/null \
  || echo "no git commit available" > "$BUNDLE_DIR/commit.txt"

python --version > "$BUNDLE_DIR/python-version.txt" 2>/dev/null || true

if command -v terraform >/dev/null 2>&1; then
  terraform version > "$BUNDLE_DIR/terraform-version.txt" 2>/dev/null || true
fi

FILE_COUNT=$(find "$BUNDLE_DIR" -type f | wc -l | tr -d ' ')

if [[ "$FILE_COUNT" -eq 0 ]]; then
  echo "No evidence files found to capture." >&2
  exit 1
fi

{
  echo "["
  FIRST=1

  for file in "$BUNDLE_DIR"/*; do
    base="$(basename "$file")"

    if [[ "$base" == "manifest.json" ]]; then
      continue
    fi

    HASH="$($SHASUM "$file" | awk '{print $1}')"
    SIZE="$(wc -c < "$file" | tr -d ' ')"

    if [[ "$FIRST" -eq 1 ]]; then
      FIRST=0
    else
      printf ","
    fi

    printf '\n  {"filename":"%s","sha256":"%s","size":%s,"captured_at_utc":"%s"}' \
      "$base" "$HASH" "$SIZE" "$CAPTURED_AT"
  done

  echo
  echo "]"
} > "$BUNDLE_DIR/manifest.json"

BUNDLE_TGZ="/tmp/aws-grc-evidence-$RUN_ID.tar.gz"

tar -czf "$BUNDLE_TGZ" -C "$WORK" "bundle-$RUN_ID"

KEY="runs/$RUN_ID/bundle.tar.gz"

UPLOAD_OUT=$(aws $PROFILE_ARG s3api put-object \
  --bucket "$VAULT" \
  --key "$KEY" \
  --body "$BUNDLE_TGZ" \
  --output json)

VERSION_ID=$(echo "$UPLOAD_OUT" | awk -F'"' '/"VersionId"/{print $4}')

printf '{"run_id":"%s","vault":"%s","key":"%s","version_id":"%s","captured_at_utc":"%s"}\n' \
  "$RUN_ID" "$VAULT" "$KEY" "$VERSION_ID" "$CAPTURED_AT"