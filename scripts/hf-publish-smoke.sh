#!/bin/sh
set -eu

if ! command -v hf >/dev/null 2>&1; then
  echo "SKIPPED: Hugging Face CLI is unavailable; authenticated publication was not attempted"
  exit 0
fi
if ! hf auth whoami >/dev/null 2>&1; then
  echo "SKIPPED: Hugging Face credentials are unavailable; authenticated publication was not attempted"
  exit 0
fi
echo "Authenticated Hugging Face publication requires an explicit archive batch input."
echo "Run: go run ./cmd/health-archive -input RECEIPTS.jsonl -output archive -publish"
