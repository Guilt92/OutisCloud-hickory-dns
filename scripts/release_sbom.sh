#!/usr/bin/env bash
# Generate CycloneDX SBOMs for the Rust workspace and the UI, for release assets.
# Requires cargo-cyclonedx (cargo install cargo-cyclonedx) and npm >= 9.
set -euo pipefail
OUT=${1:-dist/sbom}; mkdir -p "$OUT"
if command -v cargo-cyclonedx >/dev/null 2>&1 || cargo cyclonedx --version >/dev/null 2>&1; then
  cargo cyclonedx --format json --output-pattern 'sbom-{package}' --output-dir "$OUT"
else
  echo "cargo-cyclonedx is not installed; run: cargo install cargo-cyclonedx" >&2
  exit 1
fi
if [ -f web/ui/package.json ]; then
  ( cd web/ui && npm sbom --sbom-format cyclonedx > "../$OUT/ui.cdx.json" )
fi
echo "SBOMs written to $OUT"
