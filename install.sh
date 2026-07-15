#!/usr/bin/env bash
set -euo pipefail
# One-line installer for sbom-diff
# Usage: curl -fsSL https://raw.githubusercontent.com/fabiocicerchia/sbom-diff/main/install.sh | bash

if command -v pipx &>/dev/null; then
  pipx install git+https://github.com/fabiocicerchia/sbom-diff
else
  pip install --user git+https://github.com/fabiocicerchia/sbom-diff
fi
echo "sbom-diff installed. Run: sbom-diff --help"
