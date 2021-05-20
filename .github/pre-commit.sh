#!/usr/bin/env bash
set -euo pipefail
cd $(git rev-parse --show-toplevel)
./.github/make-workflows.sh
git add .github/workflows
