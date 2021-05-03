#!/usr/bin/env bash
set -euo pipefail

gitroot=$(git rev-parse --show-toplevel)

cd $gitroot
./.github/make-workflows.sh
git add .github/workflows
