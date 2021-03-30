#!/usr/bin/env bash
set -euo pipefail

cd $(dirname $(realpath ${BASH_SOURCE[0]}))
prometheus --config.file=prometheus.yml
