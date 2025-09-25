#!/usr/bin/env bash
set -euo pipefail

# Sweep TEST_PPS values and run: make run-linear-test TEST_PPS=<value>
# Usage:
#   utils/run_linear_sweep.sh [PPS1 PPS2 ...]
# Example:
#   utils/run_linear_sweep.sh 100 200 300 400 500

# Cache sudo credentials (Makefile runs Mininet via sudo)
#if command -v sudo >/dev/null 2>&1; then
#  sudo -v || true
#fi

# Move to repo root (this script lives in utils/)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Values to test
if [ "$#" -gt 0 ]; then
  PPS_LIST=("$@")
else
  PPS_LIST=(100 200 300 400 500)
fi

# Ensure Mininet is cleaned up on exit
trap 'make stop >/dev/null 2>&1 || true' EXIT

for pps in "${PPS_LIST[@]}"; do
  echo "===================================================="
  echo "Running run-linear-test with TEST_PPS=${pps}"
  echo "===================================================="

  # Start from a clean state (removes logs/ and pcaps/)
  make clean || true

  # Run experiment; target also generates results and archives
  make run-linear-test TEST_PPS="${pps}"
done

echo "All runs completed: ${PPS_LIST[*]}"
