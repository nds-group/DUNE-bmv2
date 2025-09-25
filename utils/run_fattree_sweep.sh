#!/usr/bin/env bash
set -euo pipefail

# Sweep through values combinations (cartesian product) and run: make run-test OPTION_1=<value_1> OPTION_2=<value_1> ... 

usage() {
  echo "Usage:"
  echo "  utils/run_fattree_sweep.sh --pods <pod1> [<pod2> ...] --spines <spine1> [<spine2> ...] --leafs <leaf1> [<leaf2> ...] --superspines <superspine1> [<superspine2> ...] --hosts-per-leaf <host1> [<host2> ...] --test-pps <pps1> [<pps2> ...]"
  echo "Example:"
  echo "  utils/run_fattree_sweep.sh --pods 4 8 --spines 2 4 --leafs 2 4 --superspines 1 2 --hosts-per-leaf 2 4 --test-pps 100 200"
}

# Move to repo root (this script lives in utils/)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PODS_LIST=()
LEAFS_LIST=()
SPINES_LIST=()
SUPERSPINES_LIST=()
HOSTS_PER_LEAF_LIST=()
TEST_PPS_LIST=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --superspines)
      shift
      [[ $# -gt 0 ]] || { echo "Error: --superspines needs at least one value"; usage; exit 1; }
      while [[ $# -gt 0 && "$1" != --* ]]; do SUPERSPINES_LIST+=("$1"); shift; done
      ;;
    --spines)
      shift
      [[ $# -gt 0 ]] || { echo "Error: --spines needs at least one value"; usage; exit 1; }
      while [[ $# -gt 0 && "$1" != --* ]]; do SPINES_LIST+=("$1"); shift; done
      ;;
    --leafs)
      shift
      [[ $# -gt 0 ]] || { echo "Error: --leafs needs at least one value"; usage; exit 1; }
      while [[ $# -gt 0 && "$1" != --* ]]; do LEAFS_LIST+=("$1"); shift; done
      ;;
    --pods)
      shift
      [[ $# -gt 0 ]] || { echo "Error: --pods needs at least one value"; usage; exit 1; }
      while [[ $# -gt 0 && "$1" != --* ]]; do PODS_LIST+=("$1"); shift; done
      ;;
    --hosts-per-leaf)
      shift
      [[ $# -gt 0 ]] || { echo "Error: --hosts-per-leaf needs at least one value"; usage; exit 1; }
      while [[ $# -gt 0 && "$1" != --* ]]; do HOSTS_PER_LEAF_LIST+=("$1"); shift; done
      ;;
    --test-pps)
      shift
      [[ $# -gt 0 ]] || { echo "Error: --test-pps needs at least one value"; usage; exit 1; }
      while [[ $# -gt 0 && "$1" != --* ]]; do TEST_PPS_LIST+=("$1"); shift; done
      ;;
    --) shift; break ;;
    *) echo "Unknown flag: $1"; usage; exit 1 ;;
  esac
done

cartesian_product() {
  local prefix="$1"
  shift
  local -n arr="$1"
  shift
  for item in "${arr[@]}"; do
    if [ $# -eq 0 ]; then
      printf '%s%s\n' "$prefix" "$item"
    else
      cartesian_product "${prefix}${item} " "$@"
    fi
  done
}

# Ensure Mininet (or similar) is cleaned up on exit
trap 'make stop >/dev/null 2>&1 || true' EXIT

while IFS= read -r tuple; do
  IFS=' ' read -r -a elems <<< "$tuple"

  echo "===================================================="
    echo "Running: make run-test PODS=${elems[0]} SPINES=${elems[1]} LEAFS=${elems[2]} SUPER_SPINES=${elems[3]} HOSTS_PER_LEAF=${elems[4]} TEST_PPS=${elems[5]}"
  echo "===================================================="
    make clean || true
  make run-test PODS="${elems[0]}" SPINES="${elems[1]}" LEAFS="${elems[2]}" SUPER_SPINES="${elems[3]}" HOSTS_PER_LEAF="${elems[4]}" TEST_PPS="${elems[5]}"
done < <(cartesian_product "" PODS_LIST SPINES_LIST LEAFS_LIST SUPERSPINES_LIST HOSTS_PER_LEAF_LIST TEST_PPS_LIST)


echo "All runs completed:"
echo "  PODS: ${PODS_LIST[*]}"
echo "  SPINES: ${SPINES_LIST[*]}"
echo "  LEAFS: ${LEAFS_LIST[*]}"
echo "  SUPERSPINES: ${SUPERSPINES_LIST[*]}"
echo "  HOSTS_PER_LEAF: ${HOSTS_PER_LEAF_LIST[*]}"
echo "  TEST_PPS: ${TEST_PPS_LIST[*]}"
