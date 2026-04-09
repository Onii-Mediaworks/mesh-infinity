#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

OS=""
PROFILE="release"
UNSIGNED="1"
CLEAN="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --os)
      OS="${2:-}"
      shift 2
      ;;
    --profile)
      PROFILE="${2:-}"
      shift 2
      ;;
    --unsigned)
      UNSIGNED="1"
      shift
      ;;
    --signed)
      UNSIGNED="0"
      shift
      ;;
    --clean)
      CLEAN="1"
      shift
      ;;
    -h|--help)
      exec make -C "$ROOT_DIR" help
      ;;
    *)
      echo "ERROR: unknown argument '$1'"
      exec make -C "$ROOT_DIR" help
      ;;
  esac
done

if [[ "$CLEAN" == "1" ]]; then
  make -C "$ROOT_DIR" clean
fi

if [[ -z "$OS" ]]; then
  exec make -C "$ROOT_DIR" help
fi

exec make -C "$ROOT_DIR" build OS="$OS" PROFILE="$PROFILE" UNSIGNED="$UNSIGNED"
