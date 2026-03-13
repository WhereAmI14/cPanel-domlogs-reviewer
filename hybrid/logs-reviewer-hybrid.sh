#!/usr/bin/env bash

if [ -z "${BASH_VERSION:-}" ]; then
  echo "This script must be run with bash." >&2
  exit 1
fi

set -euo pipefail

DEFAULT_BASE_URL="https://raw.githubusercontent.com/WhereAmI14/cPanel-domlogs-reviewer/dev/hybrid"
BASE_URL="${HYBRID_BASE_URL:-$DEFAULT_BASE_URL}"
KEEP_TEMP=0
declare -a FORWARD_ARGS=()

usage() {
  cat <<'EOF'
Usage:
  Local repo execution:
    bash hybrid/logs-reviewer-hybrid.sh [runner options]

  Remote bootstrap execution:
    curl -fsSL https://raw.githubusercontent.com/WhereAmI14/cPanel-domlogs-reviewer/dev/hybrid/logs-reviewer-hybrid.sh | bash

Bootstrap options:
  --base-url URL   Override the download base URL for runner.sh and log_enrich.py
  --keep-temp      Keep the temporary working directory for inspection
  -h, --help       Show this help

Runner options are forwarded to runner.sh unchanged.
Use `--` if you need to pass `-h` through to the runner.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --)
      shift
      FORWARD_ARGS+=("$@")
      break
      ;;
    --base-url)
      [[ $# -lt 2 ]] && { echo "Missing value for $1" >&2; exit 2; }
      BASE_URL="$2"
      shift 2
      ;;
    --keep-temp)
      KEEP_TEMP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      FORWARD_ARGS+=("$1")
      shift
      ;;
  esac
done

TMPDIR="$(mktemp -d)"
cleanup() {
  if [[ "$KEEP_TEMP" -eq 1 ]]; then
    echo "Hybrid temp dir kept at: $TMPDIR" >&2
  else
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

download_file() {
  local url="$1"
  local out="$2"
  curl -fsSL "$url" -o "$out"
}

run_local_bundle() {
  local script_path script_dir
  script_path="${BASH_SOURCE[0]:-}"
  [[ -n "$script_path" && -f "$script_path" ]] || return 1

  script_dir="$(cd "$(dirname "$script_path")" && pwd)"
  [[ -f "$script_dir/runner.sh" && -f "$script_dir/log_enrich.py" ]] || return 1

  cp "$script_dir/runner.sh" "$TMPDIR/runner.sh"
  cp "$script_dir/log_enrich.py" "$TMPDIR/log_enrich.py"
  cp "$script_dir/README.md" "$TMPDIR/README.md" 2>/dev/null || true
  chmod +x "$TMPDIR/runner.sh"
  exec bash "$TMPDIR/runner.sh" "${FORWARD_ARGS[@]}"
}

if run_local_bundle; then
  exit 0
fi

download_file "$BASE_URL/runner.sh" "$TMPDIR/runner.sh"
download_file "$BASE_URL/log_enrich.py" "$TMPDIR/log_enrich.py"
chmod +x "$TMPDIR/runner.sh"

exec bash "$TMPDIR/runner.sh" "${FORWARD_ARGS[@]}"
