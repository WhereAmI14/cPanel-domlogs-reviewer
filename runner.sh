#!/usr/bin/env bash

if [ -z "${BASH_VERSION:-}" ]; then
  echo "This script must be run with bash." >&2
  exit 1
fi

set -euo pipefail
export LC_ALL=C

RED=$'\033[31;1m'
CYAN=$'\033[36;1m'
GREEN=$'\033[32;1m'
YELLOW=$'\033[33;1m'
BLUE=$'\033[34;1m'
DEF=$'\033[0m'

ME=$(whoami)
USE_TIME=false
M=0
CUTOFF_EPOCH=0
REQUESTED_LOOKBACK_SECS=0
ACTIVE_OLDEST_EPOCH=0
COMBINED_OLDEST_EPOCH=0
MAIN_INCLUDE_ARCHIVES=0
TIMEFRAME_INPUT=""
TIMEFRAME_DISPLAY=""
RUN_GLOBAL_INPUT=""
RUN_INSPECT_INPUT=""
RUN_ARCHIVE_INPUT=""
DOMAIN_INPUT=""
ARCHIVE_DATE_INPUT=""
ARCHIVE_DOMAIN_INPUT=""
LOG_USER_INPUT=""
FULL_DOMAIN_INPUT=""
MAX_DOMAINS_INLINE=20
TOP_DOMAIN_ROWS=10

declare -a BASE_LOGS=()
declare -a ARCHIVE_LOGS=()
declare -a ARCHIVE_PERIODS=()
cleanup_files=()

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_HELPER="$SCRIPT_DIR/log_enrich.py"

usage() {
  cat <<'EOF'
Usage: runner.sh [options]

Options:
  -t, --timeframe VALUE    Time window (examples: "5 minutes", "24 hours", "all")
  -g, --global y|n         Run global insights
  -i, --inspect y|n        Inspect raw entries for a single domain
  -a, --archive y|n        Review archived rotated logs from ~/logs
      --threshold N        Inline-domain threshold before compact mode (default: 20)
      --full-domain NAME   Print the full summary for one domain even in compact mode
      --archive-date DATE  Archive date token to inspect (example: Feb-2026)
      --archive-domain N   Domain log name for archive inspect
  -d, --domain NAME        Domain log name for inspect mode
  -u, --user USER          Username to read logs from /home/USER/access-logs or /home/USER/access_logs
  -h, --help               Show this help

Notes:
  - Bash orchestrator for the root-level tool bundle.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--timeframe)
      [[ $# -lt 2 ]] && { echo "Missing value for $1" >&2; exit 2; }
      TIMEFRAME_INPUT="$2"
      shift 2
      ;;
    -g|--global)
      [[ $# -lt 2 ]] && { echo "Missing value for $1" >&2; exit 2; }
      RUN_GLOBAL_INPUT="$2"
      shift 2
      ;;
    -i|--inspect)
      [[ $# -lt 2 ]] && { echo "Missing value for $1" >&2; exit 2; }
      RUN_INSPECT_INPUT="$2"
      shift 2
      ;;
    -a|--archive)
      [[ $# -lt 2 ]] && { echo "Missing value for $1" >&2; exit 2; }
      RUN_ARCHIVE_INPUT="$2"
      shift 2
      ;;
    --threshold|--threshhold)
      [[ $# -lt 2 ]] && { echo "Missing value for $1" >&2; exit 2; }
      [[ "$2" =~ ^[0-9]+$ ]] || { echo "Invalid value for $1: $2" >&2; exit 2; }
      MAX_DOMAINS_INLINE="$2"
      shift 2
      ;;
    --full-domain)
      [[ $# -lt 2 ]] && { echo "Missing value for $1" >&2; exit 2; }
      FULL_DOMAIN_INPUT="$2"
      shift 2
      ;;
    --archive-date)
      [[ $# -lt 2 ]] && { echo "Missing value for $1" >&2; exit 2; }
      ARCHIVE_DATE_INPUT="$2"
      shift 2
      ;;
    --archive-domain)
      [[ $# -lt 2 ]] && { echo "Missing value for $1" >&2; exit 2; }
      ARCHIVE_DOMAIN_INPUT="$2"
      shift 2
      ;;
    -d|--domain)
      [[ $# -lt 2 ]] && { echo "Missing value for $1" >&2; exit 2; }
      DOMAIN_INPUT="$2"
      shift 2
      ;;
    -u|--user)
      [[ $# -lt 2 ]] && { echo "Missing value for $1" >&2; exit 2; }
      LOG_USER_INPUT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

cleanup() {
  local f
  for f in "${cleanup_files[@]:-}"; do
    [[ -n "$f" && -f "$f" ]] && rm -f "$f"
  done
}
trap cleanup EXIT

read_tty() {
  local prompt="$1"
  local out
  if ! { exec 3</dev/tty; } 2>/dev/null; then
    return 1
  fi
  if ! read -ru 3 -rp "$prompt" out; then
    exec 3<&-
    return 1
  fi
  exec 3<&-
  printf '%s' "$out"
}

normalize_yn() {
  local v="${1,,}"
  case "$v" in
    y|yes) printf 'y' ;;
    n|no) printf 'n' ;;
    *) return 1 ;;
  esac
}

can_read_tty() {
  if { exec 3</dev/tty; } 2>/dev/null; then
    exec 3<&-
    return 0
  fi
  return 1
}

prompt_yes_no() {
  local prompt="$1"
  local preset="$2"
  local v

  if [[ -n "$preset" ]]; then
    normalize_yn "$preset" || { echo "Invalid value: $preset (expected y/n)" >&2; exit 2; }
    return 0
  fi

  while true; do
    v=$(read_tty "$prompt") || {
      echo "Non-interactive mode requires explicit options" >&2
      exit 2
    }
    if normalize_yn "$v"; then
      return 0
    fi
    echo "Invalid"
  done
}

parse_timeframe_value() {
  local tf="$1" n unit
  if [[ "$tf" == "all" ]]; then
    USE_TIME=false
    REQUESTED_LOOKBACK_SECS=0
    return 0
  fi

  if [[ "$tf" =~ ^[[:space:]]*([0-9]+)[[:space:]]*([a-zA-Z]+)[[:space:]]*$ ]]; then
    n="${BASH_REMATCH[1]}"
    unit="${BASH_REMATCH[2],,}"

    case "$unit" in
      minute|minutes) M="$n" ;;
      hour|hours) M=$((n * 60)) ;;
      day|days) M=$((n * 1440)) ;;
      *) return 1 ;;
    esac

    USE_TIME=true
    CUTOFF_EPOCH=$(( $(date +%s) - (M * 60) ))
    REQUESTED_LOOKBACK_SECS=$((M * 60))
    return 0
  fi
  return 1
}

parse_timeframe() {
  local tf
  if [[ -n "$TIMEFRAME_INPUT" ]]; then
    parse_timeframe_value "$TIMEFRAME_INPUT" || {
      echo "Invalid --timeframe value: $TIMEFRAME_INPUT" >&2
      exit 2
    }
    TIMEFRAME_DISPLAY="$TIMEFRAME_INPUT"
    return
  fi

  while true; do
    tf=$(read_tty $'\e[36mCheck logs for (5 minutes, 5 hours, 24 hours, all):\e[0m ') || {
      echo "Non-interactive mode requires --timeframe" >&2
      exit 2
    }
    if parse_timeframe_value "$tf"; then
      TIMEFRAME_DISPLAY="$tf"
      return
    fi
    echo "Invalid"
  done
}

ensure_python_helper() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is not available; log enrichment cannot run." >&2
    exit 1
  fi

  if [[ ! -f "$PY_HELPER" ]]; then
    echo "Missing Python helper: $PY_HELPER" >&2
    exit 1
  fi
}

collect_base_logs() {
  local f tmpf scope_user

  if [[ "$ME" == "root" ]]; then
    scope_user="${LOG_USER_INPUT:-}"
    if [[ -z "$scope_user" ]]; then
      scope_user=$(read_tty $'\e[36mAs root, enter cPanel username to scan (blank for all users):\e[0m ') || true
      scope_user="${scope_user//[[:space:]]/}"
    fi
  else
    scope_user="${LOG_USER_INPUT:-$ME}"
  fi

  tmpf=$(mktemp)
  cleanup_files+=("$tmpf")
  python3 "$PY_HELPER" \
    --mode discover-base \
    --caller-user "$ME" \
    --log-user "$scope_user" > "$tmpf"

  BASE_LOGS=()
  while IFS= read -r f; do
    [[ -n "$f" ]] && BASE_LOGS+=("$f")
  done < "$tmpf"

  [[ ${#BASE_LOGS[@]} -gt 0 ]]
}

stream_base_log() {
  local base="$1"

  if [[ -f "$base" ]]; then
    if [[ -r "$base" ]]; then
      cat -- "$base" || true
    else
      echo "WARN: cannot read $base (permission denied?)" >&2
    fi
  fi

  if [[ -f "$base-ssl_log" ]]; then
    if [[ -r "$base-ssl_log" ]]; then
      cat -- "$base-ssl_log" || true
    else
      echo "WARN: cannot read $base-ssl_log (permission denied?)" >&2
    fi
  fi
}

stream_archived_files() {
  local -a targets=("$@")
  [[ ${#targets[@]} -gt 0 ]] || return 0
  gzip -cd -- "${targets[@]}" || true
}

collect_archived_logs() {
  local kind value tmpf

  ARCHIVE_LOGS=()
  ARCHIVE_PERIODS=()

  if [[ ${#BASE_LOGS[@]} -eq 0 ]]; then
    return 0
  fi

  tmpf=$(mktemp)
  cleanup_files+=("$tmpf")
  printf '%s\n' "${BASE_LOGS[@]}" | python3 "$PY_HELPER" --mode discover-archives > "$tmpf"

  while IFS=$'\t' read -r kind value; do
    case "$kind" in
      LOG) ARCHIVE_LOGS+=("$value") ;;
      PERIOD) ARCHIVE_PERIODS+=("$value") ;;
    esac
  done < "$tmpf"
}

stream_archived_base_log() {
  local base="$1"
  local base_name f tmpf
  local -a targets=()
  base_name=$(basename "$base")

  tmpf=$(mktemp)
  cleanup_files+=("$tmpf")
  printf '%s\n' "${ARCHIVE_LOGS[@]}" | python3 "$PY_HELPER" \
    --mode match-base-archives \
    --base-name "$base_name" > "$tmpf"

  while IFS= read -r f; do
    [[ -n "$f" ]] && targets+=("$f")
  done < "$tmpf"

  stream_archived_files "${targets[@]}"
}

stream_selected_base_log() {
  local base="$1"
  stream_base_log "$base"
  if [[ "$MAIN_INCLUDE_ARCHIVES" -eq 1 ]]; then
    stream_archived_base_log "$base"
  fi
}

find_base_log() {
  local requested="$1"
  local base_input base

  base_input="${requested//[[:space:]]/}"
  base_input="${base_input%-ssl_log}"
  [[ -n "$base_input" ]] || return 1

  for base in "${BASE_LOGS[@]}"; do
    if [[ "$(basename "$base")" == "$base_input" ]]; then
      printf '%s\n' "$base"
      return 0
    fi
  done

  return 1
}

print_selected_domain_summary() {
  local requested="$1"
  local selected_base status

  selected_base=$(find_base_log "$requested") || {
    echo "No matching log found for: ${requested%-ssl_log}"
    return 0
  }

  echo "${CYAN}Full summary for requested domain:${DEF} $(basename "$selected_base")"
  echo
  if stream_selected_base_log "$selected_base" | print_python_summary_from_stream "Domain: $(basename "$selected_base")" --quiet-empty; then
    echo
    return 0
  fi

  status=$?
  if [[ "$status" -ne 3 ]]; then
    return "$status"
  fi

  echo "No log entries found for: $(basename "$selected_base")"
  echo
}

oldest_epoch_from_stream() {
  python3 "$PY_HELPER" --mode oldest-epoch
}

seconds_to_human_duration() {
  local s="$1"
  local d h m
  if [[ "$s" -lt 60 ]]; then
    printf '%ss' "$s"
    return 0
  fi
  d=$((s / 86400))
  h=$(((s % 86400) / 3600))
  m=$(((s % 3600) / 60))
  if [[ "$d" -gt 0 ]]; then
    printf '%sd %sh' "$d" "$h"
  elif [[ "$h" -gt 0 ]]; then
    printf '%sh %sm' "$h" "$m"
  else
    printf '%sm' "$m"
  fi
}

print_python_summary_from_stream() {
  local heading="$1"
  shift
  python3 "$PY_HELPER" \
    --mode summary \
    --heading "$heading" \
    --cutoff-epoch "$CUTOFF_EPOCH" \
    "$@"
}

print_filtered_raw_from_stream() {
  python3 "$PY_HELPER" \
    --mode filter-raw \
    --cutoff-epoch "$CUTOFF_EPOCH"
}

print_domain_rollup_from_file() {
  local metrics_file="$1"
  python3 "$PY_HELPER" \
    --mode domain-rollup \
    --input-file "$metrics_file" \
    --top-n "$TOP_DOMAIN_ROWS"
}

build_domain_metrics() {
  local metrics_file="$1"
  local report_file="${2:-}"
  local base domain filtered_tmp status

  : > "$metrics_file"
  if [[ -n "$report_file" ]]; then
    : > "$report_file"
  fi

  for base in "${BASE_LOGS[@]}"; do
    domain=$(basename "$base")
    filtered_tmp=$(mktemp)
    cleanup_files+=("$filtered_tmp")

    stream_selected_base_log "$base" | print_filtered_raw_from_stream > "$filtered_tmp"
    [[ -s "$filtered_tmp" ]] || continue

    if python3 "$PY_HELPER" \
      --mode summary-metrics \
      --input-file "$filtered_tmp" \
      --cutoff-epoch 0 \
      --domain "$domain" >> "$metrics_file"; then
      :
    else
      status=$?
      if [[ "$status" -ne 3 ]]; then
        return "$status"
      fi
    fi

    if [[ -n "$report_file" ]]; then
      if python3 "$PY_HELPER" \
        --mode summary \
        --input-file "$filtered_tmp" \
        --cutoff-epoch 0 \
        --heading "Domain: $domain" \
        --quiet-empty >> "$report_file"; then
        printf '\n' >> "$report_file"
      else
        status=$?
        if [[ "$status" -ne 3 ]]; then
          return "$status"
        fi
      fi
    fi
  done
}

configure_main_data_sources() {
  local now active_span combined_span requested_span

  now=$(date +%s)
  ACTIVE_OLDEST_EPOCH=0
  COMBINED_OLDEST_EPOCH=0
  MAIN_INCLUDE_ARCHIVES=0

  ACTIVE_OLDEST_EPOCH=$(
    {
      for base in "${BASE_LOGS[@]}"; do
        stream_base_log "$base"
      done
    } | oldest_epoch_from_stream
  )

  if [[ "$ACTIVE_OLDEST_EPOCH" -gt 0 ]]; then
    active_span=$((now - ACTIVE_OLDEST_EPOCH))
    echo "${GREEN}Active log coverage:${DEF} $(seconds_to_human_duration "$active_span")"
  else
    echo "${GREEN}Active log coverage:${DEF} unavailable"
  fi

  if [[ "$USE_TIME" != true ]]; then
    echo "${BLUE}Source selection:${DEF} active logs only (timeframe: all)"
    return 0
  fi

  if [[ "$REQUESTED_LOOKBACK_SECS" -gt 0 ]]; then
    requested_span=$(seconds_to_human_duration "$REQUESTED_LOOKBACK_SECS")
    echo "${BLUE}Requested window:${DEF} $requested_span"
  fi

  if [[ "$ACTIVE_OLDEST_EPOCH" -gt 0 && "$CUTOFF_EPOCH" -ge "$ACTIVE_OLDEST_EPOCH" ]]; then
    echo "${BLUE}Source selection:${DEF} active logs only (requested window is covered)"
    return 0
  fi

  if [[ ${#ARCHIVE_LOGS[@]} -eq 0 ]]; then
    echo "${BLUE}Source selection:${DEF} active logs only ${YELLOW}(no archives found)${DEF}"
    return 0
  fi

  MAIN_INCLUDE_ARCHIVES=1
  echo "${BLUE}Source selection:${DEF} ${YELLOW}including rotated archives (requested window exceeds active coverage)${DEF}"

  COMBINED_OLDEST_EPOCH=$(
    {
      for base in "${BASE_LOGS[@]}"; do
        stream_selected_base_log "$base"
      done
    } | oldest_epoch_from_stream
  )

  if [[ "$COMBINED_OLDEST_EPOCH" -gt 0 ]]; then
    combined_span=$((now - COMBINED_OLDEST_EPOCH))
    echo "${BLUE}Active+archive coverage:${DEF} $(seconds_to_human_duration "$combined_span")"
    if [[ "$CUTOFF_EPOCH" -lt "$COMBINED_OLDEST_EPOCH" ]]; then
      echo "${YELLOW}Requested window exceeds available data; showing maximum available range.${DEF}"
    fi
  fi
}

review_archived_logs() {
  local run_archive date_choice raw_domain base_input show_raw archive_heading
  local kind value tmpf status
  local -a all_targets=()
  local -a available_domains=()
  local -a archive_targets=()
  local -a matched_files=()

  if [[ ${#ARCHIVE_LOGS[@]} -eq 0 ]]; then
    return 0
  fi

  if [[ ${#ARCHIVE_PERIODS[@]} -gt 0 ]]; then
    echo "${YELLOW}Archived rotated logs detected in ~/logs for:${DEF} ${ARCHIVE_PERIODS[*]}"
  else
    echo "${YELLOW}Archived rotated logs detected in ~/logs.${DEF}"
  fi

  if [[ -n "$RUN_ARCHIVE_INPUT" ]]; then
    run_archive=$(prompt_yes_no "" "$RUN_ARCHIVE_INPUT")
  else
    if ! can_read_tty; then
      echo "Skipping archive review (no tty). Use --archive y to enable in non-interactive mode."
      return 0
    fi
    run_archive=$(prompt_yes_no $'\e[36mReview archived rotated logs? (y/n):\e[0m ' "")
  fi

  if [[ "$run_archive" != "y" ]]; then
    return 0
  fi

  date_choice="${ARCHIVE_DATE_INPUT:-}"
  if [[ -z "$date_choice" && ${#ARCHIVE_PERIODS[@]} -eq 1 ]]; then
    date_choice="${ARCHIVE_PERIODS[0]}"
  fi

  tmpf=$(mktemp)
  cleanup_files+=("$tmpf")
  printf '%s\n' "${ARCHIVE_LOGS[@]}" | python3 "$PY_HELPER" \
    --mode archive-query \
    --date-choice "$date_choice" \
    --raw-domain "" > "$tmpf"

  available_domains=()
  all_targets=()
  archive_targets=()
  matched_files=()
  archive_heading=""
  base_input=""
  status=""
  while IFS=$'\t' read -r kind value; do
    case "$kind" in
      STATUS) status="$value" ;;
      AVAILABLE_DOMAIN) available_domains+=("$value") ;;
      HEADING) archive_heading="$value" ;;
      TARGET) all_targets+=("$value") ;;
    esac
  done < "$tmpf"

  if [[ "$status" == "NO_DATE_MATCH" ]]; then
    echo "No archived logs found for date: $date_choice"
    return 0
  fi

  if [[ ${#available_domains[@]} -gt 0 ]]; then
    echo
    if [[ -n "$date_choice" ]]; then
      echo "${GREEN}Available archived domains for $date_choice:${DEF}"
    else
      echo "${GREEN}Available archived domains:${DEF}"
    fi
    printf ' - %s\n' "${available_domains[@]}"
    echo
  fi

  if [[ -n "$ARCHIVE_DOMAIN_INPUT" ]]; then
    raw_domain="$ARCHIVE_DOMAIN_INPUT"
  else
    raw_domain=$(read_tty "Enter archived domain to analyze (blank for all): ") || true
  fi
  raw_domain="${raw_domain//[[:space:]]/}"

  if [[ -z "$raw_domain" ]]; then
    archive_targets=("${all_targets[@]}")
  else
    printf '%s\n' "${ARCHIVE_LOGS[@]}" | python3 "$PY_HELPER" \
      --mode archive-query \
      --date-choice "$date_choice" \
      --raw-domain "$raw_domain" > "$tmpf"

    status=""
    archive_targets=()
    matched_files=()
    archive_heading=""
    base_input=""
    while IFS=$'\t' read -r kind value; do
      case "$kind" in
        STATUS) status="$value" ;;
        HEADING) archive_heading="$value" ;;
        BASE_INPUT) base_input="$value" ;;
        MATCHED_FILE) matched_files+=("$value") ;;
        TARGET) archive_targets+=("$value") ;;
      esac
    done < "$tmpf"

    if [[ "$status" == "NO_DOMAIN_MATCH" ]]; then
      if [[ -n "$date_choice" ]]; then
        echo "No matching archived log found for domain: $base_input ($date_choice)"
      else
        echo "No matching archived log found for domain: $base_input"
      fi
      return 0
    fi

    if [[ ${#matched_files[@]} -gt 0 ]]; then
      echo
      echo "${GREEN}Archived files for $base_input (${#matched_files[@]} files)${DEF}"
      printf ' - %s\n' "${matched_files[@]}"
      echo
    fi
  fi

  stream_archived_files "${archive_targets[@]}" | print_python_summary_from_stream "$archive_heading"

  if ! can_read_tty; then
    return 0
  fi

  show_raw=$(prompt_yes_no $'\e[36mShow raw archived entries? (y/n):\e[0m ' "")
  if [[ "$show_raw" != "y" ]]; then
    return 0
  fi

  echo
  if [[ -n "$raw_domain" ]]; then
    if [[ -n "$date_choice" ]]; then
      echo "${CYAN}Showing archived raw access entries for: $base_input ($date_choice)${DEF}"
    else
      echo "${CYAN}Showing archived raw access entries for: $base_input (all dates)${DEF}"
    fi
  else
    if [[ -n "$date_choice" ]]; then
      echo "${CYAN}Showing archived raw access entries for: all domains ($date_choice)${DEF}"
    else
      echo "${CYAN}Showing archived raw access entries for: all domains (all dates)${DEF}"
    fi
  fi
  echo
  stream_archived_files "${archive_targets[@]}" | print_filtered_raw_from_stream
}

main() {
  local compact_mode=0
  local g inspect_prompt s
  local metrics_file report_file status

  parse_timeframe

  if [[ -n "$FULL_DOMAIN_INPUT" ]]; then
    RUN_INSPECT_INPUT="${RUN_INSPECT_INPUT:-n}"
    RUN_ARCHIVE_INPUT="${RUN_ARCHIVE_INPUT:-n}"
  fi

  echo "${GREEN}cPanel Access Log Reviewer${DEF}"
  echo "Purpose: Summarize per-domain Apache access logs, with archive support when the requested timeframe exceeds active-log coverage."
  echo

  ensure_python_helper

  if ! collect_base_logs; then
    echo "No logs found"
    exit 0
  fi

  collect_archived_logs
  configure_main_data_sources

  echo
  echo "${GREEN}Found ${#BASE_LOGS[@]} logs${DEF}"
  echo

  if [[ -z "$FULL_DOMAIN_INPUT" && ${#BASE_LOGS[@]} -gt "$MAX_DOMAINS_INLINE" ]]; then
    compact_mode=1
    report_file="/tmp/logs-reviewer-$(date +%Y-%m-%d-%H%M%S).txt"
    echo "${YELLOW}Compact mode will be used:${DEF} ${#BASE_LOGS[@]} logs exceeds inline threshold ${MAX_DOMAINS_INLINE}."
    echo "The terminal will show a domain-level summary, and the full per-domain report will be saved to:"
    echo "$report_file"
    echo "${YELLOW}To increase the inline limit, rerun with the threshold option:${DEF} curl -fsSL ${RED}URL${DEF} | bash -s -- --threshold 50"
    echo
  fi

  echo "${CYAN}Per-domain analysis${DEF}"
  echo

  if [[ -n "$FULL_DOMAIN_INPUT" ]]; then
    print_selected_domain_summary "$FULL_DOMAIN_INPUT" || return $?
  elif [[ "$compact_mode" -eq 1 ]]; then
    metrics_file=$(mktemp)
    cleanup_files+=("$metrics_file")

    build_domain_metrics "$metrics_file" "$report_file" || return $?
    print_domain_rollup_from_file "$metrics_file"
    echo
  else
    for base in "${BASE_LOGS[@]}"; do
      local domain
      domain=$(basename "$base")
      if stream_selected_base_log "$base" | print_python_summary_from_stream "Domain: $domain" --quiet-empty; then
        echo
      else
        status=$?
        if [[ "$status" -ne 3 ]]; then
          return "$status"
        fi
      fi
    done
  fi

  if [[ -z "$FULL_DOMAIN_INPUT" && "$compact_mode" -eq 0 ]]; then
    g=$(prompt_yes_no $'\e[36mRun global domain summary? (y/n):\e[0m ' "$RUN_GLOBAL_INPUT")
    if [[ "$g" == "y" ]]; then
      if [[ -z "${metrics_file:-}" ]]; then
        metrics_file=$(mktemp)
        cleanup_files+=("$metrics_file")
        build_domain_metrics "$metrics_file" || return $?
      fi
      print_domain_rollup_from_file "$metrics_file"
    fi
  fi

  inspect_prompt="${CYAN}Inspect raw access entries for a single domain (timeframe: ${TIMEFRAME_DISPLAY:-all})? (y/n):${DEF} "
  s=$(prompt_yes_no "$inspect_prompt" "$RUN_INSPECT_INPUT")

  if [[ "$s" == "y" ]]; then
    local dlog selected_base
    echo "Available domains:"
    printf "${CYAN} - %s${DEF}\n" "${BASE_LOGS[@]##*/}"

    if [[ -n "$DOMAIN_INPUT" ]]; then
      dlog="$DOMAIN_INPUT"
    else
      dlog=$(read_tty "Enter domain log name (it will review both the non-SSL and SSL logs): ") || {
        echo "Non-interactive inspect mode requires --domain" >&2
        exit 2
      }
    fi

    selected_base=$(find_base_log "$dlog") || selected_base=""
    if [[ -z "$selected_base" ]]; then
      echo "No matching log found for: ${dlog%-ssl_log}"
    else
      echo
      echo "${CYAN}Showing raw access entries for: $(basename "$selected_base")${DEF}"
      echo
      stream_selected_base_log "$selected_base" | print_filtered_raw_from_stream
    fi
  fi

  review_archived_logs

  echo
  echo "${GREEN}Done${DEF}"
}

main "$@"
