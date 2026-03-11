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
MAGENTA=$'\033[35;1m'
DEF=$'\033[0m'

# The script is designed to be interactive but also supports non-interactive use with explicit options.
ME=$(whoami)
USE_TIME=false
M=0
CUTOFF_EPOCH=0
REQUESTED_LOOKBACK_SECS=0
MAIN_INCLUDE_ARCHIVES=0
ACTIVE_OLDEST_EPOCH=0
COMBINED_OLDEST_EPOCH=0
DNS_TIMEOUT_SECS=2

# Only emit ANSI colors when writing to a terminal (and not explicitly disabled).
USE_COLOR=0
if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-}" != "dumb" ]]; then
  USE_COLOR=1
fi

declare -a BASE_LOGS=()
TIMEFRAME_INPUT=""
TIMEFRAME_DISPLAY=""
RUN_GLOBAL_INPUT=""
RUN_INSPECT_INPUT=""
RUN_ARCHIVE_INPUT=""
DOMAIN_INPUT=""
ARCHIVE_DATE_INPUT=""
ARCHIVE_DOMAIN_INPUT=""
LOG_USER_INPUT=""
declare -a ARCHIVE_LOGS=()
declare -a ARCHIVE_PERIODS=()
declare -A PTR_CACHE=()

usage() {
  cat <<'EOF'
Usage: logs-reviewer-ptr.sh [options]

Options:
  -t, --timeframe VALUE    Time window (examples: "5 minutes", "24 hours", "all")
  -g, --global y|n         Run global insights
  -i, --inspect y|n        Inspect a single domain access log
  -a, --archive y|n        Review archived rotated logs from ~/logs
      --archive-date DATE  Archive date token to inspect (example: Feb-2026)
      --archive-domain N   Domain log name for archive inspect (example.com or example.com-ssl_log)
  -d, --domain NAME        Domain log name for inspect mode (example.com or example.com-ssl_log)
  -u, --user USER          Username to read logs from /home/USER/access-logs or /home/USER/access_logs (works for root too)
  -h, --help               Show this help
EOF
}
# Parse options manually to allow interspersed arguments and better error messages.
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
# End of option parsing
cleanup_files=()
cleanup() {
  local f
  for f in "${cleanup_files[@]:-}"; do
    [[ -n "$f" && -f "$f" ]] && rm -f "$f"
  done
}
trap cleanup EXIT

on_err() {
  local ec=$?
  # Keep it short; the script is interactive and should be readable when it fails.
  echo "Error: failed at line $1." >&2
  exit "$ec"
}
trap 'on_err $LINENO' ERR
# The script is designed to be interactive but also supports non-interactive use with explicit options. When running in non-interactive mode, all necessary options must be provided via command-line arguments; otherwise, the script will prompt for input or exit with an error if input is not possible.
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

colorize_status_last_field() {
  # Expects the HTTP status code to be the last whitespace-delimited field.
  # No-op when colors are disabled.
  if [[ "$USE_COLOR" -ne 1 ]]; then
    cat
    return
  fi
# Colorize status codes by class: 2xx green, 3xx cyan, 4xx yellow, 5xx red.
  awk -v c2="$GREEN" -v c3="$CYAN" -v c4="$YELLOW" -v c5="$RED" -v def="$DEF" '
    {
      code=$NF
      if (code ~ /^[0-9]{3}$/) {
        cls=substr(code,1,1)
        col=""
        if (cls=="2") col=c2
        else if (cls=="3") col=c3
        else if (cls=="4") col=c4
        else if (cls=="5") col=c5
        if (col != "") $NF=col code def
      }
      print
    }
  '
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
      minute|minutes)
        M="$n"
        USE_TIME=true
        ;;
      hour|hours)
        M=$((n * 60))
        USE_TIME=true
        ;;
      day|days)
        M=$((n * 1440))
        USE_TIME=true
        ;;
      *)
        return 1
        ;;
    esac

    CUTOFF_EPOCH=$(( $(date +%s) - (M * 60) ))
    REQUESTED_LOOKBACK_SECS=$((M * 60))
    return 0
  fi
  return 1
}

parse_timeframe() {
  local tf
  if [[ -n "$TIMEFRAME_INPUT" ]]; then
    if ! parse_timeframe_value "$TIMEFRAME_INPUT"; then
      echo "Invalid --timeframe value: $TIMEFRAME_INPUT" >&2
      exit 2
    fi
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
# The prompt_yes_no function is used for multiple questions, so it accepts an optional preset value for non-interactive mode. If the preset is provided, it validates and returns it immediately without prompting.
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

can_read_tty() {
  if { exec 3</dev/tty; } 2>/dev/null; then
    exec 3<&-
    return 0
  fi
  return 1
}

collect_base_logs() {
  local -A seen=()
  local -a files=()
  local f base target_user tmpf scope_user

  tmpf=$(mktemp)
  cleanup_files+=("$tmpf")

  if [[ "$ME" == "root" ]]; then
    scope_user="${LOG_USER_INPUT:-}"
    if [[ -z "$scope_user" ]]; then
      # Interactive convenience for root: allow narrowing to a single cPanel user.
      # Blank keeps the current behavior (scan all users).
      scope_user=$(read_tty $'\e[36mAs root, enter cPanel username to scan (blank for all users):\e[0m ') || true
      scope_user="${scope_user//[[:space:]]/}"
    fi

    : > "$tmpf"
    if [[ -n "$scope_user" ]]; then
      for d in "/home/$scope_user/access-logs" "/home/$scope_user/access_logs"; do
        [[ -e "$d" ]] || continue
        find -L "$d" -maxdepth 1 -type f -print0 2>/dev/null >> "$tmpf" || true
      done
    else
      find -L /home -type f \( -path '/home/*/access-logs/*' -o -path '/home/*/access_logs/*' \) -print0 2>/dev/null >> "$tmpf" || true
    fi
  else
    target_user="${LOG_USER_INPUT:-$ME}"
    : > "$tmpf"
    for d in "/home/$target_user/access-logs" "/home/$target_user/access_logs"; do
      [[ -e "$d" ]] || continue
      find -L "$d" -maxdepth 1 -type f -print0 2>/dev/null >> "$tmpf" || true
    done
    while IFS= read -r -d '' f; do
      files+=("$f")
    done < "$tmpf"

    if [[ ${#files[@]} -eq 0 && -z "$LOG_USER_INPUT" ]]; then
      target_user=$(read_tty $'\e[36mNo logs in your home dir. Enter username to inspect:\e[0m ') || {
        echo "No logs found in /home/$ME/access-logs or /home/$ME/access_logs. Pass --user USER for non-interactive mode." >&2
        exit 2
      }
      : > "$tmpf"
      for d in "/home/$target_user/access-logs" "/home/$target_user/access_logs"; do
        [[ -e "$d" ]] || continue
        find -L "$d" -maxdepth 1 -type f -print0 2>/dev/null >> "$tmpf" || true
      done
      while IFS= read -r -d '' f; do
        files+=("$f")
      done < "$tmpf"
    fi
  fi

  if [[ "$ME" == "root" ]]; then
    while IFS= read -r -d '' f; do
      files+=("$f")
    done < "$tmpf"
  fi

  for f in "${files[@]}"; do
    base="${f%-ssl_log}"
    seen["$base"]=1
  done

  if [[ ${#seen[@]} -eq 0 ]]; then
    return 1
  fi

  : > "$tmpf"
  printf '%s\n' "${!seen[@]}" | sort > "$tmpf"
  BASE_LOGS=()
  while IFS= read -r f; do
    BASE_LOGS+=("$f")
  done < "$tmpf"
}

collect_archived_logs() {
  local -A seen_dirs=()
  local -A seen_files=()
  local -A seen_periods=()
  local -a dirs=()
  local base home_dir archive_dir f bn tmpf scan_tmpf

  ARCHIVE_LOGS=()
  ARCHIVE_PERIODS=()

  for base in "${BASE_LOGS[@]}"; do
    home_dir=$(dirname "$(dirname "$base")")
    archive_dir="$home_dir/logs"
    if [[ -d "$archive_dir" ]]; then
      seen_dirs["$archive_dir"]=1
    fi
  done

  if [[ ${#seen_dirs[@]} -eq 0 ]]; then
    return 0
  fi

  dirs=("${!seen_dirs[@]}")
  for archive_dir in "${dirs[@]}"; do
    scan_tmpf=$(mktemp)
    cleanup_files+=("$scan_tmpf")
    : > "$scan_tmpf"
    find -L "$archive_dir" -maxdepth 1 -type f -name '*.gz' -print0 2>/dev/null >> "$scan_tmpf" || true

    while IFS= read -r -d '' f; do
      seen_files["$f"]=1
      bn=$(basename "$f")
      if [[ "$bn" =~ -([A-Za-z]{3}-[0-9]{4})\.gz$ ]]; then
        seen_periods["${BASH_REMATCH[1]}"]=1
      fi
    done < "$scan_tmpf"
  done

  if [[ ${#seen_files[@]} -eq 0 ]]; then
    return 0
  fi

  tmpf=$(mktemp)
  cleanup_files+=("$tmpf")

  : > "$tmpf"
  printf '%s\n' "${!seen_files[@]}" | sort > "$tmpf"
  while IFS= read -r f; do
    ARCHIVE_LOGS+=("$f")
  done < "$tmpf"

  if [[ ${#seen_periods[@]} -gt 0 ]]; then
    : > "$tmpf"
    printf '%s\n' "${!seen_periods[@]}" | sort > "$tmpf"
    while IFS= read -r f; do
      ARCHIVE_PERIODS+=("$f")
    done < "$tmpf"
  fi
}

filter_by_time() {
  if [[ "$USE_TIME" != true ]]; then
    cat
    return
  fi

  awk -v cutoff="$CUTOFF_EPOCH" '
    function month_to_num(m) {
      return (m=="Jan")?1:(m=="Feb")?2:(m=="Mar")?3:(m=="Apr")?4:(m=="May")?5:(m=="Jun")?6:(m=="Jul")?7:(m=="Aug")?8:(m=="Sep")?9:(m=="Oct")?10:(m=="Nov")?11:(m=="Dec")?12:0
    }

    {
      ts = $4
      gsub(/\[/, "", ts)
      split(ts, a, /[:\/]/)
      if (length(a) < 6) {
        next
      }

      month = month_to_num(a[2])
      if (month == 0) {
        next
      }

      epoch = mktime(sprintf("%04d %02d %02d %02d %02d %02d", a[3], month, a[1], a[4], a[5], a[6]))
      if (epoch >= cutoff) {
        print
      }
    }
  '
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

stream_archived_base_log() {
  local base="$1"
  local base_name bn f
  base_name=$(basename "$base")

  for f in "${ARCHIVE_LOGS[@]}"; do
    bn=$(basename "$f")
    if [[ "$bn" == "$base_name"-*.gz || "$bn" == "$base_name-ssl_log"-*.gz ]]; then
      gzip -cd -- "$f" || true
    fi
  done
}

stream_selected_base_log() {
  local base="$1"
  stream_base_log "$base"
  if [[ "$MAIN_INCLUDE_ARCHIVES" -eq 1 ]]; then
    stream_archived_base_log "$base"
  fi
}

oldest_epoch_from_stream() {
  awk '
    function month_to_num(m) {
      return (m=="Jan")?1:(m=="Feb")?2:(m=="Mar")?3:(m=="Apr")?4:(m=="May")?5:(m=="Jun")?6:(m=="Jul")?7:(m=="Aug")?8:(m=="Sep")?9:(m=="Oct")?10:(m=="Nov")?11:(m=="Dec")?12:0
    }
    {
      ts = $4
      gsub(/\[/, "", ts)
      split(ts, a, /[:\/]/)
      if (length(a) < 6) next
      month = month_to_num(a[2])
      if (month == 0) next
      epoch = mktime(sprintf("%04d %02d %02d %02d %02d %02d", a[3], month, a[1], a[4], a[5], a[6]))
      if (epoch > 0 && (min == 0 || epoch < min)) min = epoch
    }
    END {
      if (min > 0) print min
      else print 0
    }
  '
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
    echo "${MAGENTA}Requested window:${DEF} $requested_span"
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

print_status_with_percent() {
  local file="$1"
  local total="$2"

  awk -v total="$total" '{s[$9]++} END {for (code in s) printf "%8d  %6.2f%%  %s\n", s[code], (s[code] * 100 / total), code}' "$file" | sort -nr | colorize_status_last_field
}

resolve_ptr_host() {
  local ip="$1"
  local host=""

  if [[ -n "${PTR_CACHE[$ip]+x}" ]]; then
    printf '%s' "${PTR_CACHE[$ip]}"
    return 0
  fi

  if command -v getent >/dev/null 2>&1; then
    if command -v timeout >/dev/null 2>&1; then
      host=$(timeout "${DNS_TIMEOUT_SECS}s" getent hosts "$ip" 2>/dev/null | awk 'NR==1 {print $2}')
    else
      host=$(getent hosts "$ip" 2>/dev/null | awk 'NR==1 {print $2}')
    fi
  fi

  if [[ -z "$host" ]] && command -v host >/dev/null 2>&1; then
    if command -v timeout >/dev/null 2>&1; then
      host=$(timeout "${DNS_TIMEOUT_SECS}s" host "$ip" 2>/dev/null | awk '/domain name pointer/ {gsub(/\.$/, "", $NF); print $NF; exit}')
    else
      host=$(host "$ip" 2>/dev/null | awk '/domain name pointer/ {gsub(/\.$/, "", $NF); print $NF; exit}')
    fi
  fi

  if [[ -z "$host" || "$host" == "$ip" ]]; then
    host="-"
  fi

  PTR_CACHE["$ip"]="$host"
  printf '%s' "$host"
}

bucket_ptr_host() {
  local host="$1"

  case "$host" in
    -)
      printf '%s' "-"
      ;;
    *.bc.googleusercontent.com|*.googleusercontent.com)
      printf '%s' "googleusercontent.com"
      ;;
    *.compute.amazonaws.com|*.amazonaws.com)
      printf '%s' "amazonaws.com"
      ;;
    *.colocrossing.com)
      printf '%s' "colocrossing.com"
      ;;
    *.cloudflare.com)
      printf '%s' "cloudflare.com"
      ;;
    *.digitalocean.com)
      printf '%s' "digitalocean.com"
      ;;
    *.linodeusercontent.com)
      printf '%s' "linodeusercontent.com"
      ;;
    *)
      printf '%s' "$host"
      ;;
  esac
}

suffix_wildcard() {
  local host="$1"
  local keep_labels="$2"
  local IFS='.'
  local -a parts=()
  local suffix=""
  local i start

  read -r -a parts <<< "$host"
  if (( ${#parts[@]} <= keep_labels )); then
    printf '%s' "$host"
    return 0
  fi

  start=$((${#parts[@]} - keep_labels))
  suffix="${parts[$start]}"
  for ((i = start + 1; i < ${#parts[@]}; i++)); do
    suffix+=".${parts[$i]}"
  done

  printf '*.%s' "$suffix"
}

group_ptr_host_family() {
  local host="$1"
  local IFS='.'
  local -a parts=()
  local first_label=""

  read -r -a parts <<< "$host"
  if (( ${#parts[@]} == 0 )); then
    printf '%s' "$host"
    return 0
  fi
  first_label="${parts[0]}"

  case "$host" in
    -)
      printf '%s' "-"
      ;;
    *.bc.googleusercontent.com)
      suffix_wildcard "$host" 3
      ;;
    *.static.cloudzy.com)
      suffix_wildcard "$host" 3
      ;;
    *.fra1.stableserver.net|*.stableserver.net)
      suffix_wildcard "$host" 3
      ;;
    *.compute.amazonaws.com)
      suffix_wildcard "$host" 4
      ;;
    *)
      if (( ${#parts[@]} >= 4 )); then
        suffix_wildcard "$host" 2
      elif (( ${#parts[@]} == 3 )) && [[ "$first_label" == *[0-9]* || "$first_label" == *-* ]]; then
        suffix_wildcard "$host" 2
      else
        printf '%s' "$host"
      fi
      ;;
  esac
}

print_top_ips_with_hosts() {
  local source_file="$1"
  local limit="${2:-10}"
  local count ip host tmpf

  tmpf=$(mktemp)
  cleanup_files+=("$tmpf")
  awk '{print $1}' "$source_file" | sort | uniq -c | sort -rh | awk -v limit="$limit" 'NR<=limit {print $1, $2}' > "$tmpf"

  printf "%8s  %-39s %s\n" "Count" "IP" "PTR Host"

  while read -r count ip; do
    [[ -n "${ip:-}" ]] || continue
    host=$(resolve_ptr_host "$ip")
    printf "%8d  %-39s %s\n" "$count" "$ip" "$host"
  done < "$tmpf"
}

print_top_ptr_groups() {
  local source_file="$1"
  local limit="$2"
  local group_kind="$3"
  local group_label="$4"
  local ip_counts_tmp group_rows_tmp summary_tmp
  local count ip host group_value

  ip_counts_tmp=$(mktemp)
  group_rows_tmp=$(mktemp)
  summary_tmp=$(mktemp)
  cleanup_files+=("$ip_counts_tmp" "$group_rows_tmp" "$summary_tmp")

  awk '{print $1}' "$source_file" | sort | uniq -c | sort -rh > "$ip_counts_tmp"

  while read -r count ip; do
    [[ -n "${ip:-}" ]] || continue
    host=$(resolve_ptr_host "$ip")
    if [[ "$group_kind" == "provider" ]]; then
      group_value=$(bucket_ptr_host "$host")
    else
      group_value=$(group_ptr_host_family "$host")
    fi
    printf "%s\t%s\t%s\n" "$count" "$group_value" "$ip" >> "$group_rows_tmp"
  done < "$ip_counts_tmp"

  awk -F'\t' '
    {
      entries[$2] += $1
      groups[$2]++
    }
    END {
      for (group in entries) {
        printf "%d\t%d\t%s\n", entries[group], groups[group], group
      }
    }
  ' "$group_rows_tmp" | sort -t $'\t' -k1,1nr -k2,2nr -k3,3 > "$summary_tmp"

  printf "%8s  %9s  %s\n" "Requests" "Unique IPs" "$group_label"
  awk -F'\t' -v limit="$limit" 'NR<=limit {printf "%8d  %9d  %s\n", $1, $2, $3}' "$summary_tmp"
}

print_top_ptr_hosts() {
  local source_file="$1"
  local limit="${2:-10}"

  print_top_ptr_groups "$source_file" "$limit" "host" "PTR Host Group"
}

print_top_ptr_providers() {
  local source_file="$1"
  local limit="${2:-10}"

  print_top_ptr_groups "$source_file" "$limit" "provider" "PTR Provider"
}

print_error_ip_status_pairs_with_hosts() {
  local source_file="$1"
  local limit="${2:-10}"
  local count ip status host tmpf

  tmpf=$(mktemp)
  cleanup_files+=("$tmpf")
  awk '$9 ~ /^[45]/ {print $1, $9}' "$source_file" | sort | uniq -c | sort -rh | awk -v limit="$limit" 'NR<=limit {print $1, $2, $3}' > "$tmpf"

  printf "%8s  %-39s %-40s %s\n" "Count" "IP" "PTR Host" "Status"

  while read -r count ip status; do
    [[ -n "${status:-}" ]] || continue
    host=$(resolve_ptr_host "$ip")
    printf "%8d  %-39s %-40s %s\n" "$count" "$ip" "$host" "$status"
  done < "$tmpf"
}

print_insights_from_file() {
  local source_file="$1"
  local heading="$2"
  local total_requests unique_ips total_bytes avg_bytes bot_hits bot_pct

  if [[ ! -s "$source_file" ]]; then
    echo
    echo "No data for selected timeframe"
    return 0
  fi

  total_requests=$(wc -l < "$source_file")
  unique_ips=$(awk '{print $1}' "$source_file" | sort -u | wc -l)
  total_bytes=$(awk '$10 ~ /^[0-9]+$/ {s+=$10} END {print s+0}' "$source_file")
  avg_bytes=$(awk '$10 ~ /^[0-9]+$/ {s+=$10; c++} END {if (c>0) printf "%.2f", s/c; else print "0.00"}' "$source_file")

  echo
  echo "${GREEN}${heading}${DEF}"
  echo "Requests: $total_requests"
  echo "Unique IPs: $unique_ips"
  echo "Transferred bytes: $total_bytes"
  echo "Average response bytes: $avg_bytes"

  echo
  echo "${GREEN}Top IPs${DEF}"
  print_top_ips_with_hosts "$source_file" 10

  echo
  echo "${GREEN}Top PTR Hosts${DEF}"
  print_top_ptr_hosts "$source_file" 10

  echo
  echo "${GREEN}Top PTR Providers${DEF}"
  print_top_ptr_providers "$source_file" 10

  echo
  echo "${GREEN}Top URLs${DEF}"
  awk '{print $7}' "$source_file" | sort | uniq -c | sort -rh | awk 'NR<=10'

  echo
  echo "${GREEN}HTTP Methods${DEF}"
  awk '{m=$6; gsub(/"/,"",m); print m}' "$source_file" | sort | uniq -c | sort -rh

  echo
  echo "${GREEN}Status Codes${DEF}"
  print_status_with_percent "$source_file" "$total_requests"

  bot_hits=$(awk -F'"' '$6 ~ /bot|crawl|spider/i {c++} END {print c+0}' "$source_file")
  bot_pct=$(awk -v b="$bot_hits" -v t="$total_requests" 'BEGIN {if (t>0) printf "%.2f", (b*100/t); else print "0.00"}')

  echo
  echo "${GREEN}Bots${DEF}"
  echo "Bot requests: $bot_hits ($bot_pct%)"
  awk -F'"' '$6 ~ /bot|crawl|spider/i {print $6}' "$source_file" | sort | uniq -c | sort -rh | awk 'NR<=10'

  echo
  echo "${GREEN}Top Referrers${DEF}"
  awk -F'"' '{print $4}' "$source_file" | grep -v '^-$' | sort | uniq -c | sort -rh | awk 'NR<=10'

  echo
  echo "${GREEN}Top 4xx URLs${DEF}"
  awk '$9 ~ /^4/ {print $7}' "$source_file" | sort | uniq -c | sort -rh | awk 'NR<=10'

  echo
  echo "${GREEN}Top 5xx URLs${DEF}"
  awk '$9 ~ /^5/ {print $7}' "$source_file" | sort | uniq -c | sort -rh | awk 'NR<=10'

  echo
  echo "${GREEN}Top Error IP/Status Pairs${DEF}"
  print_error_ip_status_pairs_with_hosts "$source_file" 10 | colorize_status_last_field

  echo
  echo "${GREEN}Peak Minute Burst${DEF}"
  awk '{k=substr($4,2,17); c[k]++} END {max=0; key=""; for (k in c) if (c[k]>max) {max=c[k]; key=k}; if (max>0) printf "%s (%d requests)\n", key, max; else print "n/a"}' "$source_file"
}

review_archived_logs() {
  local run_archive date_choice raw_domain base_input match_count show_raw archive_heading
  local f bn domain tmpf
  local -a scope_matches=()
  local -a matched_periods=()
  local -a available_domains=()
  local -A seen_periods=()
  local -A seen_domains=()
  local archive_tmp

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

  scope_matches=()
  if [[ -n "$date_choice" ]]; then
    for f in "${ARCHIVE_LOGS[@]}"; do
      bn=$(basename "$f")
      if [[ "$bn" == *"-$date_choice.gz" ]]; then
        scope_matches+=("$f")
      fi
    done
    if [[ ${#scope_matches[@]} -eq 0 ]]; then
      echo "No archived logs found for date: $date_choice"
      return 0
    fi
  else
    scope_matches=("${ARCHIVE_LOGS[@]}")
  fi

  seen_domains=()
  for f in "${scope_matches[@]}"; do
    bn=$(basename "$f")
    domain=""
    if [[ "$bn" =~ ^(.+)-ssl_log-[A-Za-z]{3}-[0-9]{4}\.gz$ ]]; then
      domain="${BASH_REMATCH[1]}"
    elif [[ "$bn" =~ ^(.+)-[A-Za-z]{3}-[0-9]{4}\.gz$ ]]; then
      domain="${BASH_REMATCH[1]}"
    fi
    if [[ -n "$domain" ]]; then
      seen_domains["$domain"]=1
    fi
  done

  available_domains=()
  if [[ ${#seen_domains[@]} -gt 0 ]]; then
    tmpf=$(mktemp)
    cleanup_files+=("$tmpf")
    : > "$tmpf"
    printf '%s\n' "${!seen_domains[@]}" | sort > "$tmpf"
    while IFS= read -r domain; do
      available_domains+=("$domain")
    done < "$tmpf"
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

  archive_tmp=$(mktemp)
  cleanup_files+=("$archive_tmp")

  if [[ -z "$raw_domain" ]]; then
    if [[ -n "$date_choice" ]]; then
      archive_heading="Archived summary ($date_choice, all domains)"
    else
      archive_heading="Archived summary (all dates, all domains)"
    fi
    {
      for f in "${scope_matches[@]}"; do
        gzip -cd -- "$f" || true
      done
    } | filter_by_time > "$archive_tmp"
  else
    base_input="${raw_domain%-ssl_log}"
    match_count=0
    matched_periods=()
    for f in "${scope_matches[@]}"; do
      bn=$(basename "$f")
      if [[ "$bn" == "$base_input"-*.gz || "$bn" == "$base_input-ssl_log"-*.gz ]]; then
        match_count=$((match_count + 1))
        if [[ "$bn" =~ -([A-Za-z]{3}-[0-9]{4})\.gz$ ]]; then
          if [[ -z "${seen_periods[${BASH_REMATCH[1]}]:-}" ]]; then
            seen_periods["${BASH_REMATCH[1]}"]=1
            matched_periods+=("${BASH_REMATCH[1]}")
          fi
        fi
      fi
    done

    if [[ "$match_count" -eq 0 ]]; then
      if [[ -n "$date_choice" ]]; then
        echo "No matching archived log found for domain: $base_input ($date_choice)"
      else
        echo "No matching archived log found for domain: $base_input"
      fi
      return 0
    fi

    if [[ -n "$date_choice" ]]; then
      archive_heading="Archived summary ($date_choice, $base_input)"
    elif [[ ${#matched_periods[@]} -gt 0 ]]; then
      archive_heading="Archived summary (${matched_periods[*]}, $base_input)"
    else
      archive_heading="Archived summary (all dates, $base_input)"
    fi

    echo
    echo "${GREEN}Archived files for $base_input (${match_count} files)${DEF}"
    for f in "${scope_matches[@]}"; do
      bn=$(basename "$f")
      if [[ "$bn" == "$base_input"-*.gz || "$bn" == "$base_input-ssl_log"-*.gz ]]; then
        echo " - $bn"
      fi
    done
    echo

    {
      for f in "${scope_matches[@]}"; do
        bn=$(basename "$f")
        if [[ "$bn" == "$base_input"-*.gz || "$bn" == "$base_input-ssl_log"-*.gz ]]; then
          gzip -cd -- "$f" || true
        fi
      done
    } | filter_by_time > "$archive_tmp"
  fi

  print_insights_from_file "$archive_tmp" "$archive_heading"

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
  cat -- "$archive_tmp"
}

parse_timeframe

echo "${GREEN}Access log reviewer${DEF}"
echo "Purpose: Summarize per-domain Apache access logs (top IPs, status codes), optionally global insights and raw inspection."
echo

# Some environments ship an awk without mktime(); in that case, avoid crashing and disable time filtering.
if [[ "$USE_TIME" == true ]]; then
  if ! awk 'BEGIN{mktime("2020 01 01 00 00 00"); exit 0}' >/dev/null 2>&1; then
    echo "WARN: awk does not support mktime(); disabling time filter. Use --timeframe all for accurate results." >&2
    USE_TIME=false
  fi
fi

if ! collect_base_logs; then
  echo "No logs found"
  exit 0
fi

collect_archived_logs

configure_main_data_sources
echo

echo "${GREEN}Found ${#BASE_LOGS[@]} logs${DEF}"
echo

echo "${CYAN}Per-domain analysis${DEF}"
echo

for base in "${BASE_LOGS[@]}"; do
  domain=$(basename "$base")
  domain_tmp=$(mktemp)
  cleanup_files+=("$domain_tmp")

  stream_selected_base_log "$base" | filter_by_time > "$domain_tmp"

  if [[ ! -s "$domain_tmp" ]]; then
    continue
  fi

  total=$(wc -l < "$domain_tmp")
  unique_ips=$(awk '{print $1}' "$domain_tmp" | sort -u | wc -l)

  echo "${RED}Domain: $domain${DEF}"
  echo "Requests: $total | Unique IPs: $unique_ips"

  echo "Top IPs"
  print_top_ips_with_hosts "$domain_tmp" 10

  echo "Top PTR Hosts"
  print_top_ptr_hosts "$domain_tmp" 10

  echo "Top PTR Providers"
  print_top_ptr_providers "$domain_tmp" 10

  echo "Status codes"
  print_status_with_percent "$domain_tmp" "$total"
  echo

done

g=$(prompt_yes_no $'\e[36mRun global insights? (y/n):\e[0m ' "$RUN_GLOBAL_INPUT")

if [[ "$g" == "y" ]]; then
  TMP=$(mktemp)
  cleanup_files+=("$TMP")

  {
    for base in "${BASE_LOGS[@]}"; do
      stream_selected_base_log "$base"
    done
  } | filter_by_time > "$TMP"
  print_insights_from_file "$TMP" "Summary"
fi

inspect_prompt="${CYAN}Inspect raw access entries for a single domain (timeframe: ${TIMEFRAME_DISPLAY:-all})? (y/n):${DEF} "
s=$(prompt_yes_no "$inspect_prompt" "$RUN_INSPECT_INPUT")

if [[ "$s" == "y" ]]; then
  echo "Available domains:"
  printf ' - %s\n' "${BASE_LOGS[@]##*/}"

  if [[ -n "$DOMAIN_INPUT" ]]; then
    dlog="$DOMAIN_INPUT"
  else
    dlog=$(read_tty "Enter domain log name (e.g. example.com or example.com-ssl_log): ") || {
      echo "Non-interactive inspect mode requires --domain" >&2
      exit 2
    }
  fi
  BASE_INPUT="${dlog%-ssl_log}"

  selected_base=""
  for base in "${BASE_LOGS[@]}"; do
    if [[ "$(basename "$base")" == "$BASE_INPUT" ]]; then
      selected_base="$base"
      break
    fi
  done

  if [[ -z "$selected_base" ]]; then
    echo "No matching log found for: $BASE_INPUT"
  else
    echo
    echo "${CYAN}Showing raw access entries for: $(basename "$selected_base")${DEF}"
    echo
    stream_selected_base_log "$selected_base" | filter_by_time
  fi
fi

review_archived_logs

echo
echo "${GREEN}Done${DEF}"

# Ivan Rachev 
