# Bash Variant

This directory contains the original Bash-only version of `cPanel Access Log Reviewer`.

The root-level tool is the recommended version for normal use:

- `../logs-reviewer.sh`
- `../runner.sh`
- `../log_enrich.py`

Keep this Bash variant as a fallback if you want a single-script implementation without the Python helper.

## What This Variant Does

- analyzes Apache access logs on cPanel/WHM servers
- prints per-domain summaries and global insights
- supports PTR / reverse-DNS lookups
- supports Org / ISP enrichment when external tools are available
- reviews rotated archives from `~/logs`
- works in interactive and non-interactive modes

## Requirements

### Required

- Bash 4+
- `awk` with `mktime()` support
- access to cPanel user log directories:
  - `/home/USER/access-logs`
  - `/home/USER/access_logs`

### Optional

- `getent` or `host` for PTR resolution
- `curl` for Org / ISP enrichment
- `jq` for cleaner JSON parsing
- `whois` as a final fallback
- `timeout` for fast failure on slow lookups

Missing enrichment sources display `-` rather than failing the whole run.

## Usage

Run the tool directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/WhereAmI14/cPanel-access-log-reviewer/main/bash-variant/logs-reviewer.sh | bash
```

Run it from the repository root:

```bash
bash bash-variant/logs-reviewer.sh [OPTIONS]
```

Or from inside the `bash-variant/` directory:

```bash
bash logs-reviewer.sh [OPTIONS]
```

## Options

| Flag | Description |
|------|-------------|
| `-t, --timeframe VALUE` | Time window: `"5 minutes"`, `"2 hours"`, `"7 days"`, or `"all"` |
| `-g, --global y\|n` | Run global insights across all domains |
| `-i, --inspect y\|n` | Inspect raw entries for a single domain |
| `-a, --archive y\|n` | Review archived rotated logs from `~/logs` |
| `--archive-date DATE` | Archive period to inspect, e.g. `Feb-2026` |
| `--archive-domain NAME` | Domain to inspect in archive mode |
| `-d, --domain NAME` | Domain log name for inspect mode |
| `-u, --user USER` | Read logs from another cPanel user when permitted |
| `-h, --help` | Show help |

## Examples

```bash
# Interactive run
bash bash-variant/logs-reviewer.sh

# Non-interactive, last 2 hours, global summary
bash bash-variant/logs-reviewer.sh -t "2 hours" -g y -i n -a n

# As root, scoped to a specific cPanel user
bash bash-variant/logs-reviewer.sh -u clientusername -t "1 hour" -g y -i n -a n

# Review a specific archived month
bash bash-variant/logs-reviewer.sh -a y --archive-date Feb-2026 --archive-domain example.com
```

## Notes

- This variant is kept for compatibility and fallback use.
- The root-level tool is the primary maintained version.
- An IP may have a valid Org but no PTR record, or the reverse; both are handled independently.

##
This variant of the tool might not include some of the features of the main version!
