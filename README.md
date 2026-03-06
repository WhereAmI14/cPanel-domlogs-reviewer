# cPanel Apache Log Analyzer

A CLI tool for analyzing Apache access logs on cPanel servers. Supports interactive and non-interactive use, time-range filtering, bot detection, peak burst analysis, and archived rotated log review.

Built for real operational use on cPanel/WHM hosting environments.

---

## Features

- **Time filtering** - analyze the last N minutes, hours, or days
- **Per-domain breakdown** - top IPs and status codes per domain
- **Global insights** - aggregated view across all domains
- **Bot detection** - identifies and separates crawler/spider traffic
- **Peak burst analysis** - finds the busiest single minute in the log
- **Archive support** - reads rotated `.gz` logs from `~/logs`
- **Non-interactive mode** - fully scriptable via CLI flags
- **Color-safe output** - respects `NO_COLOR` and non-TTY environments

---

## Requirements

- Bash 4+
- awk with `mktime()` support (gawk or mawk; standard on cPanel servers)
- Access to cPanel user log directories (`/home/USER/access-logs` or `/home/USER/access_logs`)

---

## Usage

```bash
bash logs-reviewer.sh [OPTIONS]
```

### Options

| Flag | Description |
|------|-------------|
| `-t, --timeframe VALUE` | Time window: `"5 minutes"`, `"24 hours"`, `"7 days"`, or `"all"` |
| `-g, --global y\|n` | Run global insights across all domains |
| `-i, --inspect y\|n` | Inspect raw entries for a single domain |
| `-a, --archive y\|n` | Review archived rotated logs from `~/logs` |
| `--archive-date DATE` | Archive period to inspect (example: `Feb-2026`) |
| `--archive-domain NAME` | Domain to inspect in archive mode |
| `-d, --domain NAME` | Domain log name for inspect mode (example: `example.com`) |
| `-u, --user USER` | Read logs from `/home/USER/access-logs` (useful when running as root) |
| `-h, --help` | Show help |

---

## Examples

**Interactive — check the last 24 hours:**
```bash
bash logs-reviewer.sh
# Follow the prompts
```

**Non-interactive — last 2 hours, global insights, no inspection:**
```bash
bash logs-reviewer.sh -t "2 hours" -g y -i n -a n
```

**As root, scoped to a specific cPanel user:**
```bash
bash logs-reviewer.sh -u clientusername -t "1 hour" -g y -i n -a n
```

**Review a specific archived month for one domain:**
```bash
bash logs-reviewer.sh -a y --archive-date Feb-2026 --archive-domain example.com
```

---

## Log Discovery

The script automatically discovers logs from cPanel's standard path:

- `/home/USER/access-logs/`

Both plain log files and `-ssl_log` variants are included. Archived rotated logs (`.gz`) are read from `~/logs` using cPanel's standard `domain-Mon-YYYY.gz` naming convention.

---

## Environment

| Variable | Effect |
|----------|--------|
| `NO_COLOR` | Disables ANSI color output |
| `TERM=dumb` | Automatically disables color |

Output is plain text when piped or redirected.

---

## License

MIT