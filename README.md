# cPanel Apache Log Analyzer

A CLI tool for analyzing Apache access logs on cPanel/WHM servers. Provides per-domain summaries, global insights, PTR/host enrichment, bot detection, and archive support.

Built for real operational use on cPanel/WHM hosting environments.

---

## Features

- **Time filtering** — analyze the last N minutes, hours, or days, or all available data
- **Per-domain breakdown** — request counts, unique IP counts, top IPs, and status codes per domain
- **Global insights** — aggregate summary across all discovered domains
- **PTR / reverse-DNS lookups** for top IPs and error IP/status pairs, with per-run caching
- **Grouped PTR host summaries** — e.g. `*.ahrefs.net`, `*.us-west-2.compute.amazonaws.com`
- **PTR provider summaries** — e.g. `googleusercontent.com`, `amazonaws.com`
- **Optional Org / ISP enrichment** via `ipinfo.io` → `ipwho.is` → `whois` fallback chain
- **Bot detection** — identifies bot/crawler traffic from user-agent patterns
- **Peak burst analysis** — finds the busiest minute in the selected window
- **Archive support** — reads rotated `.gz` logs from `~/logs`
- **Interactive and non-interactive modes** — works from prompts or CLI flags
- **Color-safe output** — respects `NO_COLOR`, `TERM=dumb`, and non-TTY output

---

## Requirements

### Required

- Bash 4+
- `awk` with `mktime()` support
- Access to cPanel user log directories:
  - `/home/USER/access-logs`
  - `/home/USER/access_logs`

### Required for PTR Resolution

At least one of:

- `getent`
- `host`

### Optional (for Org / ISP Enrichment)

- `curl` + outbound HTTPS access
- `jq` for cleaner JSON parsing
- `whois` as a final fallback
- `timeout` for fast failure on slow lookups

Missing enrichment sources will display `-` rather than failing.

---

## Usage
```bash
bash logs-reviewer.sh [OPTIONS]
```

### Options

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

---

## Examples
```bash
# Interactive run
bash logs-reviewer.sh

# Non-interactive, last 2 hours, global summary
bash logs-reviewer.sh -t "2 hours" -g y -i n -a n

# As root, scoped to a specific cPanel user
bash logs-reviewer.sh -u clientusername -t "1 hour" -g y -i n -a n

# Review a specific archived month
bash logs-reviewer.sh -a y --archive-date Feb-2026 --archive-domain example.com
```

---

## Output Sections

| Section | Description |
|---------|-------------|
| Top IPs | Request count, IP, PTR host, Org / ISP |
| Top PTR Hosts | Grouped reverse-DNS hostnames |
| Top PTR Providers | Grouped by provider (e.g. amazonaws.com) |
| Top URLs | Most requested paths |
| HTTP Methods | GET / POST / HEAD breakdown |
| Status Codes | With percentage of total |
| Bots | Detected crawler user-agents |
| Top Referrers | External referrer breakdown |
| Top 4xx URLs | Most frequent client error paths |
| Top 5xx URLs | Most frequent server error paths |
| Top Error IP/Status Pairs | Combined IP + status for error traffic |
| Peak Minute Burst | Highest request volume in a single minute |

---

## PTR and Org Lookup Behavior

**PTR / Host Lookup** (per IP, cached per run):
1. `getent hosts <ip>`
2. `host <ip>` as fallback
3. `-` if no record found

**Org / ISP Lookup** (per IP, cached per run):
1. `ipinfo.io`
2. `ipwho.is`
3. `whois` if installed
4. `-` if all sources fail

An IP may have a valid Org but no PTR record, or the reverse — both are handled independently.

---

## Environment Variables

| Variable | Effect |
|----------|--------|
| `NO_COLOR` | Disables ANSI color output |
| `TERM=dumb` | Disables ANSI styling automatically |
| `IPINFO_TOKEN` | Optional token for authenticated `ipinfo.io` lookups |

Output stays plain text when piped or redirected.

---

## Caveats

- Reverse DNS is optional — many IPs legitimately have no PTR record
- Public IP metadata providers may rate-limit unauthenticated traffic
- PTR enrichment adds latency proportional to the number of unique IPs resolved
- 
---

## License

MIT
