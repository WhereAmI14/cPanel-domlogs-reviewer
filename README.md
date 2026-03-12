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
