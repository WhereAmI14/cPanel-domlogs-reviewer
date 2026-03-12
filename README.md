# cPanel Apache Log Analyzer

A CLI tool for reviewing Apache access logs on cPanel servers.

This repository currently contains two script variants:

- `logs-reviewer.sh` - the original analyzer
- `logs-reviewer-ptr.sh` - an enhanced variant with PTR/host enrichment, provider grouping, optional org/ISP lookup, and improved table formatting

Built for real operational use on cPanel/WHM hosting environments.

---

## Script Variants

| Script | Purpose |
|------|-------------|
| `logs-reviewer.sh` | Original log analyzer with per-domain summaries, global insights, archive review, and raw inspection |
| `logs-reviewer-ptr.sh` | Enhanced analyzer that adds PTR lookups, grouped host/provider summaries, `Org / ISP` enrichment, bold table headers, and cleaner summary tables |

If you want the original lightweight behavior, use `logs-reviewer.sh`.

If you want enriched IP reporting, use `logs-reviewer-ptr.sh`.

---

## Features

### Available in Both Scripts

- **Time filtering** - analyze the last N minutes, hours, or days, or all available data
- **Per-domain breakdown** - request counts, unique IP counts, top IPs, and status codes per domain
- **Global insights** - aggregate summary across all discovered domains
- **Bot detection** - identifies bot/crawler traffic from user-agent patterns
- **Peak burst analysis** - finds the busiest minute in the selected window
- **Archive support** - reads rotated `.gz` logs from `~/logs`
- **Interactive and non-interactive modes** - works from prompts or CLI flags
- **Color-safe output** - respects `NO_COLOR`, `TERM=dumb`, and non-TTY output

### Additional Features in `logs-reviewer-ptr.sh`

- **PTR / reverse-DNS lookups** for top IPs and error IP/status pairs
- **Per-run PTR caching** so repeated IPs are not resolved more than once
- **Grouped PTR host summaries** such as `*.ahrefs.net` or `*.us-west-2.compute.amazonaws.com`
- **PTR provider summaries** such as `googleusercontent.com`, `amazonaws.com`, `linodeusercontent.com`
- **Optional `Org / ISP` enrichment** for IPs
- **API fallback chain for org lookup**
  - `ipinfo.io`
  - `ipwho.is`
  - `whois` if available
- **Improved report layout**
  - bold table headers
  - aligned columns
  - explicit `(none)` output for empty sections
  - cleaner bot/referrer/error tables
- **Short network timeouts** for PTR and HTTP-based enrichment

---

## Comparison With the Original Script

Compared with `logs-reviewer.sh`, the PTR variant adds:

- IP-to-hostname resolution in `Top IPs`
- grouped `Top PTR Hosts`
- grouped `Top PTR Providers`
- `Org / ISP` column in IP-based tables
- enriched `Top Error IP/Status Pairs`
- more readable section tables for:
  - bots
  - referrers
  - top 4xx URLs
  - top 5xx URLs
- explicit empty-state output

The core log-discovery, timeframe filtering, archive handling, interactive prompts, and raw log inspection behavior remain aligned with the original script.

---

## Requirements

### Required

- Bash 4+
- `awk` with `mktime()` support
- access to cPanel user log directories:
  - `/home/USER/access-logs`
  - `/home/USER/access_logs`

### Required for PTR Resolution in `logs-reviewer-ptr.sh`

At least one of:

- `getent`
- `host`

### Optional for `Org / ISP` Enrichment in `logs-reviewer-ptr.sh`

- `curl`
- outbound HTTPS access
- `jq` for cleaner JSON parsing
- `whois` as a final fallback if installed
- `timeout` for fast failure on slow lookups

The PTR script works without these optional tools, but missing enrichment sources will display `-`.

---

## Usage

### Original Script

```bash
bash logs-reviewer.sh [OPTIONS]
```

### PTR / Enhanced Script

```bash
bash logs-reviewer-ptr.sh [OPTIONS]
```

Both scripts support the same CLI flags.

### Options

| Flag | Description |
|------|-------------|
| `-t, --timeframe VALUE` | Time window such as `"5 minutes"`, `"2 hours"`, `"7 days"`, or `"all"` |
| `-g, --global y\|n` | Run global insights across all domains |
| `-i, --inspect y\|n` | Inspect raw entries for a single domain |
| `-a, --archive y\|n` | Review archived rotated logs from `~/logs` |
| `--archive-date DATE` | Archive period to inspect, for example `Feb-2026` |
| `--archive-domain NAME` | Domain to inspect in archive mode |
| `-d, --domain NAME` | Domain log name for inspect mode |
| `-u, --user USER` | Read logs from another cPanel user when permitted |
| `-h, --help` | Show help |

---

## Examples

### Interactive Run

```bash
bash logs-reviewer.sh
```

### PTR-Enhanced Run

```bash
bash logs-reviewer-ptr.sh
```

### Non-Interactive Run

```bash
bash logs-reviewer-ptr.sh -t "2 hours" -g y -i n -a n
```

### Root User Scoping

```bash
bash logs-reviewer-ptr.sh -u clientusername -t "1 hour" -g y -i n -a n
```

### Review a Specific Archived Month

```bash
bash logs-reviewer-ptr.sh -a y --archive-date Feb-2026 --archive-domain example.com
```

---

## Example Sections in `logs-reviewer-ptr.sh`

The enhanced script can display sections such as:

- `Top IPs`
- `Top PTR Hosts`
- `Top PTR Providers`
- `Top URLs`
- `HTTP Methods`
- `Status Codes`
- `Bots`
- `Top Referrers`
- `Top 4xx URLs`
- `Top 5xx URLs`
- `Top Error IP/Status Pairs`
- `Peak Minute Burst`

IP-based sections may include:

- `PTR Host`
- `Org / ISP`

Example:

```text
Top IPs
   Count  IP                                      PTR Host                                   Org / ISP
      20  192.250.229.198                         s13602.fra1.stableserver.net               Stablepoint
       6  216.244.66.238                          -                                          Wowrack.com
```

---

## How PTR and Org Lookup Work in the PTR Script

### PTR / Host Lookup

For each unique IP:

1. check the in-memory PTR cache
2. try `getent hosts <ip>`
3. fall back to `host <ip>`
4. if no reverse-DNS name is found, print `-`

### Org / ISP Lookup

For each unique IP:

1. check the in-memory org cache
2. query `ipinfo.io`
3. if that fails, query `ipwho.is`
4. if available, fall back to `whois`
5. if all sources fail, print `-`

This means an IP may have:

- no PTR host
- but still have a valid `Org / ISP`

or the reverse.

---

## Environment

| Variable | Effect |
|----------|--------|
| `NO_COLOR` | Disables ANSI color output |
| `TERM=dumb` | Disables ANSI styling automatically |
| `IPINFO_TOKEN` | Optional token for authenticated `ipinfo.io` lookups in `logs-reviewer-ptr.sh` |

Output stays plain text when piped or redirected.

---

## Caveats

- Reverse DNS is optional. Many IPs legitimately have no PTR record.
- Public IP metadata providers may rate-limit unauthenticated traffic.
- If `ipinfo.io` and `ipwho.is` both fail, `Org / ISP` will show `-`.
- `logs-reviewer-ptr.sh` is more feature-rich but also more complex than the original Bash-only analyzer.

---

## Roadmap

A Python migration plan for the enrichment-heavy logic is tracked in:

- [PYTHON_INTEGRATION_TODO.md](/home/ivanr/live-repos/cpanel-logs/PYTHON_INTEGRATION_TODO.md)

---

## License

MIT
