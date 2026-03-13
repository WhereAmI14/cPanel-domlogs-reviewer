# Hybrid Version

This is the multi-file hybrid version of the cPanel access-log reviewer.

The goal of this version is:

- keep the operator workflow simple
- preserve the `curl | bash` style entrypoint
- avoid leaving installed files on the server
- move the heavy parsing and reporting logic out of Bash and into Python

## What The Tool Does

The hybrid tool reviews Apache/cPanel access logs and produces:

- per-domain request summaries
- PTR/host and Org/ISP enrichment for top IPs
- grouped PTR-host summaries
- status-code, bot, referrer, URL, and error summaries
- raw-entry inspection for a selected domain
- archive review from `~/logs/*.gz`
- automatic active-plus-archive source selection when the requested timeframe exceeds active-log coverage

On servers with many domains, it can switch to compact mode:

- the terminal shows a domain-level summary instead of every domain inline
- the full per-domain report is written to a file in `/tmp`

## Files

### `logs-reviewer-hybrid.sh`

Bootstrap entrypoint for the hybrid version inside this directory.

Purpose:

- create a temporary working directory
- copy or download the runtime files into it
- execute the runner
- clean up on exit

This is the canonical bootstrap entrypoint for the hybrid version.

### `runner.sh`

Bash orchestration layer.

Purpose:

- parse CLI flags
- handle interactive prompts
- discover whether active logs and archives should be used
- stream active and archive log data
- coordinate compact mode
- call the Python helper for summaries, filtering, archive metadata, and rollups

This file owns the operator flow, not the heavy analytics logic.

### `log_enrich.py`

Python analysis and rendering engine.

Purpose:

- discover base logs and archive logs
- parse Apache log lines
- filter by cutoff time
- compute per-domain summary metrics
- render full summaries and domain-level rollups
- resolve PTR hostnames
- resolve Org/ISP metadata
- group PTR hosts for cleaner output

This file is the main logic engine for the hybrid version.

## Recommended Entry Point

The canonical public command is:

```bash
curl -fsSL https://raw.githubusercontent.com/WhereAmI14/cPanel-domlogs-reviewer/dev/hybrid/logs-reviewer-hybrid.sh | bash
```

To pass options to the downloaded script:

```bash
curl -fsSL https://raw.githubusercontent.com/WhereAmI14/cPanel-domlogs-reviewer/dev/hybrid/logs-reviewer-hybrid.sh | \
  bash -s -- --threshold 50 -t "24 hours" -g y -i n
```

## Local Usage

Run from the repository root:

```bash
bash hybrid/logs-reviewer-hybrid.sh
```

With options:

```bash
bash hybrid/logs-reviewer-hybrid.sh --threshold 50 -t "24 hours" -g y -i n
```

Target one domain for a full summary during compact mode:

```bash
curl -fsSL https://raw.githubusercontent.com/WhereAmI14/cPanel-domlogs-reviewer/dev/hybrid/logs-reviewer-hybrid.sh | \
  bash -s -- -t "24 hours" --full-domain build.whyicantuse.info -g n -i n
```

## Important Options

`runner.sh` currently supports:

- `-t`, `--timeframe`: limit analysis to a window such as `"5 minutes"`, `"24 hours"`, or `"all"`.
- `-g`, `--global`: answer the global rollup prompt non-interactively with `y` or `n`.
- `-i`, `--inspect`: answer the raw-entry inspection prompt non-interactively with `y` or `n`.
- `-a`, `--archive`: answer the archived-log review prompt non-interactively with `y` or `n`.
- `--full-domain`: print the complete summary block for one domain even when compact mode is active.
- `--archive-date`: choose a specific archive period token such as `Feb-2026`.
- `--archive-domain`: choose one archived domain log name for archive inspection.
- `-d`, `--domain`: choose one live domain log name for raw inspect mode.
- `-u`, `--user`: as root, limit discovery to one cPanel user instead of scanning all users.
- `--threshold`: control when compact mode starts by setting the max number of inline domain summaries.

Example:

```bash
bash hybrid/logs-reviewer-hybrid.sh --threshold 50
```

## Output Model

### Normal Mode

If the number of discovered domains is at or below the threshold:

- each domain is printed inline with its full summary
- an optional domain-level global summary can be shown

### Compact Mode

If the number of discovered domains exceeds the threshold:

- the terminal shows a domain-level summary
- the full per-domain report is written to `/tmp/logs-reviewer-YYYY-MM-DD-HHMMSS.txt`
- the terminal tells you how to rerun with a higher threshold

## Python Compatibility

`log_enrich.py` is written to work with Python 3.9 through 3.12.

It is standard-library first. No extra packages are required.

If `tldextract` is already installed on the server, the helper will use it automatically for better registrable-domain extraction when grouping PTR hosts.
