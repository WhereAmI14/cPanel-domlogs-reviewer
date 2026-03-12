# Hybrid Multi-File Prototype

This directory now uses a temp-directory bootstrap model instead of a single large Bash file.

## Files

- `logs-reviewer-hybrid.sh`
  - public bootstrap entrypoint
- `runner.sh`
  - Bash orchestration layer
- `log_enrich.py`
  - Python enrichment and report rendering

## Design

Goal:

- keep the user-facing model close to `curl | bash`
- avoid keeping permanent files on the server
- split the logic into maintainable files

How it works:

1. the bootstrap script creates a temp directory with `mktemp -d`
2. it copies or downloads `runner.sh` and `log_enrich.py`
3. it executes the runner from that temp directory
4. it removes the temp directory on exit

## Invocation

### Local repository execution

```bash
bash hybrid/logs-reviewer-hybrid.sh -t "1 hour" -g y -i n
```

### Remote bootstrap execution

```bash
curl -fsSL https://your-url/hybrid/logs-reviewer-hybrid.sh | \
  bash -s -- --base-url https://your-url/hybrid -t "1 hour" -g y -i n
```

If you prefer, you can also export the base URL:

```bash
HYBRID_BASE_URL="https://your-url/hybrid" \
curl -fsSL https://your-url/hybrid/logs-reviewer-hybrid.sh | \
  bash -s -- -t "1 hour" -g y -i n
```

## Bootstrap Options

- `--base-url URL`
  - remote base used to download `runner.sh` and `log_enrich.py`
- `--keep-temp`
  - keep the temp working directory for debugging
- `-h`, `--help`
  - show bootstrap help

All other arguments are forwarded to `runner.sh`.

## Runner Scope

Included in this prototype:

- timeframe filtering
- per-domain summaries
- global summary
- automatic active-plus-archive source selection when the requested window exceeds active coverage
- archive review
- archived raw entry inspection
- raw inspection for one domain
- Python-rendered enriched tables

Not included yet:

- exact output parity with `logs-reviewer-ptr.sh`

## Python Compatibility

`log_enrich.py` is intentionally standard-library only.

Why:

- easier rollout across servers
- no required `pip install`
- better compatibility across Python 3.9 through 3.12

The helper currently uses:

- `argparse`
- `collections`
- `json`
- `re`
- `socket`
- `urllib.request`

Optional future pip modules can still be added later, but they are not required for this prototype.

If `tldextract` is installed, `log_enrich.py` will use it automatically for better registrable-domain extraction when grouping PTR hosts and providers.
