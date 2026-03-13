# cPanel Access Log Reviewer

`cPanel Access Log Reviewer` is a command-line tool for analyzing Apache access logs on cPanel servers. It produces per-domain summaries, highlights suspicious or noisy traffic patterns, and supports both active logs and rotated archive logs.

The main version now lives in the repository root. The recommended entrypoint is the root-level bootstrap script, which stages `runner.sh` and `log_enrich.py` in a temporary directory and executes the tool without leaving an installed copy behind.

## Repository Layout

- `logs-reviewer.sh`: bootstrap entrypoint for local and remote execution
- `runner.sh`: Bash orchestration layer for prompts, source selection, and output flow
- `log_enrich.py`: Python analysis engine for parsing, summarization, and enrichment
- `bash-variant/logs-reviewer.sh`: original Bash-only implementation kept as a fallback variant

## Features

- Per-domain traffic summaries
- Top IP analysis with PTR host and Org / ISP enrichment
- Grouped PTR-host rollups
- Top URLs, methods, status codes, referrers, and error views
- Bot request detection
- Raw-entry inspection for a selected live domain
- Archived log review from `~/logs/*.gz`
- Automatic inclusion of rotated archives when the requested timeframe exceeds active-log coverage
- Compact mode for servers with many domains
- Full summary output for a single selected domain without printing every domain first

## Quick Start

Run the tool directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/WhereAmI14/cPanel-access-log-reviewer/main/logs-reviewer.sh | bash
```

To pass options to the downloaded script, use `bash -s --`:

```bash
curl -fsSL https://raw.githubusercontent.com/WhereAmI14/cPanel-access-log-reviewer/main/logs-reviewer.sh | bash -s -- -t "24 hours" -g y -i n
```

## Local Usage

You can also clone the repo and run it locally on the server as:

```bash
bash logs-reviewer.sh
```

Example with options:

```bash
bash logs-reviewer.sh --threshold 50 -t "24 hours" -g y -i n
```

## Common Examples

Review the last 24 hours without interactive prompts:

```bash
curl -fsSL https://raw.githubusercontent.com/WhereAmI14/cPanel-access-log-reviewer/main/logs-reviewer.sh | \
  bash -s -- -t "24 hours" -g y -i n
```

Print the full summary for one domain only:

```bash
curl -fsSL https://raw.githubusercontent.com/WhereAmI14/cPanel-access-log-reviewer/main/logs-reviewer.sh | \
  bash -s -- -t "24 hours" --full-domain example.com -g n -i n
```

Inspect raw access entries for a single live domain:

```bash
curl -fsSL https://raw.githubusercontent.com/WhereAmI14/cPanel-access-log-reviewer/main/logs-reviewer.sh | \
  bash -s -- -t "24 hours" -i y -d example.com
```

Increase the inline-domain limit before compact mode starts:

```bash
bash logs-reviewer.sh --threshold 50
```

## Options

- `-t`, `--timeframe`: limit analysis to a window such as `"5 minutes"`, `"24 hours"`, or `"all"`.
- `-g`, `--global`: answer the global rollup prompt non-interactively with `y` or `n`.
- `-i`, `--inspect`: answer the raw-entry inspection prompt non-interactively with `y` or `n`.
- `-a`, `--archive`: answer the archived-log review prompt non-interactively with `y` or `n`.
- `--full-domain`: print the complete per-domain summary for a single domain and skip the full multi-domain rollup output.
- `--archive-date`: choose a specific archive period token such as `Feb-2026`.
- `--archive-domain`: choose one archived domain log name for archive inspection.
- `-d`, `--domain`: choose one live domain log name for raw inspect mode.
- `-u`, `--user`: when running as `root`, limit discovery to one cPanel user instead of scanning all users.
- `--threshold`: set the maximum number of domains that will be printed inline before compact mode is enabled.
- `-h`, `--help`: show usage information.

## How Output Works

### Normal Mode

If the number of discovered domains is at or below the configured threshold:

- each domain is printed with its full summary
- an optional global domain rollup can be shown

### Compact Mode

If the number of discovered domains exceeds the configured threshold:

- the terminal shows a domain-level rollup instead of every full summary inline
- the complete per-domain report is written to `~/tmp/logs-reviewer-YYYY-MM-DD-HHMMSS.txt`
- `--full-domain` bypasses the rollup view and prints only the selected domain summary

## Requirements

- `bash`
- `python3`
- access to cPanel Apache log files

The Python helper is standard-library first and does not require extra packages.

If `tldextract` is already installed on the server, it will be used automatically for more accurate registrable-domain grouping in PTR host summaries.

## CI Checks

This repository uses GitHub Actions to run basic quality checks on pushes and pull requests to `dev`.

Current checks include:

- Python linting with `flake8`
- shell script linting with `ShellCheck`
- GitHub Actions workflow validation with `actionlint`
- Bash syntax checks
- Python syntax and CLI smoke checks across Python `3.9` through `3.12`
- SonarQube Cloud analysis

## Bash Variant

The original Bash-only implementation is still available in `bash-variant/README.md`. Keep it as a fallback if you need a pure Bash version or want to compare behavior with the main root-level tool.

## Notes

- The tool reads both standard and SSL access logs for a selected domain.
- When the requested timeframe reaches further back than the active logs cover, the tool can include matching rotated archives automatically.
- If you are piping the bootstrap script into Bash and need to pass options, always use `bash -s -- ...`.
