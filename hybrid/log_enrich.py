#!/usr/bin/env python3

import argparse
import collections
import json
import os
import re
import socket
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

try:
    import tldextract
except Exception:
    tldextract = None


LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}|-) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)"'
)
APACHE_TIME_RE = re.compile(
    r"^(?P<day>\d{1,2})/(?P<mon>[A-Z][a-z]{2})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?: (?P<tz>[+-]\d{4}))?$"
)
BOT_RE = re.compile(r"bot|crawl|spider", re.I)
MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

PTR_CACHE = {}
ORG_CACHE = {}


def use_color():
    return (
        os.isatty(1)
        and not os.environ.get("NO_COLOR")
        and os.environ.get("TERM") != "dumb"
    )


USE_COLOR = use_color()
GREEN = "\033[32;1m" if USE_COLOR else ""
YELLOW = "\033[33;1m" if USE_COLOR else ""
CYAN = "\033[36;1m" if USE_COLOR else ""
RED = "\033[31;1m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""
DEF = "\033[0m" if USE_COLOR else ""
PTR_TIMEOUT = 2.0
HTTP_TIMEOUT = 3.0


def print_bold(text):
    if USE_COLOR:
        print(f"{BOLD}{text}{DEF}")
    else:
        print(text)


def print_empty():
    print("  (none)")


def colorize_status(status):
    if not USE_COLOR or not status or not status[0].isdigit():
        return status
    table = {"2": GREEN, "3": CYAN, "4": YELLOW, "5": RED}
    if status[0] in table:
        return f"{table[status[0]]}{status}{DEF}"
    return status


def iter_lines(path):
    if path:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                yield line
        return

    for line in sys.stdin:
        yield line


def parse_apache_epoch(time_value):
    match = APACHE_TIME_RE.match(time_value)
    if not match:
        return None

    month = MONTHS.get(match.group("mon"))
    if not month:
        return None

    tz_raw = match.group("tz") or "+0000"
    sign = -1 if tz_raw.startswith("-") else 1
    tz_offset = timedelta(
        hours=int(tz_raw[1:3]),
        minutes=int(tz_raw[3:5]),
    )
    tzinfo = timezone(sign * tz_offset)

    try:
        timestamp = datetime(
            int(match.group("year")),
            month,
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            tzinfo=tzinfo,
        )
    except ValueError:
        return None

    return int(timestamp.timestamp())


def parse_log_line(line):
    line = line.rstrip("\n")
    match = LOG_RE.match(line)
    if not match:
        return None

    request_parts = match.group("request").split()
    method = request_parts[0] if len(request_parts) >= 1 else "-"
    url = request_parts[1] if len(request_parts) >= 2 else "-"
    size_raw = match.group("size")
    try:
        size = int(size_raw)
    except ValueError:
        size = 0

    time_value = match.group("time")
    return {
        "epoch": parse_apache_epoch(time_value),
        "ip": match.group("ip"),
        "status": match.group("status"),
        "url": url,
        "method": method,
        "bytes": size,
        "referrer": match.group("referrer"),
        "ua": match.group("ua"),
        "time": time_value,
        "raw": line,
    }


def summarize_stream(path, cutoff_epoch):
    summary = {
        "total_requests": 0,
        "total_bytes": 0,
        "ip_counts": collections.Counter(),
        "status_counts": collections.Counter(),
        "url_counter": collections.Counter(),
        "method_counter": collections.Counter(),
        "ref_counter": collections.Counter(),
        "top4xx": collections.Counter(),
        "top5xx": collections.Counter(),
        "minute_counter": collections.Counter(),
        "bot_counter": collections.Counter(),
        "bot_requests": 0,
        "error_pair_counts": collections.Counter(),
    }

    for line in iter_lines(path):
        record = parse_log_line(line)
        if not record:
            continue
        if cutoff_epoch and (record["epoch"] is None or record["epoch"] < cutoff_epoch):
            continue

        summary["total_requests"] += 1
        summary["total_bytes"] += record["bytes"]
        summary["ip_counts"][record["ip"]] += 1
        summary["status_counts"][record["status"]] += 1
        summary["url_counter"][record["url"]] += 1
        summary["method_counter"][record["method"]] += 1

        if record["time"]:
            summary["minute_counter"][record["time"][:17]] += 1
        if record["referrer"] != "-":
            summary["ref_counter"][record["referrer"]] += 1

        status = record["status"]
        if status.startswith("4"):
            summary["top4xx"][record["url"]] += 1
            summary["error_pair_counts"][(record["ip"], status)] += 1
        elif status.startswith("5"):
            summary["top5xx"][record["url"]] += 1
            summary["error_pair_counts"][(record["ip"], status)] += 1

        if BOT_RE.search(record["ua"]):
            summary["bot_counter"][record["ua"]] += 1
            summary["bot_requests"] += 1

    return summary


def print_filtered_raw(path, cutoff_epoch):
    for line in iter_lines(path):
        if not cutoff_epoch:
            sys.stdout.write(line)
            continue

        record = parse_log_line(line)
        if not record:
            continue
        if record["epoch"] is not None and record["epoch"] >= cutoff_epoch:
            sys.stdout.write(line)


def print_oldest_epoch(path):
    oldest = 0
    for line in iter_lines(path):
        record = parse_log_line(line)
        if not record or record["epoch"] is None:
            continue
        if oldest == 0 or record["epoch"] < oldest:
            oldest = record["epoch"]
    print(oldest)


def resolve_ptr(ip):
    if ip in PTR_CACHE:
        return PTR_CACHE[ip]

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(PTR_TIMEOUT)
        host = socket.gethostbyaddr(ip)[0]
    except Exception:
        host = "-"
    finally:
        socket.setdefaulttimeout(old_timeout)

    PTR_CACHE[ip] = host
    return host


def http_json(url):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "logs-reviewer-hybrid/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None


def resolve_org(ip):
    token = os.environ.get("IPINFO_TOKEN", "")
    if ip in ORG_CACHE:
        return ORG_CACHE[ip]

    org = "-"
    ipinfo_url = f"https://ipinfo.io/{urllib.parse.quote(ip)}/json"
    if token:
        ipinfo_url += f"?token={urllib.parse.quote(token)}"

    data = http_json(ipinfo_url)
    if isinstance(data, dict):
        org = data.get("org") or "-"
        org = re.sub(r"^AS\d+\s+", "", org)

    if org in ("", "-", None, "null"):
        data = http_json(f"https://ipwho.is/{urllib.parse.quote(ip)}")
        if isinstance(data, dict):
            connection = data.get("connection") or {}
            org = connection.get("org") or connection.get("isp") or "-"

    if org in ("", None, "null"):
        org = "-"

    ORG_CACHE[ip] = org
    return org


def registrable_domain(host):
    if host == "-":
        return host

    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return host

    if tldextract is not None:
        extracted = tldextract.extract(host)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"

    second_level_suffixes = {"ac", "co", "com", "edu", "gov", "net", "org"}
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in second_level_suffixes:
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


def group_ptr_host_family(host):
    if host == "-":
        return host

    parts = host.split(".")
    root = registrable_domain(host)
    first = parts[0] if parts else ""
    if len(parts) >= 3 and root not in ("", "-", host):
        return "*." + root
    if len(parts) == 2 and root not in ("", "-", host) and (any(ch.isdigit() for ch in first) or "-" in first):
        return "*." + root
    return host


def print_counted_table(rows, value_label, max_len):
    if not rows:
        print_empty()
        return
    print_bold(f"{'Count':>8}  {value_label}")
    for value, count in rows:
        value = str(value)
        if max_len > 3 and len(value) > max_len:
            value = value[: max_len - 3] + "..."
        print(f"{count:8d}  {value}")


def print_top_ips(ip_counts):
    rows = ip_counts.most_common(10)
    print_bold(f"{'Count':>8}  {'IP':<39} {'PTR Host':<42} Org / ISP")
    for ip, count in rows:
        host = resolve_ptr(ip)
        org = resolve_org(ip)
        print(f"{count:8d}  {ip:<39} {host:<42} {org}")


def print_grouped_ptr(ip_counts, label):
    grouped = collections.defaultdict(lambda: {"requests": 0, "ips": set()})
    for ip, count in ip_counts.items():
        host = resolve_ptr(ip)
        key = group_ptr_host_family(host)
        grouped[key]["requests"] += count
        grouped[key]["ips"].add(ip)

    rows = sorted(
        (
            (data["requests"], len(data["ips"]), key)
            for key, data in grouped.items()
        ),
        key=lambda item: (-item[0], -item[1], item[2]),
    )[:10]

    if not rows:
        print_empty()
        return

    print_bold(f"{'Requests':>8}  {'Unique IPs':>9}  {label}")
    for requests, ips, key in rows:
        print(f"{requests:8d}  {ips:9d}  {key}")


def print_status_codes(status_counts, total_requests):
    rows = sorted(status_counts.items(), key=lambda item: (-item[1], item[0]))
    if not rows:
        print_empty()
        return

    print_bold(f"{'Count':>8}  {'Percent':>7}  Status")
    for status, count in rows:
        pct = (count * 100.0 / total_requests) if total_requests else 0.0
        print(f"{count:8d}  {pct:6.2f}%  {colorize_status(status)}")


def print_error_pairs(error_pair_counts):
    rows = error_pair_counts.most_common(10)
    if not rows:
        print_empty()
        return

    print_bold(
        f"{'Count':>8}  {'IP':<39} {'PTR Host':<40} {'Org / ISP':<22} Status")
    for (ip, status), count in rows:
        host = resolve_ptr(ip)
        org = resolve_org(ip)
        print(f"{count:8d}  {ip:<39} {host:<40} {org:<22} {colorize_status(status)}")


def run_summary(args):
    summary = summarize_stream(args.input_file, args.cutoff_epoch)
    total_requests = summary["total_requests"]
    if not total_requests:
        if args.quiet_empty:
            return 3
        print()
        print("No data for selected timeframe")
        return 0

    total_bytes = summary["total_bytes"]
    unique_ips = len(summary["ip_counts"])
    avg_bytes = total_bytes / total_requests if total_requests else 0.0

    print()
    print(f"{GREEN}{args.heading}{DEF}")
    print(f"Requests: {total_requests}")
    print(f"Unique IPs: {unique_ips}")
    print(f"Transferred bytes: {total_bytes}")
    print(f"Average response bytes: {avg_bytes:.2f}")

    print()
    print(f"{GREEN}Top IPs{DEF}")
    print_top_ips(summary["ip_counts"])

    print()
    print(f"{GREEN}Top PTR Hosts{DEF}")
    print_grouped_ptr(summary["ip_counts"], "PTR Host Group")

    print()
    print(f"{GREEN}Top URLs{DEF}")
    print_counted_table(summary["url_counter"].most_common(10), "URL", 110)

    print()
    print(f"{GREEN}HTTP Methods{DEF}")
    print_counted_table(summary["method_counter"].most_common(), "Method", 40)

    print()
    print(f"{GREEN}Status Codes{DEF}")
    print_status_codes(summary["status_counts"], total_requests)

    print()
    print(f"{GREEN}Bots{DEF}")
    bot_pct = (summary["bot_requests"] * 100.0 / total_requests) if total_requests else 0.0
    print(f"Bot requests: {summary['bot_requests']} ({bot_pct:.2f}%)")
    print_counted_table(summary["bot_counter"].most_common(10), "User Agent", 110)

    print()
    print(f"{GREEN}Top Referrers{DEF}")
    print_counted_table(summary["ref_counter"].most_common(10), "Referrer", 110)

    print()
    print(f"{GREEN}Top 4xx URLs{DEF}")
    print_counted_table(summary["top4xx"].most_common(10), "URL", 110)

    print()
    print(f"{GREEN}Top 5xx URLs{DEF}")
    print_counted_table(summary["top5xx"].most_common(10), "URL", 110)

    print()
    print(f"{GREEN}Top Error IP/Status Pairs{DEF}")
    print_error_pairs(summary["error_pair_counts"])

    print()
    print(f"{GREEN}Peak Minute Burst{DEF}")
    if summary["minute_counter"]:
        minute, count = max(
            summary["minute_counter"].items(),
            key=lambda item: (item[1], item[0]),
        )
        print(f"{minute} ({count} requests)")
    else:
        print("n/a")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("summary", "oldest-epoch", "filter-raw"),
        default="summary",
    )
    parser.add_argument("--input-file")
    parser.add_argument("--heading")
    parser.add_argument("--cutoff-epoch", type=int, default=0)
    parser.add_argument("--quiet-empty", action="store_true")
    args = parser.parse_args()

    if args.mode == "summary":
        if not args.heading:
            parser.error("--heading is required in summary mode")
        raise SystemExit(run_summary(args))

    if args.mode == "oldest-epoch":
        print_oldest_epoch(args.input_file)
        return

    print_filtered_raw(args.input_file, args.cutoff_epoch)


if __name__ == "__main__":
    main()
