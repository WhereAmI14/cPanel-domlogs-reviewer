#!/usr/bin/env python3

import argparse
import collections
import json
import os
import re
import socket
import urllib.parse
import urllib.request


LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}|-) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)"'
)

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


def parse_records(path):
    records = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            match = LOG_RE.match(line)
            if not match:
                continue

            request_parts = match.group("request").split()
            method = request_parts[0] if len(request_parts) >= 1 else "-"
            url = request_parts[1] if len(request_parts) >= 2 else "-"
            size_raw = match.group("size")
            try:
                size = int(size_raw)
            except ValueError:
                size = 0

            records.append(
                {
                    "ip": match.group("ip"),
                    "status": match.group("status"),
                    "url": url,
                    "method": method,
                    "bytes": size,
                    "referrer": match.group("referrer"),
                    "ua": match.group("ua"),
                    "time": match.group("time"),
                }
            )
    return records


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


def suffix_wildcard(host, keep_labels):
    parts = host.split(".")
    if len(parts) <= keep_labels:
        return host
    return "*." + ".".join(parts[-keep_labels:])


def group_ptr_host_family(host):
    if host == "-":
        return host
    if host.endswith(".bc.googleusercontent.com"):
        return suffix_wildcard(host, 3)
    if host.endswith(".static.cloudzy.com"):
        return suffix_wildcard(host, 3)
    if host.endswith(".fra1.stableserver.net") or host.endswith(".stableserver.net"):
        return suffix_wildcard(host, 3)
    if host.endswith(".compute.amazonaws.com"):
        return suffix_wildcard(host, 4)

    parts = host.split(".")
    first = parts[0] if parts else ""
    if len(parts) >= 4:
        return suffix_wildcard(host, 2)
    if len(parts) == 3 and (any(ch.isdigit() for ch in first) or "-" in first):
        return suffix_wildcard(host, 2)
    return host


def bucket_provider(host):
    if host == "-":
        return host
    if host.endswith(".bc.googleusercontent.com") or host.endswith(".googleusercontent.com"):
        return "googleusercontent.com"
    if host.endswith(".compute.amazonaws.com") or host.endswith(".amazonaws.com"):
        return "amazonaws.com"
    if host.endswith(".colocrossing.com"):
        return "colocrossing.com"
    if host.endswith(".cloudflare.com"):
        return "cloudflare.com"
    if host.endswith(".digitalocean.com"):
        return "digitalocean.com"
    if host.endswith(".linodeusercontent.com"):
        return "linodeusercontent.com"
    return host


def print_counted_table(rows, value_label, max_len):
    if not rows:
        print_empty()
        return
    print_bold(f"{'Count':>8}  {value_label}")
    for count, value in rows:
        value = str(value)
        if max_len > 3 and len(value) > max_len:
            value = value[: max_len - 3] + "..."
        print(f"{count:8d}  {value}")


def print_top_ips(records):
    counts = collections.Counter(record["ip"] for record in records)
    rows = counts.most_common(10)
    print_bold(f"{'Count':>8}  {'IP':<39} {'PTR Host':<42} Org / ISP")
    for ip, count in rows:
        host = resolve_ptr(ip)
        org = resolve_org(ip)
        print(f"{count:8d}  {ip:<39} {host:<42} {org}")


def print_grouped_ptr(records, mode, label):
    ip_counts = collections.Counter(record["ip"] for record in records)
    grouped = collections.defaultdict(lambda: {"requests": 0, "ips": set()})
    for ip, count in ip_counts.items():
        host = resolve_ptr(ip)
        if mode == "provider":
            key = bucket_provider(host)
        else:
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


def print_status_codes(records):
    counts = collections.Counter(record["status"] for record in records)
    rows = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    if not rows:
        print_empty()
        return

    total = len(records)
    print_bold(f"{'Count':>8}  {'Percent':>7}  Status")
    for status, count in rows:
        pct = (count * 100.0 / total) if total else 0.0
        print(f"{count:8d}  {pct:6.2f}%  {colorize_status(status)}")


def print_error_pairs(records):
    counts = collections.Counter(
        (record["ip"], record["status"])
        for record in records
        if record["status"].startswith(("4", "5"))
    )
    rows = counts.most_common(10)
    if not rows:
        print_empty()
        return

    print_bold(f"{'Count':>8}  {'IP':<39} {'PTR Host':<40} {'Org / ISP':<22} Status")
    for (ip, status), count in rows:
        host = resolve_ptr(ip)
        org = resolve_org(ip)
        print(f"{count:8d}  {ip:<39} {host:<40} {org:<22} {colorize_status(status)}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-file", required=True)
    parser.add_argument("--heading", required=True)
    args = parser.parse_args()

    records = parse_records(args.input_file)
    if not records:
        print()
        print("No data for selected timeframe")
        return

    total_requests = len(records)
    unique_ips = len({record["ip"] for record in records})
    total_bytes = sum(record["bytes"] for record in records)
    avg_bytes = (total_bytes / total_requests) if total_requests else 0.0

    bot_records = [record for record in records if re.search(r"bot|crawl|spider", record["ua"], re.I)]
    bot_counter = collections.Counter(record["ua"] for record in bot_records)
    ref_counter = collections.Counter(record["referrer"] for record in records if record["referrer"] != "-")
    top4xx = collections.Counter(record["url"] for record in records if record["status"].startswith("4"))
    top5xx = collections.Counter(record["url"] for record in records if record["status"].startswith("5"))
    url_counter = collections.Counter(record["url"] for record in records)
    method_counter = collections.Counter(record["method"] for record in records)
    minute_counter = collections.Counter(record["time"][:17] for record in records if record["time"])

    print()
    print(f"{GREEN}{args.heading}{DEF}")
    print(f"Requests: {total_requests}")
    print(f"Unique IPs: {unique_ips}")
    print(f"Transferred bytes: {total_bytes}")
    print(f"Average response bytes: {avg_bytes:.2f}")

    print()
    print(f"{GREEN}Top IPs{DEF}")
    print_top_ips(records)

    print()
    print(f"{GREEN}Top PTR Hosts{DEF}")
    print_grouped_ptr(records, "host", "PTR Host Group")

    print()
    print(f"{GREEN}Top PTR Providers{DEF}")
    print_grouped_ptr(records, "provider", "PTR Provider")

    print()
    print(f"{GREEN}Top URLs{DEF}")
    print_counted_table(url_counter.most_common(10), "URL", 110)

    print()
    print(f"{GREEN}HTTP Methods{DEF}")
    print_counted_table(method_counter.most_common(), "Method", 40)

    print()
    print(f"{GREEN}Status Codes{DEF}")
    print_status_codes(records)

    print()
    print(f"{GREEN}Bots{DEF}")
    bot_pct = (len(bot_records) * 100.0 / total_requests) if total_requests else 0.0
    print(f"Bot requests: {len(bot_records)} ({bot_pct:.2f}%)")
    print_counted_table(bot_counter.most_common(10), "User Agent", 110)

    print()
    print(f"{GREEN}Top Referrers{DEF}")
    print_counted_table(ref_counter.most_common(10), "Referrer", 110)

    print()
    print(f"{GREEN}Top 4xx URLs{DEF}")
    print_counted_table(top4xx.most_common(10), "URL", 110)

    print()
    print(f"{GREEN}Top 5xx URLs{DEF}")
    print_counted_table(top5xx.most_common(10), "URL", 110)

    print()
    print(f"{GREEN}Top Error IP/Status Pairs{DEF}")
    print_error_pairs(records)

    print()
    print(f"{GREEN}Peak Minute Burst{DEF}")
    if minute_counter:
        minute, count = max(minute_counter.items(), key=lambda item: (item[1], item[0]))
        print(f"{minute} ({count} requests)")
    else:
        print("n/a")


if __name__ == "__main__":
    main()
