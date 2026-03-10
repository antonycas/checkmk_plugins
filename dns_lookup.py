#!/usr/bin/env python3
import csv
import subprocess
import sys
import argparse
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pprint import pprint

def extract_ips_from_nslookup(output):
    """Extract all resolved IP addresses from nslookup output."""
    lines = output.splitlines()
    result_ips = []
    in_answer_section = False

    for line in lines:
        line = line.strip()

        if line.startswith("Name:"):
            in_answer_section = True
            continue

        if in_answer_section and line.startswith("Address:"):
            ip = line.split("Address:")[-1].strip()
            if ip:
                result_ips.append(ip)

    return result_ips


def dns_lookup(fqdn, dns_server):
    """Perform a DNS lookup using nslookup and extract all returned IPs."""
    try:
        result = subprocess.run(
            ["nslookup", fqdn, dns_server],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=5
        )
        output = result.stdout.strip() or result.stderr.strip()
        ips = extract_ips_from_nslookup(output)
        return dns_server, {"fqdn": fqdn, "ips": ips}
    except Exception as e:
        return dns_server, {"fqdn": fqdn, "ips": [], "error": str(e)}


def read_fqdns_from_csv(filename):
    """Read FQDNs and one or more expected IPs from a CSV file."""
    fqdns = []
    with open(filename, newline="") as csvfile:
        reader = csv.reader(csvfile)
        headers = next(reader, None)  # skip header
        for row in reader:
            if not row or not row[0].strip():
                continue
            fqdn = row[0].strip()
            expected_raw = ",".join(row[1:]).strip()
            expected_ips = [ip.strip() for ip in expected_raw.split(",") if ip.strip()]
            fqdns.append({"fqdn": fqdn, "expected_ips": expected_ips})
    return fqdns


def read_dns_servers_from_csv(filename, include_groups):
    """Read DNS servers from a CSV file, filtering by identifier."""
    dns_servers = []
    with open(filename, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            server = row.get("dns_server", "").strip()
            group = row.get("identifier", "").strip().lower()
            if not server or not group:
                continue
            if group in include_groups:
                dns_servers.append(server)
    return dns_servers


def build_allowed_ip_list(fqdns_data):
    """
    Build a flat list of all expected IPs from the CSV (excluding wildcards).
    This list is used for wildcard (*) validation across all FQDNs.
    """
    allowed_ips = []
    for entry in fqdns_data:
        for ip in entry["expected_ips"]:
            if ip != "*" and ip not in allowed_ips:
                allowed_ips.append(ip)
    return allowed_ips


def main():
    parser = argparse.ArgumentParser(description="Checkmk DNS lookup plugin")
    parser.add_argument(
        "-f", "--file",
        dest="csv_filename",
        default="fqdns.csv",
        help="Path to the FQDN CSV file (default: fqdns.csv)"
    )
    parser.add_argument(
        "--dns-file",
        dest="dns_filename",
        default="dns_servers.csv",
        help="Path to the DNS servers CSV file (default: dns_servers.csv)"
    )
    parser.add_argument(
        "--dns-groups",
        dest="dns_groups",
        default="public",
        help="Comma-separated list of DNS server identifiers to include (default: public)"
    )
    parser.add_argument(
        "--ignore-ips",
        dest="ignore_ips",
        default="",
        help="Comma-separated list of IPs to ignore during validation"
    )

    args = parser.parse_args()

    csv_filename = args.csv_filename
    dns_filename = args.dns_filename
    dns_groups = [g.strip().lower() for g in args.dns_groups.split(",") if g.strip()]
    ignore_ips = [ip.strip() for ip in args.ignore_ips.split(",") if ip.strip()]

    # Handle missing files
    if not os.path.isfile(csv_filename):
        print(f"UNKNOWN: CSV file not found at '{csv_filename}' — DNS checks skipped")
        sys.exit(3)
    if not os.path.isfile(dns_filename):
        print(f"UNKNOWN: DNS server file not found at '{dns_filename}' — DNS checks skipped")
        sys.exit(3)

    # Load data
    dns_servers = read_dns_servers_from_csv(dns_filename, dns_groups)
    if not dns_servers:
        print(f"UNKNOWN: No DNS servers found for group(s): {', '.join(dns_groups)}")
        sys.exit(3)

    fqdns_data = read_fqdns_from_csv(csv_filename)
    allowed_ips = build_allowed_ip_list(fqdns_data)

    max_workers = 10
    results = {dns: [] for dns in dns_servers}

    # Perform concurrent lookups
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(dns_lookup, row["fqdn"], dns)
            for row in fqdns_data
            for dns in dns_servers
        ]
        for future in as_completed(futures):
            dns_server, entry = future.result()
            results[dns_server].append(entry)
    pprint(results)
    # Compare results
    critical_issues = []
    for dns_server, lookups in results.items():
        for record in lookups:
            fqdn = record["fqdn"]
            returned_ips = record["ips"]

            # --- Case 1: No IPs at all ---
            if not returned_ips:
                critical_issues.append(f"{dns_server} returned no IP address for {fqdn}")
                continue

            # --- Case 2: Filter ignored IPs ---
            filtered_ips = [ip for ip in returned_ips if ip not in ignore_ips]

            # If all returned IPs are ignored, skip this record (no alert)
            if not filtered_ips and returned_ips:
                continue

            expected_ips = next(
                (item["expected_ips"] for item in fqdns_data if item["fqdn"] == fqdn),
                []
            )

            has_wildcard = "*" in expected_ips

            # --- Wildcard logic ---
            if has_wildcard:
                if allowed_ips and not any(ip in allowed_ips for ip in filtered_ips):
                    critical_issues.append(
                        f"{dns_server} returned {', '.join(filtered_ips)} for {fqdn} "
                        f"(no match in allowed IP list despite wildcard)"
                    )
                continue

            # --- Strict match: all and only expected IPs ---
            if expected_ips and set(filtered_ips) != set(expected_ips):
                missing = set(expected_ips) - set(filtered_ips)
                extra = set(filtered_ips) - set(expected_ips)
                msg_parts = []
                if missing:
                    msg_parts.append(f"missing {', '.join(sorted(missing))}")
                if extra:
                    msg_parts.append(f"unexpected {', '.join(sorted(extra))}")
                detail = "; ".join(msg_parts) if msg_parts else "mismatch"
                critical_issues.append(
                    f"{dns_server} returned {', '.join(filtered_ips)} for {fqdn} ({detail})"
                )

    # --- Checkmk-compatible output ---
    ignore_note = f" Ignoring IPs: {', '.join(ignore_ips)}." if ignore_ips else ""

    if critical_issues:
        print(f"CRITICAL: Unexpected or missing addresses returned, see detailed output for more information.{ignore_note}")
        for issue in critical_issues:
            print(f"- {issue}")
        sys.exit(2)
    else:
        print(f"OK: All DNS lookups returned expected results.{ignore_note}")
        sys.exit(0)


if __name__ == "__main__":
    main()

