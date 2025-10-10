#!/usr/bin/env python3
import csv
import subprocess
import sys
import argparse
import os
from concurrent.futures import ThreadPoolExecutor, as_completed


def extract_ips_from_nslookup(output):
    """
    Extract all resolved IP addresses from nslookup output.
    Ignores the resolver information section and captures all 'Address:' lines
    that appear after the first 'Name:' line.
    """
    lines = output.splitlines()
    result_ips = []
    in_answer_section = False

    for line in lines:
        line = line.strip()

        # Detect start of answer section
        if line.startswith("Name:"):
            in_answer_section = True
            continue

        # Capture IPs after 'Name:' appears
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
            universal_newlines=True,  # Python 3.6+ compatible
            timeout=5
        )
        output = result.stdout.strip() or result.stderr.strip()
        ips = extract_ips_from_nslookup(output)
        return dns_server, {"fqdn": fqdn, "ips": ips}

    except Exception as e:
        return dns_server, {"fqdn": fqdn, "ips": [], "error": str(e)}


def read_fqdns_from_csv(filename):
    """
    Read FQDNs and one or more expected IPs from a CSV file.
    This version is robust to unquoted multiple commas in the expected_ip column.
    """
    fqdns = []
    with open(filename, newline="") as csvfile:
        reader = csv.reader(csvfile)
        headers = next(reader, None)  # skip header
        for row in reader:
            if not row or not row[0].strip():
                continue
            fqdn = row[0].strip()
            # Join remaining columns in case multiple expected IPs aren't quoted
            expected_raw = ",".join(row[1:]).strip()
            expected_ips = [ip.strip() for ip in expected_raw.split(",") if ip.strip()]
            fqdns.append({"fqdn": fqdn, "expected_ips": expected_ips})
    return fqdns


def main():
    # --- Parse command-line arguments ---
    parser = argparse.ArgumentParser(description="Checkmk DNS lookup plugin")
    parser.add_argument(
        "-f", "--file",
        dest="csv_filename",
        default="fqdns.csv",
        help="Path to the FQDN CSV file (default: fqdns.csv)"
    )
    args = parser.parse_args()

    csv_filename = args.csv_filename

    # If the CSV file is missing, exit UNKNOWN (code 3)
    if not os.path.isfile(csv_filename):
        print(f"UNKNOWN: CSV file not found at '{csv_filename}' — DNS checks skipped")
        sys.exit(3)

    # DNS servers to query
    dns_servers = ["8.8.8.8", "1.1.1.1"]
    max_workers = 10

    fqdns_data = read_fqdns_from_csv(csv_filename)
    results = {dns: [] for dns in dns_servers}

    # Perform concurrent DNS lookups
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(dns_lookup, row["fqdn"], dns)
            for row in fqdns_data
            for dns in dns_servers
        ]

        for future in as_completed(futures):
            dns_server, entry = future.result()
            results[dns_server].append(entry)

    # Compare results
    critical_issues = []
    for dns_server, lookups in results.items():
        for record in lookups:
            fqdn = record["fqdn"]
            returned_ips = record["ips"]

            # Get expected IPs for this fqdn
            expected_ips = next(
                (item["expected_ips"] for item in fqdns_data if item["fqdn"] == fqdn),
                []
            )

            # Mark critical if no IPs returned at all
            if not returned_ips:
                critical_issues.append(
                    f"{dns_server} returned no IP address for {fqdn}"
                )
                continue

            # Mark critical if none of the expected IPs appear in results
            if expected_ips and not any(ip in returned_ips for ip in expected_ips):
                critical_issues.append(
                    f"{dns_server} returned {', '.join(returned_ips)} for {fqdn} "
                    f"(expected one of {', '.join(expected_ips)})"
                )

    # --- Checkmk-compatible output ---
    if critical_issues:
        print("CRITICAL: Unexpected or missing addresses returned")
        for issue in critical_issues:
            print(f"- {issue}")
        sys.exit(2)
    else:
        print("OK: All DNS lookups returned expected results")
        sys.exit(0)


if __name__ == "__main__":
    main()

