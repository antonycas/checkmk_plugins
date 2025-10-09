#!/usr/bin/env python3
import subprocess
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

        # Once we hit a 'Name:' line, we know we're now in the answer section
        if line.startswith("Name:"):
            in_answer_section = True
            continue

        # Capture 'Address:' lines *after* the answer section starts
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
            universal_newlines=True,  # Python 3.6-compatible text mode
            timeout=5
        )
        output = result.stdout.strip() or result.stderr.strip()
        ips = extract_ips_from_nslookup(output)
        return dns_server, {"fqdn": fqdn, "ips": ips}

    except Exception as e:
        return dns_server, {"fqdn": fqdn, "ips": [], "error": str(e)}


def main():
    # Domains and DNS servers to test
    fqdns = ["google.com", "openai.com", "github.com", "nonexistent.domain"]
    dns_servers = ["8.8.8.8", "1.1.1.1"]
    max_workers = 10

    # Results structure: {dns_server: [ {fqdn, ips}, ... ]}
    results = {dns: [] for dns in dns_servers}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(dns_lookup, fqdn, dns)
            for fqdn in fqdns
            for dns in dns_servers
        ]

        for future in as_completed(futures):
            dns_server, entry = future.result()
            results[dns_server].append(entry)

    # Pretty output
    for dns_server, lookups in results.items():
        print(f"\n=== Results from DNS server {dns_server} ===")
        for record in lookups:
            if record["ips"]:
                print(f"{record['fqdn']}: {', '.join(record['ips'])}")
            else:
                print(f"{record['fqdn']}: No result")

    return results


if __name__ == "__main__":
    main()

