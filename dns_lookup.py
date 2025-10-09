import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def dns_lookup(fqdn):
    """Perform a DNS lookup for the given FQDN."""
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except Exception as e:
        return fqdn, f"Error: {e}"

def main():
    # Example list of FQDNs
    fqdns = [
        "google.com",
        "openai.com",
        "github.com",
        "nonexistent.domain"
    ]

    # Number of threads to use
    max_workers = 10

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_fqdn = {executor.submit(dns_lookup, fqdn): fqdn for fqdn in fqdns}

        for future in as_completed(future_to_fqdn):
            fqdn, result = future.result()
            print(f"{fqdn}: {result}")

if __name__ == "__main__":
    main()

