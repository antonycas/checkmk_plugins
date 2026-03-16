#!/usr/bin/env python3

import argparse
import json
import sys
import os.path
import requests
import re
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, date

parser = argparse.ArgumentParser()
parser.add_argument('-s', '--service', required=True, help='Azure Service Name.')
parser.add_argument('-f', '--file', required=True, help='JSON file containing expected ips.')
args = parser.parse_args()

if os.path.isfile(args.file):
    try:
        with open(args.file) as f:
            js = json.load(f)
    except Exception as ex:
        print(f"UNKNONW: Unable to open {args.file}. {ex}")
        sys.exit(3)
else:
    print(f"UNKNOWN: Cannot locate {args.file}.")
    sys.exit(3)
try:
    expected_addresses = js[args.service]
except Exception as ex:
    print(f"UNKNOWN: No data in {args.file} for {args.service}")
    sys.exit(3)

HEADERS = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
DOWNLOAD_PAGES = [
    "https://www.microsoft.com/en-us/download/details.aspx?id=56519",
    "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519",
]
JSON_URL_REGEX = re.compile(
    r"https://download\.microsoft\.com/download/[^\s\"'<>]+/ServiceTags_Public_\d{8}\.json",
    re.IGNORECASE,
)

def fetch_text(url: str, timeout: int = 30) -> str:
    resp = requests.get(url, headers=HEADERS, timeout=timeout)
    resp.raise_for_status()
    return resp.text

def get_latest_json_url() -> str:
    """
    Discover the current ServiceTags_Public_YYYYMMDD.json URL by scanning
    the official Microsoft download HTML for the direct download link.
    """
    for page_url in DOWNLOAD_PAGES:
        try:
            html = fetch_text(page_url)
        except Exception as exc:
            print(f"Warning: failed to fetch {page_url}: {exc}")
            continue

        match = JSON_URL_REGEX.search(html)
        if match:
            return match.group(0)

        # Fallback: sometimes HTML entities or escaping can interfere
        # so search all matches and pick the first plausible one.
        matches = JSON_URL_REGEX.findall(html)
        if matches:
            return matches[0]


#link = https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20260302.json
link = get_latest_json_url()
print(link)
# Download file and select values
file_download = requests.get(link, headers=HEADERS)
js = json.loads(file_download.content)
#todays_js = [ v for v in js['values'] if v['id'] in sites ]
todays_js = js['values']
current_addresses = None
for j in todays_js:
    if j['name'] == args.service:
        current_addresses = j['properties']['addressPrefixes']
        break

if current_addresses == None:
    print(f"UNKNOWN: No IPs in downloaded file for {args.service}.")
    sys.exit(3)

current_addresses = [ a for a in current_addresses if re.search('^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$', a)   ]
added_addresses = [ a for a in current_addresses if a not in expected_addresses ]
removed_addresses = [ a for a in expected_addresses if a not in current_addresses ]
if any(added_addresses) or any(removed_addresses):
    output_string = f"WARNING: {args.service} has the following changes: "
    if any(added_addresses):
        output_string += f"Addresses Added: {added_addresses}. "
    if any(removed_addresses):
        output_string += f"Addresses Removed: {removed_addresses}"
    print(output_string)
    sys.exit(1)
else:
    print("OK: Returned addresses match expected.")
    sys.exit(0)
print(f"EXPECTED: {expected_addresses}")
print(f"CURRENT: {current_addresses}")
