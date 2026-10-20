#!/usr/bin/env python3
"""Refresh data/oui.txt.gz from the IEEE MAC address registry.

    python3 tools/update_oui.py              # download from IEEE
    python3 tools/update_oui.py oui.csv      # use a file you already downloaded

Vendor names are shortened ("Apple, Inc." -> "Apple") and well-known brands are
mapped to the names oui.py's hand-written table uses, since device-type
detection matches on those.
"""

import csv
import gzip
import io
import re
import sys
import urllib.request
from pathlib import Path

URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT = Path(__file__).resolve().parent.parent / "data" / "oui.txt.gz"

# Registry name prefix (case-insensitive) -> the brand name Lantern uses.
BRANDS = {
    "apple": "Apple", "hewlett packard enterprise": "HPE", "hewlett packard": "HP", "hewlett-packard": "HP",
    "hp inc": "HP", "tp-link": "TP-Link", "cisco-linksys": "Linksys", "linksys": "Linksys",
    "cisco meraki": "Cisco Meraki", "cisco": "Cisco", "ubiquiti": "Ubiquiti", "netgear": "Netgear",
    "dell": "Dell", "intel": "Intel", "microsoft": "Microsoft", "samsung": "Samsung", "google": "Google",
    "nest labs": "Google", "espressif": "Espressif", "raspberry pi": "Raspberry Pi", "brother": "Brother",
    "canon": "Canon", "seiko epson": "Epson", "xerox": "Xerox", "fuji xerox": "Xerox", "synology": "Synology",
    "qnap": "QNAP", "sonos": "Sonos", "amazon": "Amazon", "lenovo": "Lenovo", "asustek": "ASUS",
    "d-link": "D-Link", "routerboard": "MikroTik", "mikrotik": "MikroTik", "kyocera": "Kyocera",
    "lexmark": "Lexmark", "vmware": "VMware", "fortinet": "Fortinet", "belkin": "Belkin",
    "ring llc": "Ring", "roku": "Roku", "lg electronics": "LG", "sony": "Sony", "nintendo": "Nintendo",
    "micro-star": "MSI", "giga-byte": "Gigabyte", "realtek": "Realtek", "huawei": "Huawei",
    "xiaomi": "Xiaomi", "beijing xiaomi": "Xiaomi", "arris": "Arris", "eero": "eero", "polycom": "Polycom",
    "ricoh": "Ricoh", "konica minolta": "Konica Minolta", "sharp": "Sharp", "toshiba": "Toshiba",
    "zebra": "Zebra", "aruba": "Aruba", "juniper": "Juniper", "palo alto": "Palo Alto Networks",
    "sonicwall": "SonicWall", "texas instruments": "Texas Instruments", "tuya": "Tuya", "wyze": "Wyze",
    "ecobee": "ecobee", "philips lighting": "Philips Hue", "signify": "Philips Hue", "zte": "ZTE",
    "sagemcom": "Sagemcom", "technicolor": "Technicolor", "acer": "Acer",
}

# Blocks IEEE subdivides and sells on (MA-M / MA-S); the real vendor isn't known from 24 bits.
SKIP = {"IEEE Registration Authority"}

# Corporate suffixes to drop, repeatedly, from the end of a name.
_SUFFIX = re.compile(
    r"[\s,.]*\b(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|l\.l\.c|gmbh|ag|sa|s\.a|"
    r"srl|spa|s\.p\.a|bv|b\.v|nv|ab|as|oy|kg|plc|pty|pte|sas|kk|k\.k|technologies|technology|"
    r"electronics|international|holdings|group|industrial|systems|communications|networks)\.?\s*$",
    re.IGNORECASE)


def clean_name(name):
    name = " ".join(name.split())
    lowered = name.lower()
    for prefix, brand in BRANDS.items():
        if lowered.startswith(prefix):
            return brand
    previous = None
    while previous != name:
        previous = name
        name = _SUFFIX.sub("", name).strip(" ,.")
    # Shout-case registrations ("SHENZHEN FOO TECHNOLOGY") read better title-cased.
    if name.isupper() and len(name) > 4:
        name = name.title()
    return name or previous


def main():
    if len(sys.argv) > 1:
        text = Path(sys.argv[1]).read_text(encoding="utf-8")
    else:
        request = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0 (lantern update_oui)"})
        with urllib.request.urlopen(request, timeout=60) as resp:
            text = resp.read().decode("utf-8")

    table = {}
    for row in csv.DictReader(io.StringIO(text)):
        prefix = row["Assignment"].strip().upper()
        if row["Registry"] == "MA-L" and len(prefix) == 6 and row["Organization Name"].strip() not in SKIP:
            table[f"{prefix[0:2]}:{prefix[2:4]}:{prefix[4:6]}"] = clean_name(row["Organization Name"])

    OUT.parent.mkdir(exist_ok=True)
    lines = "".join(f"{p}\t{n}\n" for p, n in sorted(table.items()))
    # mtime=0 keeps the file byte-identical when the data hasn't changed.
    with open(OUT, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as f:
        f.write(lines.encode("utf-8"))
    print(f"Wrote {len(table):,} prefixes to {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
