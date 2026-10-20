"""MAC address prefix (OUI) to manufacturer lookup.

Names come from the IEEE registry bundled as data/oui.txt.gz (refresh it with
tools/update_oui.py). The hand-maintained table below is the fallback when that
file is missing, and covers a few prefixes the registry lists under odd names.
Keep vendor names consistent with tools/update_oui.py's BRANDS, since
device-type detection matches on them.
"""

import gzip
import sys
from pathlib import Path

# PyInstaller unpacks bundled files to sys._MEIPASS; from source they sit next to this file.
DATA_FILE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / "data" / "oui.txt.gz"
_registry = None

_VENDORS = {
    "Aplix": "00:1C:4D",
    "Apple": (
        "00:03:93 00:05:02 00:0D:93 00:1B:63 00:1E:C9 00:1F:F3 00:23:12 00:25:00 "
        "00:50:E4 00:A0:40 08:00:07 3C:07:54 60:FB:42 F8:1E:DF"
    ),
    "ASUS": (
        "00:0C:6E 00:11:2F 00:13:D4 00:15:F2 00:17:31 00:1A:92 00:1B:FC 00:1D:60 "
        "00:1E:8C 00:1F:C6 00:22:15 00:23:54 00:24:8C 00:25:D3 00:26:18 00:90:A9 "
        "00:E0:18 08:60:6E 10:7B:44 10:BF:48 10:C3:7B 14:58:D0 14:DA:E9 14:DD:A9 "
        "1C:87:2C 1C:B7:2C 40:16:7E 50:46:5D 60:45:CB 70:8B:CD 74:D0:2B 78:24:AF "
        "88:D7:F6 90:E6:BA 9C:5C:8E AC:22:0B AC:9E:17 BC:EE:7B C8:60:00 D0:17:C2 "
        "D8:50:E6 E0:3F:49 E0:CB:4E F0:79:59"
    ),
    "Belkin": "00:0A:95 94:10:3E",
    "Broadcom": "00:10:18",
    "Brother": "00:1B:A9 00:80:77 30:05:5C",
    "Canon": (
        "00:00:85 00:04:F2 00:0B:54 00:15:99 00:17:EE 00:1E:8F 00:26:75 00:40:17 "
        "00:BB:C1 18:0C:AC 1C:6F:65 44:65:0D 9C:E6:5E"
    ),
    "Cisco": (
        "00:00:0C 00:01:42 00:05:73 00:05:DC 00:06:28 00:06:52 00:06:7C 00:06:C1 "
        "00:06:F6 00:07:0D 00:07:0E 00:07:4F 00:07:50 00:07:7D 00:07:84 00:07:85 "
        "00:07:B3 00:07:B4 00:07:EB 00:07:EC 00:08:20 00:08:21 00:08:2F 00:08:30 "
        "00:08:31 00:08:7C 00:08:7D 00:08:A3 00:08:A4 00:08:C2 00:08:E2 00:08:E3 "
        "00:09:11 00:09:12 00:09:43 00:09:44 00:09:7B 00:09:7C 00:09:B6 00:09:B7 "
        "00:09:E8 00:09:E9 00:0A:41 00:0A:42 00:0A:8A 00:0A:8B 00:0A:B7 00:0A:B8 "
        "00:0A:F3 00:0A:F4 00:0B:45 00:0B:46 00:0B:5F 00:0B:60 00:0B:84 00:0B:85 "
        "00:0B:BE 00:0B:BF 00:0B:FC 00:0B:FD 00:0C:30 00:0C:31 00:0C:41 00:0C:85 "
        "00:0C:86 00:0C:CE 00:0C:CF 00:0D:28 00:0D:29 00:0D:65 00:0D:66 00:0D:BC "
        "00:0D:BD 00:0D:EC 00:0D:ED 00:0E:08 00:0E:38 00:0E:39 00:0E:83 00:0E:84 "
        "00:0E:D6 00:0E:D7 00:0F:23 00:0F:24 00:0F:34 00:0F:35 00:0F:66 00:0F:8F "
        "00:0F:90 00:0F:F7 00:0F:F8 00:10:07 00:10:0B 00:10:0D 00:10:11 00:10:14 "
        "00:10:1F 00:10:29 00:10:2F 00:10:54 00:10:79 00:10:7B 00:10:A6 00:10:F6 "
        "00:10:FF 00:11:20 00:11:21 00:11:5C 00:11:5D 00:11:92 00:11:93 00:11:BB "
        "00:11:BC 00:12:00 00:12:01 00:12:17 00:12:43 00:12:44 00:12:7F 00:12:80 "
        "00:12:D9 00:12:DA 00:13:19 00:13:1A 00:13:5F 00:13:60 00:13:7F 00:13:80 "
        "00:13:C3 00:13:C4 00:14:1B 00:14:1C 00:14:68 00:14:69 00:14:A8 00:14:A9 "
        "00:14:BF 00:14:F1 00:14:F2 00:15:2B 00:15:2C 00:15:62 00:15:63 00:15:C6 "
        "00:15:C7 00:15:F9 00:15:FA 00:16:46 00:16:47 00:16:9C 00:16:9D 00:16:B6 "
        "00:16:C7 00:16:C8 00:17:0E 00:17:0F 00:17:3B 00:17:59 00:17:5A 00:17:94 "
        "00:17:95 00:17:DF 00:17:E0 00:18:0A 00:18:18 00:18:19 00:18:39 00:18:68 "
        "00:18:73 00:18:74 00:18:B9 00:18:BA 00:18:F8 00:19:06 00:19:07 00:19:2F "
        "00:19:30 00:19:47 00:19:55 00:19:56 00:19:A9 00:19:AA 00:19:E7 00:19:E8 "
        "00:1A:2F 00:1A:30 00:1A:6C 00:1A:6D 00:1A:A1 00:1A:A2 00:1B:D4 00:1C:0E "
        "00:1C:57 00:1D:45 00:1D:70 00:1E:13 00:1E:49 00:1E:79 00:1E:BD 00:1F:26 "
        "00:1F:6C 00:1F:9E 00:1F:CA 00:21:55 00:21:A0 00:21:D8 00:22:0C 00:22:3A "
        "00:22:6B 00:22:BD 00:23:04 00:23:33 00:23:5D 00:23:AB 00:23:EA 00:24:13 "
        "00:24:50 00:24:97 00:24:C3 00:24:F7 00:25:45 00:25:83 00:25:B4 00:26:0A "
        "00:26:51 00:26:99 00:26:CA 00:27:0C"
    ),
    "D-Link": "00:1E:58 1C:BD:B9",
    "Datapoint": "00:00:15",
    "DEC": "08:00:2B",
    "Dell": (
        "00:06:5B 00:08:74 00:0B:DB 00:0D:56 00:0F:1F 00:0F:4B 00:12:3F 00:13:72 "
        "00:14:22 00:15:C5 00:1A:A0 00:1C:23 00:1D:09 00:1E:4F 00:1E:C2 00:21:70 "
        "00:22:19 00:24:E8 00:26:B9 14:FE:B5 18:03:73 1C:40:24 20:04:0F 24:B6:FD "
        "28:F1:0E 34:17:EB 44:A8:42 48:4D:7E 54:BF:64 74:86:7A 78:2B:CB 84:2B:2B "
        "84:8F:69 90:B1:1C 98:90:96 A4:1F:72 A4:BA:DB B0:83:FE B8:85:84 B8:AC:6F "
        "B8:CA:3A BC:30:5B C8:1F:66 D0:67:E5 D0:94:66 D4:81:D7 D4:AE:52 E0:DB:55 "
        "EC:F4:BB F0:1F:AF F0:4D:A2 F4:8E:38 F8:B1:56 F8:BC:12 F8:DB:88"
    ),
    "Digital Equipment": "00:80:86",
    "Ember": "00:0D:6F",
    "Epson": "00:00:48 00:1B:35 00:26:AB",
    "Espressif": (
        "24:0A:C4 24:6F:28 30:AE:7B 30:AE:A4 50:02:91 54:5A:A6 5C:CF:7F 60:01:94 "
        "68:C6:3A 7C:9E:BD 80:7D:3A 84:0D:8E A0:76:4E A4:CF:12 AC:67:B2 FC:F5:C4"
    ),
    "Fortinet": "04:D5:90",
    "Francotyp-Postalia": "00:11:4B",
    "Google": (
        "00:1A:11 1C:F2:9A 3C:28:6D 3C:5A:B4 44:07:0B 54:60:09 94:EB:2C 94:EB:CD "
        "A4:77:33 F4:F5:D8 F4:F5:E8"
    ),
    "HP": (
        "00:01:E6 00:0E:7F 00:10:83 00:10:A9 00:11:0A 00:11:85 00:12:79 00:13:21 "
        "00:14:38 00:14:C2 00:15:60 00:16:35 00:17:08 00:18:FE 00:19:BB 00:1A:4B "
        "00:1B:78 00:1C:C4 00:1E:0B 00:1F:29 00:21:5A 00:22:64 00:23:7D 00:24:81 "
        "00:25:B3 00:26:55 00:30:6E 10:E7:C6 28:93:FE 3C:D9:2B 9C:7B:EF B0:5A:DA"
    ),
    "I-Data": "00:06:5C",
    "IBM": (
        "00:01:03 00:02:55 00:04:AC 00:05:41 00:06:0D 00:06:29 00:09:6B 00:0D:60 "
        "00:10:D9 00:11:25 00:14:5E 00:17:23 00:1A:64 00:20:35 00:21:5E 08:00:5A "
        "40:F2:E9 5C:F3:FC 6C:AE:8B 98:BE:94"
    ),
    "ICP Electronics": "00:08:9B",
    "Intel": "00:15:17 00:1B:21 00:1B:77 00:24:D7 34:13:E8 A4:4C:C8 FC:AA:14",
    "Japan Macnics": "08:00:42",
    "Kast": "00:20:75",
    "Kingmax": "00:A0:0C",
    "LIFX": "D0:73:D5",
    "Linksys": "00:1A:70",
    "LT Security": "14:2F:FD",
    "Microsoft": (
        "00:03:FF 00:0D:3A 00:12:5A 00:17:FA 00:1D:72 00:25:AE 00:50:F2 28:18:78 "
        "30:59:B7 50:1A:C5"
    ),
    "Microsoft Hyper-V": "00:15:5D",
    "MikroTik": (
        "00:0C:42 08:55:31 4C:5E:0C 64:D1:54 6C:3B:6B 74:4D:28 B8:69:F4 C4:AD:34 "
        "D4:CA:6D DC:2C:6E E4:8D:8C"
    ),
    "Netgear": "00:09:5B BC:A5:11",
    "NeXT": "00:00:0F",
    "Octothorpe": "00:BB:01",
    "Parallels": "00:1C:42",
    "PixStream": "00:50:69",
    "PMC-Sierra": "00:E0:04",
    "Polycom": "64:16:7F",
    "QEMU/KVM": "52:54:00",
    "Quanta": "20:7C:8F",
    "Racal-Datacom": "00:07:01",
    "Raspberry Pi": "B8:27:EB D8:3A:DD DC:A6:32 E4:5F:01",
    "Realtek": "00:E0:4C",
    "Samsung": "00:12:FB",
    "SanDisk": "00:1B:44",
    "Shiva": "00:80:D3",
    "Shuttle": "80:EE:73",
    "Silex Technology": "00:80:92",
    "Silicon Graphics": "08:00:69",
    "Synology": "00:11:32",
    "Targus": "4C:56:DF",
    "Tektronix": "08:00:11",
    "Texas Instruments": "F4:32:02",
    "TP-Link": (
        "0C:80:63 10:FE:ED 14:91:38 14:CC:20 18:D6:C7 20:DC:E6 30:B5:C2 3C:84:6A "
        "50:C7:BF 50:FA:84 54:C8:0F 60:E3:27 64:70:02 6C:19:8F 70:E2:84 74:EA:3A "
        "7C:8B:CA 84:16:F9 8C:0C:90 90:F6:52 A0:F3:C1 B0:BE:76 BC:46:99 BC:D1:77 "
        "C0:61:18 C4:6E:1F CC:32:E5 D8:0D:17 E8:DE:27 EC:08:6B EC:26:CA F0:FE:6B "
        "F4:EC:38 F8:D1:11"
    ),
    "Tricom": "00:40:2B",
    "Ubiquiti": (
        "04:18:D6 18:E8:29 24:5A:4C 24:A4:3C 44:D9:E7 68:72:51 74:83:C2 78:8A:20 "
        "80:2A:A8 B4:FB:E4 DC:9F:DB E4:18:6B E4:38:83 F0:9F:C2 F4:92:BF F4:E2:C6"
    ),
    "Ungermann-Bass": "00:DD:00 00:DD:01 00:DD:08",
    "Universal": "00:16:41",
    "VirtualBox": "08:00:27",
    "VMware": "00:05:69 00:0C:29 00:1C:14 00:50:56",
    "Xerox": (
        "00:00:AA 00:C0:EE 00:DD:02 00:DD:B0 00:DD:B1 00:DD:B2 00:DD:B3 08:00:87 "
        "9C:93:4E"
    ),
    "Xircom": "00:80:C7",
    "Xyplex": "00:80:C8",
}

OUI_TABLE = {prefix: vendor for vendor, prefixes in _VENDORS.items() for prefix in prefixes.split()}


def _load_registry():
    """The IEEE table as {prefix: vendor}, read once on first use."""
    global _registry
    if _registry is None:
        _registry = {}
        try:
            with gzip.open(DATA_FILE, "rt", encoding="utf-8") as f:
                for line in f:
                    prefix, _, vendor = line.rstrip("\n").partition("\t")
                    _registry[prefix] = vendor
        except OSError:
            pass  # fall back to OUI_TABLE alone
    return _registry


def lookup_manufacturer(mac):
    """Return the vendor for a normalized MAC (AA:BB:CC:DD:EE:FF), or "Unknown"."""
    if not mac or mac == "Unknown":
        return "Unknown"
    prefix = mac[:8].upper()
    vendor = _load_registry().get(prefix) or OUI_TABLE.get(prefix)
    if vendor:
        return vendor
    # The "locally administered" bit marks a made-up address, which is what phones,
    # tablets and laptops use for private Wi-Fi addresses.
    if int(mac[:2], 16) & 0x02:
        return "Private (randomized)"
    return "Unknown"
