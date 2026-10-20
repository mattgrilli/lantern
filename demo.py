"""Sample data for `python3 lantern.py --demo`: a made-up small office network.

Used for screenshots and trying the app without scanning anything. Nothing in
demo mode is saved to disk.
"""

from netscan import COMMON_PORTS, classify_device, device_key, format_ports
from oui import lookup_manufacturer

NETWORK = "10.0.0.0/24"

# ip, mac, hostname, open ports, label
_DEVICES = [
    ("10.0.0.1", "74:83:C2:5A:10:01", "gateway.office.lan", [53, 80, 443], "Main Router"),
    ("10.0.0.2", "00:1A:A2:3C:44:02", "core-switch", [22, 80, 443], "Core Switch"),
    ("10.0.0.5", "F0:9F:C2:7B:21:05", "unifi-ap-lobby", [22, 80], "Lobby Access Point"),
    ("10.0.0.10", "00:11:32:9A:0E:10", "nas01", [22, 80, 139, 443, 445, 548], "File Server"),
    ("10.0.0.12", "00:50:56:A1:B2:12", "build-agent-01", [22, 80, 3306], ""),
    ("10.0.0.20", "9C:93:4E:20:61:20", "XRX-VersaLink-C405", [80, 443, 515, 631, 9100], "Office Xerox"),
    ("10.0.0.21", "00:80:77:41:5E:21", "BRN-MFC-L2750DW", [80, 443, 631, 9100], "Front Desk Printer"),
    ("10.0.0.31", "D4:AE:52:17:C3:31", "DESKTOP-ACCT01", [139, 445, 3389], "Accounting PC"),
    ("10.0.0.32", "B8:CA:3A:5F:02:32", "DESKTOP-DESIGN2", [139, 445, 3389], ""),
    ("10.0.0.40", "3C:07:54:8E:91:40", "Sams-MacBook-Pro", [22, 548, 5900], "Sam's MacBook"),
    ("10.0.0.41", "60:FB:42:0D:7A:41", "conference-imac", [548, 5900], "Conference iMac"),
    ("10.0.0.55", "64:16:7F:22:AB:55", "polycom-conf-rm", [80, 443], "Conference Phone"),
    ("10.0.0.60", "B8:27:EB:4D:19:60", "raspberrypi", [22, 80], "Door Sensor Hub"),
    ("10.0.0.61", "24:0A:C4:73:E2:61", "esp-thermostat", [80], ""),
    ("10.0.0.72", "3C:5A:B4:61:0F:72", "chromecast-lounge", [8443], "Lounge TV"),
    ("10.0.0.88", "2A:6F:13:C8:44:88", "Jordans-iPhone", [], ""),
    ("10.0.0.91", "DA:12:7E:05:B1:91", "Unknown", [], ""),
]

SAMPLE_LOG = [
    "Scanning 10.0.0.0/24 — 254 addresses, 50 threads, deep scan on",
    "mDNS found 2 printer(s): 10.0.0.20, 10.0.0.21",
    "NEW device: 10.0.0.91 Unknown (Private (randomized))",
    "Scan complete in 9s — 16 device(s), 1 new, 1 no longer responding",
    "ALERT: Front Desk Printer (10.0.0.21) is OFFLINE",
]

_NOTES = {
    "10.0.0.20": "Toner ordered 3/12. Service contract #XR-20417.",
    "10.0.0.10": "Nightly backup at 2am. RAID 5, 4 x 8TB.",
}
_WATCHED = {"10.0.0.1", "10.0.0.10", "10.0.0.20", "10.0.0.21"}
_NEW = {"10.0.0.91"}          # appeared since the last scan
_OFFLINE = {"10.0.0.21"}      # stopped answering


def _device(ip, mac, hostname, ports, last_seen):
    manufacturer = lookup_manufacturer(mac)
    return {
        "ip": ip, "hostname": hostname, "mac": mac, "manufacturer": manufacturer,
        "type": classify_device(hostname, manufacturer, ports),
        "open_ports": ports, "ports": format_ports(ports), "last_seen": last_seen,
    }


def demo_state():
    """Everything LanternApp keeps in memory, filled with sample data."""
    devices, labels, notes, watch = {}, {}, {}, set()
    for ip, mac, hostname, ports, label in _DEVICES:
        dev = _device(ip, mac, hostname, ports,
                      "2026-03-14 08:12:41" if ip in _OFFLINE else "2026-03-14 09:30:07")
        dev["is_new"] = ip in _NEW
        dev["online"] = ip not in _OFFLINE
        key = device_key(ip, mac)
        devices[key] = dev
        if label:
            labels[key] = labels[mac] = label
        if ip in _NOTES:
            notes[key] = notes[mac] = _NOTES[ip]
        if ip in _WATCHED:
            watch.add(key)

    def snapshot(timestamp, skip=(), moved=None):
        out = []
        for dev in devices.values():
            if dev["ip"] in skip:
                continue
            d = {k: v for k, v in dev.items() if k not in ("is_new", "online")}
            if moved and d["ip"] in moved:
                d["ip"] = moved[d["ip"]]
            d["last_seen"] = timestamp
            out.append(d)
        return {"timestamp": timestamp, "network": NETWORK, "devices": out}

    history = [
        snapshot("2026-03-13 17:45:10", skip=_NEW, moved={"10.0.0.32": "10.0.0.37"}),
        snapshot("2026-03-14 09:30:07", skip=_OFFLINE),
    ]
    profiles = {
        "Office": {"network": NETWORK, "threads": "50", "deep_scan": True},
        "Guest Wi-Fi": {"network": "10.0.50.0/24", "threads": "25", "deep_scan": False},
    }
    return {"devices": devices, "labels": labels, "notes": notes, "watch": watch,
            "history": history, "profiles": profiles}


assert all(p in COMMON_PORTS for *_, ports, _ in _DEVICES for p in ports)
