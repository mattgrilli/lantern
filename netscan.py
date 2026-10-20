"""Network probing for Lantern: ping, ARP, port checks, mDNS and device classification.

Nothing in here touches the GUI, so it can be tested and reused on its own.
The output parsers are plain functions that take command output as text.
"""

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime

from oui import lookup_manufacturer

try:
    from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    HAVE_ZEROCONF = True
except ImportError:
    HAVE_ZEROCONF = False

IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

# Keep a console window from flashing up for every ping on Windows.
SUBPROCESS_FLAGS = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0

UNKNOWN = "Unknown"

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    139: "NetBIOS", 443: "HTTPS", 445: "SMB", 515: "LPR", 548: "AFP", 631: "IPP",
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9100: "JetDirect",
}
PRINTER_PORTS = {515, 631, 9100}
PRINTER_SERVICES = ["_ipp._tcp.local.", "_ipps._tcp.local.", "_printer._tcp.local.", "_pdl-datastream._tcp.local."]

_MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{1,2}[:-]){5}[0-9A-Fa-f]{1,2}(?![0-9A-Fa-f:-])")


def _run(args, timeout):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          creationflags=SUBPROCESS_FLAGS)


# ----------------- Targets -----------------

def parse_targets(text):
    """Expand a target string into a sorted, de-duplicated list of IPv4 addresses.

    Accepts comma-separated CIDRs (192.168.1.0/24), single addresses,
    and ranges written either way: 192.168.1.10-192.168.1.50 or 192.168.1.10-50.
    Raises ValueError on anything it can't parse.
    """
    hosts = set()
    for part in (p.strip() for p in text.split(",")):
        if not part:
            continue
        if "-" in part and "/" not in part:
            start_s, end_s = (s.strip() for s in part.split("-", 1))
            start = ipaddress.IPv4Address(start_s)
            if "." in end_s:
                end = ipaddress.IPv4Address(end_s)
            else:
                end = ipaddress.IPv4Address(str(start).rsplit(".", 1)[0] + "." + end_s)
            if end < start:
                raise ValueError(f"Range ends before it starts: {part}")
            hosts.update(ipaddress.IPv4Address(i) for i in range(int(start), int(end) + 1))
        else:
            net = ipaddress.IPv4Network(part, strict=False)
            # /31 and /32 have no network/broadcast addresses to skip.
            hosts.update(net.hosts() if net.num_addresses > 2 else net)
    if not hosts:
        raise ValueError("No addresses to scan")
    return sorted(hosts)


# ----------------- Local network detection -----------------

def local_ipv4():
    """Best guess at this machine's primary IPv4 address, or None."""
    try:
        # Connecting a UDP socket sends nothing; it just picks the outbound interface.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 80))
            return s.getsockname()[0]
    except OSError:
        pass
    try:
        ip = socket.gethostbyname(socket.gethostname())
        return None if ip.startswith("127.") else ip
    except OSError:
        return None


def parse_prefix_for_ip(output, ip):
    """Find the prefix length for `ip` in ifconfig / ip addr / ipconfig output.

    Handles `inet 10.0.0.5/24`, `netmask 0xffffff00`, `netmask 255.255.255.0`,
    `Mask:255.255.255.0` and Windows' `Subnet Mask . . . : 255.255.255.0`
    (in any language, since it only looks for the first mask-shaped value).
    """
    match = re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d])", output)
    if not match:
        return None
    after = output[match.end():match.end() + 300]
    cidr = re.match(r"/(\d{1,2})\b", after)
    if cidr:
        return int(cidr.group(1))
    hexmask = re.search(r"netmask\s+0x([0-9a-fA-F]{8})", after)
    if hexmask:
        return bin(int(hexmask.group(1), 16)).count("1")
    dotted = re.search(r"(?<![\d.])(255\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])", after)
    if dotted:
        try:
            return ipaddress.IPv4Network(f"0.0.0.0/{dotted.group(1)}").prefixlen
        except ValueError:
            return None
    return None


def detect_local_network():
    """Return (IPv4Network, local ip) for the primary interface, or (None, None)."""
    ip = local_ipv4()
    if not ip:
        return None, None
    if IS_WINDOWS:
        cmd = ["ipconfig"]
    elif IS_LINUX and shutil.which("ip"):
        cmd = ["ip", "-o", "-4", "addr", "show"]
    else:
        cmd = ["ifconfig"]
    prefix = None
    try:
        prefix = parse_prefix_for_ip(_run(cmd, timeout=5).stdout, ip)
    except (OSError, subprocess.SubprocessError):
        pass
    # Very wide prefixes (corporate /16s, VPNs) make for huge scans; /24 is a safer default.
    if prefix is None or prefix < 16:
        prefix = 24
    return ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False), ip


# ----------------- Ping -----------------

def ping_command(ip, count=1, timeout=1.0):
    """Build the platform's ping command. `timeout` is per reply, in seconds."""
    if IS_WINDOWS:
        return ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), ip]
    if IS_MAC:
        # macOS: -W is the per-reply wait in ms; -t would cap the whole run.
        return ["ping", "-c", str(count), "-W", str(int(timeout * 1000)), ip]
    return ["ping", "-c", str(count), "-W", str(max(1, round(timeout))), ip]


def ping(ip, timeout=1.0):
    """True if `ip` answers a single echo request."""
    try:
        result = _run(ping_command(ip, 1, timeout), timeout=timeout + 2)
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode != 0:
        return False
    # Windows exits 0 when a router replies "Destination host unreachable";
    # only a real echo reply carries a TTL.
    return "TTL=" in result.stdout.upper() if IS_WINDOWS else True


def ping_summary(ip, count=4):
    """Run a short ping and return its summary lines (loss and round-trip times)."""
    result = _run(ping_command(ip, count, 1.0), timeout=count * 2 + 3)
    keys = ("packet", "loss", "min/avg", "minimum", "average", "round-trip", "rtt")
    lines = [ln.strip() for ln in result.stdout.splitlines() if any(k in ln.lower() for k in keys)]
    return lines or [f"No reply from {ip}"]


# ----------------- MAC / ARP -----------------

def normalize_mac(mac):
    """'a4:2b:b0:1:2:3' or 'A4-2B-B0-01-02-03' -> 'A4:2B:B0:01:02:03'."""
    parts = re.split(r"[:-]", mac.strip())
    if len(parts) != 6:
        return UNKNOWN
    return ":".join(p.zfill(2) for p in parts).upper()


def parse_arp_output(output, ip):
    """Pull the MAC for `ip` out of `arp -a` / `arp -n` output (macOS, Linux or Windows)."""
    ip_re = re.compile(rf"(?<![\d.]){re.escape(ip)}(?![\d.])")
    for line in output.splitlines():
        if not ip_re.search(line):
            continue
        match = _MAC_RE.search(line)
        if match:
            mac = normalize_mac(match.group(0))
            if mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                return mac
    return UNKNOWN


def parse_proc_net_arp(text, ip):
    """Read the MAC for `ip` from Linux /proc/net/arp contents."""
    for line in text.splitlines()[1:]:
        fields = line.split()
        # Flags 0x0 means the entry is incomplete (no reply yet).
        if len(fields) >= 4 and fields[0] == ip and fields[2] != "0x0":
            return parse_arp_output(f"{ip} {fields[3]}", ip)
    return UNKNOWN


def lookup_mac(ip):
    """MAC for a host that was just pinged (so it should be in the ARP cache)."""
    if IS_LINUX:
        try:
            with open("/proc/net/arp") as f:
                mac = parse_proc_net_arp(f.read(), ip)
            if mac != UNKNOWN:
                return mac
        except OSError:
            pass
    cmd = ["arp", "-a", ip] if IS_WINDOWS else ["arp", "-n", ip]
    try:
        return parse_arp_output(_run(cmd, timeout=3).stdout, ip)
    except (OSError, subprocess.SubprocessError):
        return UNKNOWN


# ----------------- Ports / hostnames -----------------

def scan_ports(ip, ports=COMMON_PORTS, timeout=0.25):
    """Return the sorted list of `ports` that accept a TCP connection."""
    found = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    found.append(port)
        except OSError:
            pass
    return sorted(found)


def format_ports(open_ports):
    if open_ports is None:
        return "Skipped"
    if not open_ports:
        return "None"
    return ", ".join(f"{p} ({COMMON_PORTS[p]})" if p in COMMON_PORTS else str(p) for p in open_ports)


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return UNKNOWN


# ----------------- Device classification -----------------

_PRINTER_VENDORS = {"Brother", "Canon", "Epson", "Xerox", "Kyocera", "Lexmark", "Silex Technology"}
_NETWORK_VENDORS = {"Cisco", "Netgear", "Ubiquiti", "D-Link", "TP-Link", "Fortinet", "MikroTik", "Linksys"}
_VM_VENDORS = {"VMware", "VirtualBox", "Parallels", "QEMU/KVM", "Microsoft Hyper-V"}
_COMPUTER_VENDORS = {"Apple", "Dell", "Microsoft", "Intel", "Lenovo", "HP", "IBM", "Shuttle", "Quanta"}
_IOT_VENDORS = {"Espressif", "Raspberry Pi", "Google", "LIFX", "Texas Instruments"}


def _has(text, words):
    return any(w in text for w in words)


def classify_device(hostname, manufacturer, open_ports):
    """Guess a device type from its hostname, vendor and open ports.

    `open_ports` is a list of ints, or None if ports weren't scanned.
    """
    host = "" if hostname in (None, UNKNOWN) else hostname.lower()
    vendor = manufacturer or UNKNOWN
    ports = set(open_ports or ())

    if ports & PRINTER_PORTS or vendor in _PRINTER_VENDORS:
        return "Printer"
    if _has(host, ("print", "laserjet", "officejet", "deskjet", "mfc-", "xerox", "lexmark", "kyocera")):
        return "Printer"
    if vendor in _VM_VENDORS:
        return "Virtual Machine"
    if vendor == "Synology" or _has(host, ("nas", "synology", "qnap", "truenas", "freenas")):
        return "NAS/Storage"
    if vendor in _NETWORK_VENDORS or _has(host, ("router", "gateway", "switch", "firewall", "unifi", "mikrotik", "deco-", "archer", "eero", "orbi")):
        return "Network"
    if _has(host, ("iphone", "ipad", "android", "pixel", "galaxy", "oneplus")):
        return "Mobile"
    if _has(host, ("echo", "alexa", "chromecast", "google-home", "roku", "firetv", "appletv", "apple-tv",
                   "sonos", "hue", "nest", "wyze", "esp-", "esp32", "esp8266", "raspberrypi")):
        return "Smart Device"
    if vendor in _IOT_VENDORS:
        return "IoT Device"
    if ports & {3389, 5900, 548} or {139, 445} <= ports:
        return "Computer"
    if _has(host, ("desktop", "laptop", "macbook", "imac", "mac-mini", "workstation", "-pc", "pc-")):
        return "Computer"
    if vendor in _COMPUTER_VENDORS:
        return "Computer"
    if len(ports & {21, 22, 25, 53, 3306}) >= 2:
        return "Server"
    if ports & {80, 443, 8080, 8443}:
        return "Server/Web"
    return UNKNOWN


# ----------------- Host probe -----------------

def device_key(ip, mac):
    """Stable identity for a device: its MAC, or the IP when the MAC is unknown."""
    return mac if mac and mac != UNKNOWN else f"IP::{ip}"


def probe_host(ip, deep=True, known_printers=()):
    """Ping `ip`; if it answers, gather what we can about it. Returns a dict or None."""
    ip = str(ip)
    if not ping(ip):
        return None
    hostname = reverse_dns(ip)
    mac, manufacturer, open_ports = UNKNOWN, UNKNOWN, None
    if deep:
        mac = lookup_mac(ip)
        manufacturer = lookup_manufacturer(mac)
        open_ports = scan_ports(ip)
    dev_type = classify_device(hostname, manufacturer, open_ports)
    # Computers sharing a printer also advertise it over mDNS, so only use the hint
    # when nothing more specific was found.
    if ip in known_printers and dev_type in (UNKNOWN, "Server/Web"):
        dev_type = "Printer"
    return {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        "manufacturer": manufacturer,
        "type": dev_type,
        "open_ports": open_ports,
        "ports": format_ports(open_ports),
        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ----------------- mDNS printer discovery -----------------

def _zeroconf_printer_ips(seconds):
    ips = set()

    class Collector(ServiceListener):
        def add_service(self, zc, type_, name):
            info = zc.get_service_info(type_, name, timeout=1500)
            if info:
                ips.update(a for a in info.parsed_addresses() if ":" not in a)

        update_service = add_service

        def remove_service(self, zc, type_, name):
            pass

    zc = Zeroconf()
    try:
        ServiceBrowser(zc, PRINTER_SERVICES, Collector())
        time.sleep(seconds)
    finally:
        zc.close()
    return ips


def _dns_sd_instances(service, seconds):
    """Names advertised for `service` according to macOS `dns-sd -B`."""
    proc = subprocess.Popen(["dns-sd", "-B", service], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)
    time.sleep(seconds)
    proc.terminate()
    out, _ = proc.communicate(timeout=2)
    names = set()
    for line in out.splitlines():
        # e.g. "13:01:02.123  Add  2  4 local.  _ipp._tcp.  HP LaserJet Pro M404"
        if " Add " in line and service in line:
            name = re.split(rf"{re.escape(service)}\.?\s+", line, maxsplit=1)[-1].strip()
            if name:
                names.add(name)
    return names


def _dns_sd_printer_ips(seconds):
    ips = set()
    names = set()
    for service in ("_ipp._tcp", "_printer._tcp"):
        names |= _dns_sd_instances(service, seconds)
    for name in names:
        # Bonjour hostnames usually follow the instance name with spaces as dashes.
        for candidate in (f"{name}.local", f"{name.replace(' ', '-')}.local"):
            try:
                ips.update(a for a in socket.gethostbyname_ex(candidate)[2])
                break
            except OSError:
                continue
    return ips


def discover_printer_ips(seconds=2):
    """IPv4 addresses advertising printer services over mDNS (best effort, may be empty)."""
    try:
        if HAVE_ZEROCONF:
            return _zeroconf_printer_ips(seconds)
        if IS_MAC and shutil.which("dns-sd"):
            return _dns_sd_printer_ips(seconds)
    except Exception:
        # mDNS is only a head start for printers; the normal scan still finds them.
        pass
    return set()


def mdns_backend():
    if HAVE_ZEROCONF:
        return "zeroconf"
    if IS_MAC and shutil.which("dns-sd"):
        return "dns-sd"
    return None


def app_data_dir():
    """Per-user directory for Lantern's saved state."""
    if IS_WINDOWS:
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    elif IS_MAC:
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "LanternScanner")
