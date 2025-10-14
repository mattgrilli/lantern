#!/usr/bin/env python3
"""
Lantern IP Scanner with Device Detection for Mac — v1.2
- Thread-safe Tkinter updates via UI dispatcher
- Stable device keys (handles 'Unknown' MAC collisions)
- Safer macOS ping behavior (timeout controlled by Python)
- Right-click binding (<Button-3>) for macOS
- One-time Treeview tag configuration
- Clean scan cancellation (no shutdown inside as_completed loop)
- Correct host counting across CIDRs
- Watch list by key (MAC or IP fallback)
- Bonjour/mDNS printer pre-discovery for instant printer detection
- Persists state to ~/Library/Application Support/LanternScanner/scanner_data.json
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import subprocess
import ipaddress
import concurrent.futures
import threading
from datetime import datetime
import socket
import re
import json
import os
import sys
from pathlib import Path
from functools import lru_cache
import time

# ---------- App data directory (no extra deps) ----------
APP_DIR = Path.home() / "Library" / "Application Support" / "LanternScanner"
APP_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = APP_DIR / "scanner_data.json"

def is_main_thread():
    return threading.current_thread() is threading.main_thread()


class IPScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Lantern IP Scanner for macOS")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)

        self.scanning = False
        self.monitoring = False
        self.scan_thread = None
        self.monitor_thread = None
        self.found_devices = []         # list[dict]
        self.device_labels = {}         # key_or_mac -> label (kept compatible with prior version using MAC keys)
        self.watch_list = set()         # set of device keys (MAC or "IP::x.x.x.x")
        self.scan_history = []          # list of scans
        self.profiles = {}              # saved scan profiles

        # Load persistent data
        self.load_data()

        self.setup_ui()
        # One-time tag styling (not per-row)
        self.tree.tag_configure('new', background='#4A90E2', foreground='white')
        self.tree.tag_configure('watched', foreground='#FFD700')

        self.detect_local_network()

    # ----------------- UI dispatcher helpers -----------------
    def ui(self, fn, *args, **kwargs):
        """Run UI updates on the main thread."""
        if is_main_thread():
            fn(*args, **kwargs)
        else:
            self.root.after(0, lambda: fn(*args, **kwargs))

    # ----------------- Bonjour / mDNS pre-discovery (printers) -----------------
    def bonjour_service_instances(self, service='_ipp._tcp', seconds=2):
        """
        Returns a set of advertised instance names for the given Bonjour service.
        Uses `dns-sd -B <service>` for a short window, then terminates.
        """
        try:
            p = subprocess.Popen(['dns-sd', '-B', service],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 text=True)
        except Exception:
            return set()
        try:
            time.sleep(max(1, seconds))
            # terminate the browse; some versions need SIGINT to flush output, terminate works ok on macOS
            p.terminate()
        except Exception:
            pass

        names = set()
        try:
            if p.stdout:
                for line in p.stdout:
                    # Typical line: "Timestamp  Add 2 _ipp._tcp. local. HP_LaserJet_Pro_..."
                    if ' Add ' in line and service in line:
                        parts = line.strip().split()
                        if parts:
                            names.add(parts[-1])
        except Exception:
            pass
        return names

    def bonjour_printer_ips(self, seconds=2):
        """
        Best-effort mapping of Bonjour-advertised printer instances to IPs.
        Tries _ipp._tcp and _printer._tcp, then resolves instance names via DNS.
        """
        instance_names = set()
        instance_names |= self.bonjour_service_instances('_ipp._tcp', seconds=seconds)
        instance_names |= self.bonjour_service_instances('_printer._tcp', seconds=seconds)

        ips = set()
        for name in instance_names:
            # Normalize candidates: raw name, stripped dot, shortname.local
            candidates = [name, name.rstrip('.')]
            short = name.split('.')[0]
            if short:
                candidates.append(f"{short}.local")
            for cand in candidates:
                try:
                    _host, _alias, addrs = socket.gethostbyname_ex(cand)
                    for a in addrs:
                        # sanity check it's IPv4
                        try:
                            ipaddress.IPv4Address(a)
                            ips.add(a)
                        except Exception:
                            pass
                except Exception:
                    continue
        return list(ips)

    # ----------------- UI setup -----------------
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)

        # Title
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, pady=(0, 10), sticky=tk.W)

        title_label = ttk.Label(title_frame, text="Lantern Network Scanner Pro", font=('Arial', 16, 'bold'))
        title_label.pack(side=tk.LEFT)

        self.monitor_indicator = ttk.Label(title_frame, text="", font=('Arial', 10))
        self.monitor_indicator.pack(side=tk.LEFT, padx=(20, 0))

        # Scan configuration
        input_frame = ttk.LabelFrame(main_frame, text="Scan Configuration", padding="10")
        input_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(1, weight=1)

        ttk.Label(input_frame, text="Network Range:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))

        network_profile_frame = ttk.Frame(input_frame)
        network_profile_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        network_profile_frame.columnconfigure(0, weight=1)

        self.network_var = tk.StringVar(value="192.168.1.0/24")
        network_entry = ttk.Entry(network_profile_frame, textvariable=self.network_var, width=30)
        network_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))

        profile_btn_frame = ttk.Frame(network_profile_frame)
        profile_btn_frame.grid(row=0, column=1)

        ttk.Button(profile_btn_frame, text="Save Profile", command=self.save_profile, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(profile_btn_frame, text="Load Profile", command=self.load_profile_dialog, width=12).pack(side=tk.LEFT, padx=2)

        ttk.Label(input_frame, text="Threads:").grid(row=0, column=2, sticky=tk.W, padx=(10, 10))
        self.threads_var = tk.StringVar(value="50")
        threads_spinbox = ttk.Spinbox(input_frame, from_=10, to=200, textvariable=self.threads_var, width=10)
        threads_spinbox.grid(row=0, column=3, sticky=tk.W)

        self.deep_scan_var = tk.BooleanVar(value=True)
        deep_scan_cb = ttk.Checkbutton(input_frame, text="Deep Scan (ports, MAC, manufacturer)", variable=self.deep_scan_var)
        deep_scan_cb.grid(row=1, column=0, columnspan=4, pady=(10, 0), sticky=tk.W)

        # Controls
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, pady=(0, 10))

        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan, style='Accent.TButton')
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state='disabled')
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.monitor_button = ttk.Button(button_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.monitor_button.pack(side=tk.LEFT, padx=5)

        ttk.Separator(button_frame, orient='vertical').pack(side=tk.LEFT, fill='y', padx=10)

        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        ttk.Button(button_frame, text="Compare Scans", command=self.compare_scans).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=5)

        ttk.Separator(button_frame, orient='vertical').pack(side=tk.LEFT, fill='y', padx=10)

        ttk.Label(button_frame, text="Quick:").pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copy IP", command=lambda: self.copy_field('IP'), width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Copy MAC", command=lambda: self.copy_field('MAC'), width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Open Browser", command=lambda: self.open_device_browser(), width=12).pack(side=tk.LEFT, padx=2)

        # Filters
        filter_frame = ttk.Frame(main_frame)
        filter_frame.grid(row=3, column=0, pady=(0, 10), sticky=(tk.W, tk.E))

        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar()
        self.filter_var.trace('w', self.apply_filter)
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(filter_frame, text="Show:").pack(side=tk.LEFT, padx=(10, 5))
        self.filter_type = tk.StringVar(value="all")
        ttk.Radiobutton(filter_frame, text="All", variable=self.filter_type, value="all", command=self.apply_filter).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(filter_frame, text="Printers", variable=self.filter_type, value="printers", command=self.apply_filter).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(filter_frame, text="Watched", variable=self.filter_type, value="watched", command=self.apply_filter).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(filter_frame, text="New", variable=self.filter_type, value="new", command=self.apply_filter).pack(side=tk.LEFT, padx=2)

        # Progress
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100, mode='determinate')
        self.progress_bar.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Results
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        results_frame.grid(row=5, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        columns = ('Status', 'Label', 'IP', 'Hostname', 'MAC', 'Manufacturer', 'Type', 'Ports', 'Last Seen')
        self.tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)

        self.tree.heading('Status', text='●')
        self.tree.heading('Label', text='Label')
        self.tree.heading('IP', text='IP Address')
        self.tree.heading('Hostname', text='Hostname')
        self.tree.heading('MAC', text='MAC Address')
        self.tree.heading('Manufacturer', text='Manufacturer')
        self.tree.heading('Type', text='Type')
        self.tree.heading('Ports', text='Open Ports')
        self.tree.heading('Last Seen', text='Last Seen')

        self.tree.column('Status', width=30)
        self.tree.column('Label', width=120)
        self.tree.column('IP', width=120)
        self.tree.column('Hostname', width=150)
        self.tree.column('MAC', width=130)
        self.tree.column('Manufacturer', width=150)
        self.tree.column('Type', width=100)
        self.tree.column('Ports', width=180)
        self.tree.column('Last Seen', width=160)

        # Context menu & bindings
        self.tree.bind('<Button-2>', self.show_context_menu)          # middle click (legacy)
        self.tree.bind('<Control-Button-1>', self.show_context_menu)  # ctrl+click (mac)
        self.tree.bind('<Button-3>', self.show_context_menu)          # right click
        self.tree.bind('<Double-1>', self.open_device_browser)

        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(results_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        vsb.grid(row=0, column=1, sticky=(tk.N, tk.S))
        hsb.grid(row=1, column=0, sticky=(tk.W, tk.E))

        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Set Label/Nickname", command=self.set_device_label)
        self.context_menu.add_command(label="Add to Watch List", command=self.add_to_watchlist)
        self.context_menu.add_command(label="Remove from Watch List", command=self.remove_from_watchlist)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy IP Address", command=lambda: self.copy_field('IP'))
        self.context_menu.add_command(label="Copy MAC Address", command=lambda: self.copy_field('MAC'))
        self.context_menu.add_command(label="Copy Hostname", command=lambda: self.copy_field('Hostname'))
        self.context_menu.add_command(label="Copy All Info", command=self.copy_all_info)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Open in Browser (HTTP)", command=lambda: self.open_device_browser(protocol='http'))
        self.context_menu.add_command(label="Open in Browser (HTTPS)", command=lambda: self.open_device_browser(protocol='https'))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Ping Device", command=self.ping_selected_device)

        # Log & status
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="10")
        log_frame.grid(row=6, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        log_frame.columnconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=6, font=('Courier', 9))
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E))

        self.status_var = tk.StringVar(value="Ready to scan")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=7, column=0, sticky=(tk.W, tk.E), pady=(10, 0))

    # ----------------- Persistence -----------------
    def load_data(self):
        try:
            if STATE_FILE.exists():
                with open(STATE_FILE, 'r') as f:
                    data = json.load(f)
                    self.device_labels = data.get('labels', {})
                    self.watch_list = set(data.get('watchlist', []))
                    self.profiles = data.get('profiles', {})
                    self.scan_history = data.get('history', [])
        except Exception as e:
            print(f"Could not load data: {e}")

    def save_data(self):
        try:
            data = {
                'labels': self.device_labels,
                'watchlist': list(self.watch_list),
                'profiles': self.profiles,
                'history': self.scan_history[-50:]
            }
            with open(STATE_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.log_message(f"Could not save data: {e}")

    # ----------------- Profiles -----------------
    def save_profile(self):
        name = simpledialog.askstring("Save Profile", "Enter profile name:")
        if name:
            self.profiles[name] = {'network': self.network_var.get(), 'threads': self.threads_var.get()}
            self.save_data()
            self.log_message(f"Saved profile: {name}")
            messagebox.showinfo("Profile Saved", f"Profile '{name}' saved successfully!")

    def load_profile_dialog(self):
        if not self.profiles:
            messagebox.showinfo("No Profiles", "No saved profiles found.")
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Load Profile")
        dialog.geometry("300x200")
        ttk.Label(dialog, text="Select a profile:").pack(pady=10)
        listbox = tk.Listbox(dialog)
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for name in self.profiles.keys():
            listbox.insert(tk.END, name)
        def load_selected():
            selection = listbox.curselection()
            if selection:
                name = listbox.get(selection[0])
                profile = self.profiles[name]
                self.network_var.set(profile['network'])
                self.threads_var.set(profile['threads'])
                self.log_message(f"Loaded profile: {name}")
                dialog.destroy()
        ttk.Button(dialog, text="Load", command=load_selected).pack(pady=5)

    # ----------------- Network detection -----------------
    def detect_local_network(self):
        try:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            output = result.stdout
            lines = output.split('\n')
            current_interface = None
            ip_address_str = None
            netmask = None

            for line in lines:
                if line and not line.startswith('\t') and not line.startswith(' '):
                    current_interface = line.split(':')[0]

                if '\tinet ' in line and '127.0.0.1' not in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'inet' and i + 1 < len(parts):
                            ip_address_str = parts[i + 1]
                        if part == 'netmask' and i + 1 < len(parts):
                            netmask = parts[i + 1]
                    if ip_address_str and netmask:
                        if netmask.startswith('0x'):
                            netmask_int = int(netmask, 16)
                            cidr = bin(netmask_int).count('1')
                        else:
                            nm_parts = netmask.split('.')
                            binary = ''.join([bin(int(x))[2:].zfill(8) for x in nm_parts])
                            cidr = binary.count('1')

                        network_obj = ipaddress.ip_network(f"{ip_address_str}/{cidr}", strict=False)
                        network = str(network_obj)
                        self.network_var.set(network)
                        self.log_message(f"Detected interface: {current_interface}")
                        self.log_message(f"Your IP: {ip_address_str}/{cidr}")
                        self.log_message(f"Network range: {network}")
                        return

            raise Exception("Could not parse ifconfig output")

        except Exception:
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                ip_parts = local_ip.split('.')
                network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                self.network_var.set(network)
                self.log_message(f"Auto-detected network (fallback): {network}")
            except:
                self.log_message("Could not auto-detect network, using default 192.168.1.0/24")

    # ----------------- Logging -----------------
    def log_message(self, message):
        ts = datetime.now().strftime('%H:%M:%S')
        def _do():
            self.log_text.insert(tk.END, f"[{ts}] {message}\n")
            self.log_text.see(tk.END)
        self.ui(_do)

    # ----------------- Utilities -----------------
    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.found_devices.clear()
        self.ui(self.progress_var.set, 0)
        self.ui(self.status_var.set, "Results cleared")

    def device_key_from(self, ip, mac):
        return mac if mac and mac != "Unknown" else f"IP::{ip}"

    def key_of(self, dev):
        return self.device_key_from(dev.get('ip'), dev.get('mac'))

    def get_mac_address(self, ip):
        """Get MAC via ARP. Ping first to populate ARP cache."""
        try:
            # simple ping to nudge ARP; control timeout via subprocess
            self.ping_ok(ip, tries=1, timeout=1.2)
            result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=2)
            match = re.search(r'([0-9a-fA-F]{1,2}[:-]){5}([0-9a-fA-F]{1,2})', result.stdout)
            if match:
                return match.group(0).upper()
        except Exception:
            pass
        return "Unknown"

    @lru_cache(maxsize=1024)
    def get_manufacturer(self, mac):
        """Identify manufacturer from MAC OUI (simple embedded db)."""
        if mac == "Unknown" or not mac:
            return "Unknown"
        oui_db = {
            '00:10:83': 'Hewlett Packard', '00:11:4B': 'Francotyp-Postalia',
            '00:15:17': 'Intel Corporate', '00:15:5D': 'Microsoft Corporation',
            '00:1E:58': 'D-Link Corporation', '00:23:7D': 'Hewlett Packard',
            '04:D5:90': 'Fortinet', '10:E7:C6': 'Hewlett Packard',
            '14:2F:FD': 'LT Security', '4C:56:DF': 'Targus', '64:16:7F': 'Polycom',
            '74:83:C2': 'Ubiquiti Networks', '9C:7B:EF': 'Hewlett Packard',
            '9C:93:4E': 'Xerox Corporation', 'B0:5A:DA': 'Hewlett Packard',
            'BC:A5:11': 'NETGEAR', 'D0:94:66': 'Dell Inc.', 'E4:38:83': 'Ubiquiti Networks',
            '00:00:0C': 'Cisco', '00:01:42': 'Cisco', '00:50:56': 'VMware',
            '08:00:27': 'Oracle VirtualBox', '00:0D:93': 'Apple', '00:25:00': 'Apple',
            'AC:DE:48': 'Apple', '00:1B:63': 'Apple', '00:C0:EE': 'Xerox',
            '00:00:AA': 'Xerox', '08:00:87': 'Xerox', '00:DD:00': 'Xerox', '00:DD:01': 'Xerox',
            '00:DD:02': 'Xerox', '00:DD:B0': 'Xerox', '00:DD:B1': 'Xerox', '00:DD:B2': 'Xerox',
            '00:DD:B3': 'Xerox', '08:00:2B': 'DEC', '00:50:C2': 'IEEE 802.11',
            '00:1D:09': 'HP', '00:1F:29': 'HP', '00:21:5A': 'HP', '00:26:55': 'Brother',
            '00:80:77': 'Brother', '00:1B:A9': 'Brother', '00:04:F2': 'Canon',
            '00:00:85': 'Canon', '9C:E6:5E': 'Canon', '44:65:0D': 'Canon',
            '00:12:FB': 'Samsung', '00:1E:C2': 'Dell', '00:14:22': 'Dell', 'B8:CA:3A': 'Dell',
            '00:0A:95': 'Belkin', '94:10:3E': 'Belkin', '00:1A:70': 'Netgear', '00:09:5B': 'Netgear',
        }
        oui = ':'.join(mac.split(':')[:3]).upper()
        return oui_db.get(oui, "Unknown")

    def identify_device_type(self, ports, manufacturer, hostname):
        ports_lower = (ports or '').lower()
        manufacturer_lower = (manufacturer or '').lower()
        hostname_lower = (hostname or '').lower()

        printer_indicators = ['515', '631', '9100', 'lpr', 'ipp']
        printer_manufacturers = ['xerox', 'hp', 'canon', 'brother', 'epson', 'kyocera']

        if any(ind in ports_lower for ind in printer_indicators): return 'Printer'
        if any(mfg in manufacturer_lower for mfg in printer_manufacturers): return 'Printer'
        if 'print' in hostname_lower: return 'Printer'

        if any(mfg in manufacturer_lower for mfg in ['cisco', 'netgear', 'ubiquiti', 'd-link', 'fortinet']):
            return 'Network'

        if '3389' in ports_lower or any(mfg in manufacturer_lower for mfg in ['dell', 'hp', 'apple', 'microsoft']):
            return 'Computer'

        if '80' in ports_lower or '443' in ports_lower or 'http' in ports_lower:
            return 'Server/Web'

        return 'Unknown'

    def scan_ports(self, ip):
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 80: 'HTTP',
            443: 'HTTPS', 445: 'SMB', 515: 'LPR', 631: 'IPP',
            9100: 'Printer', 8080: 'HTTP-Alt', 3389: 'RDP',
            161: 'SNMP', 427: 'SLP'
        }
        open_ports = []
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.25)  # tighter timeout for speed
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    open_ports.append(f"{port}({service})")
            except Exception:
                pass
        return ', '.join(open_ports) if open_ports else 'None'

    def ping_ok(self, ip, tries=1, timeout=1.5):
        """Ping control via Python timeout; uses macOS-friendly flags."""
        try:
            subprocess.run(['ping', '-c', str(tries), ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=timeout)
            return True
        except Exception:
            return False

    def ping_host(self, ip):
        """Ping and gather detailed information about a host; returns device dict or None."""
        try:
            if not self.ping_ok(str(ip)):  # single try fast path
                return None

            try:
                hostname = socket.gethostbyaddr(str(ip))[0]
            except Exception:
                hostname = "Unknown"

            device_info = {
                'ip': str(ip),
                'hostname': hostname,
                'mac': 'Unknown',
                'manufacturer': 'Unknown',
                'ports': 'Skipped' if not self.deep_scan_var.get() else 'None',
                'type': 'Unknown',
                'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'is_new': True
            }

            if self.deep_scan_var.get():
                mac = self.get_mac_address(str(ip))
                device_info['mac'] = mac
                device_info['manufacturer'] = self.get_manufacturer(mac)
                device_info['ports'] = self.scan_ports(str(ip))
                device_info['type'] = self.identify_device_type(
                    device_info['ports'], device_info['manufacturer'], hostname
                )

            return device_info

        except Exception:
            return None

    # ----------------- Treeview ops -----------------
    def add_device_to_tree(self, device):
        def _do():
            mac = device['mac']
            label = self.device_labels.get(mac, '') or self.device_labels.get(self.key_of(device), '')
            watched = self.device_key_from(device['ip'], mac) in self.watch_list
            is_watched = '★' if watched else ''
            tags = []
            if device.get('is_new'): tags.append('new')
            if watched: tags.append('watched')

            self.tree.insert('', tk.END, values=(
                is_watched,
                label,
                device['ip'],
                device['hostname'],
                mac,
                device['manufacturer'],
                device['type'],
                device['ports'],
                device['last_seen']
            ), tags=tuple(tags))
            self.found_devices.append(device)
        self.ui(_do)

    def apply_filter(self, *args):
        search_term = (self.filter_var.get() or '').lower()
        filter_type = self.filter_type.get()

        for item in self.tree.get_children():
            self.tree.delete(item)

        for device in self.found_devices:
            # Type filter
            if filter_type == 'printers' and device['type'] != 'Printer':
                continue
            elif filter_type == 'watched' and (self.device_key_from(device['ip'], device['mac']) not in self.watch_list):
                continue
            elif filter_type == 'new' and not device.get('is_new', False):
                continue

            # Text filter
            if search_term:
                mac = device['mac']
                label = self.device_labels.get(mac, '') or self.device_labels.get(self.key_of(device), '')
                searchable = f"{device['ip']} {device['hostname']} {mac} {device['manufacturer']} {device['type']} {device['ports']} {label}".lower()
                if search_term not in searchable:
                    continue

            watched = self.device_key_from(device['ip'], device['mac']) in self.watch_list
            is_watched = '★' if watched else ''
            label = self.device_labels.get(device['mac'], '') or self.device_labels.get(self.key_of(device), '')

            self.tree.insert('', tk.END, values=(
                is_watched,
                label,
                device['ip'],
                device['hostname'],
                device['mac'],
                device['manufacturer'],
                device['type'],
                device['ports'],
                device['last_seen']
            ), tags=('new' if device.get('is_new', False) else '',))

    def set_device_label(self):
        selection = self.tree.selection()
        if not selection:
            self.log_message("Please select a device first")
            return

        item = selection[0]
        values = self.tree.item(item)['values']
        mac = values[4]
        ip = values[2]
        key = self.device_key_from(ip, mac)
        current_label = self.device_labels.get(mac, '') or self.device_labels.get(key, '')

        new_label = simpledialog.askstring("Set Device Label", "Enter label/nickname:", initialvalue=current_label)
        if new_label is not None:
            new_label = new_label.strip()
            if new_label:
                # Prefer MAC key if known; also store against device key for IP-only cases
                if mac != "Unknown":
                    self.device_labels[mac] = new_label
                self.device_labels[key] = new_label
            else:
                self.device_labels.pop(mac, None)
                self.device_labels.pop(key, None)

            self.save_data()
            self.apply_filter()
            self.log_message(f"Label set for {key}")

    def add_to_watchlist(self):
        selection = self.tree.selection()
        if not selection:
            self.log_message("Please select a device first")
            return

        item = selection[0]
        values = self.tree.item(item)['values']
        mac = values[4]
        ip = values[2]
        key = self.device_key_from(ip, mac)
        self.watch_list.add(key)
        self.save_data()
        self.apply_filter()
        self.log_message(f"Added to watch list: {key}")

    def remove_from_watchlist(self):
        selection = self.tree.selection()
        if not selection:
            self.log_message("Please select a device first")
            return

        item = selection[0]
        values = self.tree.item(item)['values']
        mac = values[4]
        ip = values[2]
        key = self.device_key_from(ip, mac)
        self.watch_list.discard(key)
        self.save_data()
        self.apply_filter()
        self.log_message(f"Removed from watch list: {key}")

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    # ----------------- Actions -----------------
    def copy_field(self, field_name):
        selection = self.tree.selection()
        if not selection:
            self.log_message("Please select a device first")
            return
        item = selection[0]
        values = self.tree.item(item)['values']
        field_map = {'IP': 2, 'Hostname': 3, 'MAC': 4, 'Manufacturer': 5}
        if field_name in field_map:
            value = values[field_map[field_name]]
            self.root.clipboard_clear()
            self.root.clipboard_append(str(value))
            self.log_message(f"Copied {field_name}: {value}")
            self.ui(self.status_var.set, f"Copied {field_name} to clipboard")

    def copy_all_info(self):
        selection = self.tree.selection()
        if not selection:
            self.log_message("Please select a device first")
            return
        item = selection[0]
        values = self.tree.item(item)['values']
        info = f"""Label: {values[1]}
IP Address: {values[2]}
Hostname: {values[3]}
MAC Address: {values[4]}
Manufacturer: {values[5]}
Type: {values[6]}
Open Ports: {values[7]}
Last Seen: {values[8]}"""
        self.root.clipboard_clear()
        self.root.clipboard_append(info)
        self.log_message("Copied all device information")
        self.ui(self.status_var.set, "Copied all device info to clipboard")

    def open_device_browser(self, event=None, protocol='http'):
        selection = self.tree.selection()
        if not selection:
            self.log_message("Please select a device first")
            return
        item = selection[0]
        values = self.tree.item(item)['values']
        ip = values[2]
        import webbrowser
        url = f"{protocol}://{ip}"
        try:
            webbrowser.open(url)
            self.log_message(f"Opening {url} in browser")
            self.ui(self.status_var.set, f"Opened {url}")
        except Exception as e:
            self.log_message(f"Could not open browser: {e}")

    def ping_selected_device(self):
        selection = self.tree.selection()
        if not selection:
            self.log_message("Please select a device first")
            return
        item = selection[0]
        values = self.tree.item(item)['values']
        ip = values[2]
        self.log_message(f"Pinging {ip}...")
        try:
            result = subprocess.run(['ping', '-c', '4', ip], capture_output=True, text=True, timeout=6)
            output_lines = result.stdout.split('\n')
            for line in output_lines:
                if 'packets transmitted' in line or 'min/avg/max' in line:
                    self.log_message(line.strip())
            self.ui(self.status_var.set, f"Ping to {ip} complete")
        except Exception as e:
            self.log_message(f"Ping failed: {e}")

    # ----------------- Monitoring -----------------
    def toggle_monitoring(self):
        if not self.monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()

    def start_monitoring(self):
        if not self.watch_list:
            messagebox.showwarning("No Watched Devices",
                                   "Please add devices to your watch list first.\n\n"
                                   "Right-click on a device and select 'Add to Watch List'.")
            return
        self.monitoring = True
        self.monitor_button.config(text="Stop Monitoring")
        self.monitor_indicator.config(text="🔴 MONITORING", foreground="red")
        self.log_message(f"Started monitoring {len(self.watch_list)} device(s)")
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.monitor_button.config(text="Start Monitoring")
        self.monitor_indicator.config(text="")
        self.log_message("Stopped monitoring")

    def monitor_loop(self):
        while self.monitoring:
            for key in list(self.watch_list):
                if not self.monitoring:
                    break
                # Find device info by key
                device = next((d for d in self.found_devices if self.key_of(d) == key), None)
                if device:
                    ip = device['ip']
                    label = self.device_labels.get(device['mac'], '') or self.device_labels.get(self.key_of(device), ip)
                    try:
                        if self.ping_ok(ip, tries=1, timeout=1.5):
                            device['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            self.log_message(f"⚠️  ALERT: {label} ({ip}) is OFFLINE")
                    except Exception:
                        pass
            # sleep in small chunks so stop is responsive
            for _ in range(60):
                if not self.monitoring:
                    break
                time.sleep(1)

    # ----------------- Scanning -----------------
    def scan_network(self):
        try:
            network = self.network_var.get()
            max_workers = int(self.threads_var.get())

            self.log_message("=" * 60)
            self.log_message(f"Starting scan of {network}")
            self.log_message(f"Deep scan: {'Enabled' if self.deep_scan_var.get() else 'Disabled'}")
            self.log_message(f"Using {max_workers} threads")
            self.log_message("=" * 60)

            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())

            # Bonjour pre-discovery: prioritize printer IPs so they show up instantly
            try:
                mdns_ips = self.bonjour_printer_ips(seconds=2)
            except Exception:
                mdns_ips = []

            priority_hosts = []
            seen = set()
            for ip_str in mdns_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj in net and ip_obj not in seen:
                        priority_hosts.append(ip_obj)
                        seen.add(ip_obj)
                except Exception:
                    continue

            # Move prioritized hosts to the front, keep order stable, no duplicates
            if priority_hosts:
                self.log_message(f"Bonjour: prioritizing {len(priority_hosts)} printer candidate(s)")
            rest_hosts = [h for h in hosts if h not in seen]
            hosts = priority_hosts + rest_hosts

            total_ips = len(hosts)

            # Mark existing devices as not new
            for device in self.found_devices:
                device['is_new'] = False

            previous_keys = set(self.key_of(d) for d in self.found_devices)
            completed = 0
            found_count = 0

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self.ping_host, ip): ip for ip in hosts}

                for future in concurrent.futures.as_completed(futures):
                    if not self.scanning:
                        break

                    completed += 1
                    result = future.result()

                    if result:
                        found_count += 1
                        k = self.device_key_from(result['ip'], result['mac'])
                        if k not in previous_keys:
                            result['is_new'] = True
                            self.log_message(f"🆕 NEW: {result['ip']} - {result['manufacturer']}")
                        else:
                            result['is_new'] = False
                            existing = next((d for d in self.found_devices if self.key_of(d) == k), None)
                            if existing:
                                self.found_devices.remove(existing)

                        self.add_device_to_tree(result)

                    progress = (completed / max(total_ips, 1)) * 100
                    self.ui(self.progress_var.set, progress)
                    self.ui(self.status_var.set, f"Scanning... {completed}/{total_ips} IPs | Found: {found_count} devices")

            if self.scanning:
                self.log_message("=" * 60)
                self.log_message(f"Scan complete! Found {found_count} active device(s)")
                self.log_message("=" * 60)
                self.ui(self.status_var.set, f"Scan complete - {found_count} devices found")

                scan_record = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'network': network,
                    'devices': [d.copy() for d in self.found_devices]
                }
                self.scan_history.append(scan_record)
                self.save_data()
            else:
                self.log_message("Scan stopped by user")
                self.ui(self.status_var.set, "Scan stopped")

        except ValueError as e:
            self.log_message(f"Error: Invalid network format - {e}")
            self.ui(self.status_var.set, "Error: Invalid network format")
        except Exception as e:
            self.log_message(f"Error: {e}")
            self.ui(self.status_var.set, f"Error: {e}")
        finally:
            self.scanning = False
            self.ui(self.scan_button.config, state='normal')
            self.ui(self.stop_button.config, state='disabled')

    def start_scan(self):
        if not self.scanning:
            self.scanning = True
            self.scan_button.config(state='disabled')
            self.stop_button.config(state='normal')
            self.ui(self.progress_var.set, 0)
            self.scan_thread = threading.Thread(target=self.scan_network, daemon=True)
            self.scan_thread.start()

    def stop_scan(self):
        self.scanning = False
        self.ui(self.status_var.set, "Stopping scan...")
        self.stop_button.config(state='disabled')

    # ----------------- Compare / Export -----------------
    def compare_scans(self):
        if len(self.scan_history) < 2:
            messagebox.showinfo("Compare Scans",
                                "Need at least 2 saved scans to compare.\n\n"
                                "Scans are automatically saved after each scan completes.")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Compare Scans")
        dialog.geometry("700x480")

        ttk.Label(dialog, text="Scan Comparison", font=('Arial', 14, 'bold')).pack(pady=10)

        current_scan = self.scan_history[-1]
        previous_scan = self.scan_history[-2]

        def key_of_dev(d):  # local consistent key
            mac = d.get('mac', 'Unknown')
            ip = d.get('ip', '')
            return mac if mac != 'Unknown' else f"IP::{ip}"

        current_keys = set(key_of_dev(d) for d in current_scan['devices'])
        previous_keys = set(key_of_dev(d) for d in previous_scan['devices'])

        new_keys = current_keys - previous_keys
        missing_keys = previous_keys - current_keys

        # Track moved IPs (same MAC present but IP changed)
        moved = []
        prev_by_key = {key_of_dev(d): d for d in previous_scan['devices']}
        curr_by_key = {key_of_dev(d): d for d in current_scan['devices']}
        for k in (current_keys & previous_keys):
            prev_ip = prev_by_key[k].get('ip', '')
            curr_ip = curr_by_key[k].get('ip', '')
            if prev_ip and curr_ip and prev_ip != curr_ip:
                moved.append((k, prev_ip, curr_ip))

        result_text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD, height=22)
        result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        result_text.insert(tk.END, f"Current Scan:  {current_scan['timestamp']}\n")
        result_text.insert(tk.END, f"Previous Scan: {previous_scan['timestamp']}\n\n")
        result_text.insert(tk.END, "=" * 60 + "\n\n")

        if new_keys:
            result_text.insert(tk.END, f"NEW DEVICES ({len(new_keys)}):\n")
            for k in new_keys:
                d = curr_by_key.get(k, {})
                label = self.device_labels.get(d.get('mac', ''), '') or self.device_labels.get(k, '')
                result_text.insert(tk.END, f"  + {d.get('ip',''):15s} {d.get('mac',''):18s} {d.get('manufacturer','')}")
                if label: result_text.insert(tk.END, f" ({label})")
                result_text.insert(tk.END, "\n")
            result_text.insert(tk.END, "\n")
        else:
            result_text.insert(tk.END, "No new devices found.\n\n")

        if missing_keys:
            result_text.insert(tk.END, f"MISSING DEVICES ({len(missing_keys)}):\n")
            for k in missing_keys:
                d = prev_by_key.get(k, {})
                label = self.device_labels.get(d.get('mac', ''), '') or self.device_labels.get(k, '')
                result_text.insert(tk.END, f"  - {d.get('ip',''):15s} {d.get('mac',''):18s} {d.get('manufacturer','')}")
                if label: result_text.insert(tk.END, f" ({label})")
                result_text.insert(tk.END, "\n")
            result_text.insert(tk.END, "\n")
        else:
            result_text.insert(tk.END, "No devices went offline.\n\n")

        if moved:
            result_text.insert(tk.END, f"IP CHANGES ({len(moved)}):\n")
            for k, prev_ip, curr_ip in moved:
                result_text.insert(tk.END, f"  ~ {prev_ip:15s} → {curr_ip:15s} ({k})\n")
            result_text.insert(tk.END, "\n")

        unchanged = current_keys & previous_keys
        result_text.insert(tk.END, f"UNCHANGED: {len(unchanged)} devices\n")
        result_text.config(state='disabled')

    def export_csv(self):
        if not self.found_devices:
            messagebox.showwarning("No Data", "No scan results to export.")
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scan_results_{timestamp}.csv"
        out_path = APP_DIR / filename

        try:
            with open(out_path, 'w', newline='') as f:
                f.write("Label,IP,Hostname,MAC,Manufacturer,Type,Ports,Last Seen,Watched\n")
                for device in self.found_devices:
                    mac = device['mac']
                    key = self.key_of(device)
                    label = self.device_labels.get(mac, '') or self.device_labels.get(key, '')
                    watched = 'Yes' if key in self.watch_list else 'No'
                    f.write(f'"{label}","{device["ip"]}","{device["hostname"]}",'
                            f'"{mac}","{device["manufacturer"]}","{device["type"]}",'
                            f'"{device["ports"]}","{device["last_seen"]}","{watched}"\n')

            self.log_message(f"Exported to {out_path}")
            messagebox.showinfo("Export Complete", f"Results exported to:\n{out_path}")
        except Exception as e:
            self.log_message(f"Export failed: {e}")
            messagebox.showerror("Export Failed", f"Could not export results:\n{e}")


def main():
    root = tk.Tk()
    app = IPScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()