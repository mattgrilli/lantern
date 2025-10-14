#!/usr/bin/env python3
"""
Lantern IP Scanner with Device Detection for Mac
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

class IPScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Lantern IP Scanner for MacOS")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)
        
        self.scanning = False
        self.monitoring = False
        self.scan_thread = None
        self.monitor_thread = None
        self.found_devices = []
        self.device_labels = {}  # MAC -> custom label
        self.watch_list = set()  # MACs to monitor
        self.scan_history = []  # List of historical scans
        self.profiles = {}  # Saved scan profiles
        
        # Load persistent data
        self.load_data()
        
        self.setup_ui()
        self.detect_local_network()
        
    def setup_ui(self):
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        # Title with monitoring indicator
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, pady=(0, 10), sticky=tk.W)
        
        title_label = ttk.Label(title_frame, text="Lantern Network Scanner Pro", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(side=tk.LEFT)
        
        self.monitor_indicator = ttk.Label(title_frame, text="", 
                                          font=('Arial', 10))
        self.monitor_indicator.pack(side=tk.LEFT, padx=(20, 0))
        
        # Input frame
        input_frame = ttk.LabelFrame(main_frame, text="Scan Configuration", padding="10")
        input_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(1, weight=1)
        
        # Network input with profile dropdown
        ttk.Label(input_frame, text="Network Range:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        network_profile_frame = ttk.Frame(input_frame)
        network_profile_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        network_profile_frame.columnconfigure(0, weight=1)
        
        self.network_var = tk.StringVar(value="192.168.1.0/24")
        network_entry = ttk.Entry(network_profile_frame, textvariable=self.network_var, width=30)
        network_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        # Profile buttons
        profile_btn_frame = ttk.Frame(network_profile_frame)
        profile_btn_frame.grid(row=0, column=1)
        
        ttk.Button(profile_btn_frame, text="Save Profile", 
                  command=self.save_profile, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(profile_btn_frame, text="Load Profile", 
                  command=self.load_profile_dialog, width=12).pack(side=tk.LEFT, padx=2)
        
        # Threads input
        ttk.Label(input_frame, text="Threads:").grid(row=0, column=2, sticky=tk.W, padx=(10, 10))
        self.threads_var = tk.StringVar(value="50")
        threads_spinbox = ttk.Spinbox(input_frame, from_=10, to=200, 
                                      textvariable=self.threads_var, width=10)
        threads_spinbox.grid(row=0, column=3, sticky=tk.W)
        
        # Deep scan option
        self.deep_scan_var = tk.BooleanVar(value=True)
        deep_scan_cb = ttk.Checkbutton(input_frame, text="Deep Scan (ports, MAC, manufacturer)", 
                                       variable=self.deep_scan_var)
        deep_scan_cb.grid(row=1, column=0, columnspan=4, pady=(10, 0), sticky=tk.W)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, pady=(0, 10))
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", 
                                     command=self.start_scan, style='Accent.TButton')
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", 
                                     command=self.stop_scan, state='disabled')
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.monitor_button = ttk.Button(button_frame, text="Start Monitoring", 
                                        command=self.toggle_monitoring)
        self.monitor_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Separator(button_frame, orient='vertical').pack(side=tk.LEFT, fill='y', padx=10)
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", 
                                      command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Compare Scans", 
                  command=self.compare_scans).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Export CSV", 
                  command=self.export_csv).pack(side=tk.LEFT, padx=5)
        
        ttk.Separator(button_frame, orient='vertical').pack(side=tk.LEFT, fill='y', padx=10)
        
        # Quick action buttons
        ttk.Label(button_frame, text="Quick:").pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Copy IP", 
                  command=lambda: self.copy_field('IP'), width=8).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(button_frame, text="Copy MAC", 
                  command=lambda: self.copy_field('MAC'), width=8).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(button_frame, text="Open Browser", 
                  command=lambda: self.open_device_browser(), width=12).pack(side=tk.LEFT, padx=2)
        
        # Filter frame with advanced options
        filter_frame = ttk.Frame(main_frame)
        filter_frame.grid(row=3, column=0, pady=(0, 10), sticky=(tk.W, tk.E))
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar()
        self.filter_var.trace('w', self.apply_filter)
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        # Advanced filter options
        ttk.Label(filter_frame, text="Show:").pack(side=tk.LEFT, padx=(10, 5))
        
        self.filter_type = tk.StringVar(value="all")
        ttk.Radiobutton(filter_frame, text="All", variable=self.filter_type, 
                       value="all", command=self.apply_filter).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(filter_frame, text="Printers", variable=self.filter_type, 
                       value="printers", command=self.apply_filter).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(filter_frame, text="Watched", variable=self.filter_type, 
                       value="watched", command=self.apply_filter).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(filter_frame, text="New", variable=self.filter_type, 
                       value="new", command=self.apply_filter).pack(side=tk.LEFT, padx=2)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, 
                                           maximum=100, mode='determinate')
        self.progress_bar.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Results area with Treeview
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        results_frame.grid(row=5, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Create Treeview with additional columns
        columns = ('Status', 'Label', 'IP', 'Hostname', 'MAC', 'Manufacturer', 'Type', 'Ports', 'Last Seen')
        self.tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        # Define headings
        self.tree.heading('Status', text='●')
        self.tree.heading('Label', text='Label')
        self.tree.heading('IP', text='IP Address')
        self.tree.heading('Hostname', text='Hostname')
        self.tree.heading('MAC', text='MAC Address')
        self.tree.heading('Manufacturer', text='Manufacturer')
        self.tree.heading('Type', text='Type')
        self.tree.heading('Ports', text='Open Ports')
        self.tree.heading('Last Seen', text='Last Seen')
        
        # Define column widths
        self.tree.column('Status', width=30)
        self.tree.column('Label', width=120)
        self.tree.column('IP', width=120)
        self.tree.column('Hostname', width=150)
        self.tree.column('MAC', width=130)
        self.tree.column('Manufacturer', width=150)
        self.tree.column('Type', width=80)
        self.tree.column('Ports', width=150)
        self.tree.column('Last Seen', width=140)
        
        # Bind events
        self.tree.bind('<Button-2>', self.show_context_menu)
        self.tree.bind('<Control-Button-1>', self.show_context_menu)
        self.tree.bind('<Double-1>', self.open_device_browser)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(results_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        vsb.grid(row=0, column=1, sticky=(tk.N, tk.S))
        hsb.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Create context menu
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
        
        # Log area
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="10")
        log_frame.grid(row=6, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        log_frame.columnconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=6, font=('Courier', 9))
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready to scan")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=7, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
    def load_data(self):
        """Load persistent data from file"""
        try:
            if os.path.exists('scanner_data.json'):
                with open('scanner_data.json', 'r') as f:
                    data = json.load(f)
                    self.device_labels = data.get('labels', {})
                    self.watch_list = set(data.get('watchlist', []))
                    self.profiles = data.get('profiles', {})
                    self.scan_history = data.get('history', [])
        except Exception as e:
            print(f"Could not load data: {e}")
    
    def save_data(self):
        """Save persistent data to file"""
        try:
            data = {
                'labels': self.device_labels,
                'watchlist': list(self.watch_list),
                'profiles': self.profiles,
                'history': self.scan_history[-50:]  # Keep last 50 scans
            }
            with open('scanner_data.json', 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.log_message(f"Could not save data: {e}")
    
    def save_profile(self):
        """Save current network range as a profile"""
        name = simpledialog.askstring("Save Profile", "Enter profile name:")
        if name:
            self.profiles[name] = {
                'network': self.network_var.get(),
                'threads': self.threads_var.get()
            }
            self.save_data()
            self.log_message(f"Saved profile: {name}")
            messagebox.showinfo("Profile Saved", f"Profile '{name}' saved successfully!")
    
    def load_profile_dialog(self):
        """Show dialog to load a saved profile"""
        if not self.profiles:
            messagebox.showinfo("No Profiles", "No saved profiles found.")
            return
        
        # Create simple dialog
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
    
    def detect_local_network(self):
        """Detect the actual local network using ifconfig"""
        try:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            output = result.stdout
            
            lines = output.split('\n')
            current_interface = None
            ip_address = None
            netmask = None
            
            for line in lines:
                if line and not line.startswith('\t') and not line.startswith(' '):
                    current_interface = line.split(':')[0]
                
                if '\tinet ' in line and '127.0.0.1' not in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'inet' and i + 1 < len(parts):
                            ip_address = parts[i + 1]
                        if part == 'netmask' and i + 1 < len(parts):
                            netmask = parts[i + 1]
                    
                    if ip_address and netmask:
                        if netmask.startswith('0x'):
                            netmask_int = int(netmask, 16)
                            cidr = bin(netmask_int).count('1')
                        else:
                            netmask_parts = netmask.split('.')
                            binary = ''.join([bin(int(x))[2:].zfill(8) for x in netmask_parts])
                            cidr = binary.count('1')
                        
                        network_obj = ipaddress.ip_network(f"{ip_address}/{cidr}", strict=False)
                        network = str(network_obj)
                        
                        self.network_var.set(network)
                        self.log_message(f"Detected interface: {current_interface}")
                        self.log_message(f"Your IP: {ip_address}/{cidr}")
                        self.log_message(f"Network range: {network}")
                        return
            
            raise Exception("Could not parse ifconfig output")
            
        except Exception as e:
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                ip_parts = local_ip.split('.')
                network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                self.network_var.set(network)
                self.log_message(f"Auto-detected network (fallback): {network}")
            except:
                self.log_message("Could not auto-detect network, using default")
    
    def log_message(self, message):
        """Add a message to the log text widget"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.update()
    
    def clear_results(self):
        """Clear the results"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.found_devices.clear()
        self.progress_var.set(0)
        self.status_var.set("Results cleared")
    
    def get_mac_address(self, ip):
        """Get MAC address using arp command"""
        try:
            subprocess.run(['ping', '-c', '1', '-W', '500', ip], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1)
            
            result = subprocess.run(['arp', '-n', ip], 
                                  capture_output=True, text=True, timeout=2)
            
            match = re.search(r'([0-9a-fA-F]{1,2}[:-]){5}([0-9a-fA-F]{1,2})', result.stdout)
            if match:
                return match.group(0).upper()
        except:
            pass
        return "Unknown"
    
    def get_manufacturer(self, mac):
        """Identify manufacturer from MAC address OUI"""
        if mac == "Unknown" or not mac:
            return "Unknown"
        
        oui_db = {
            '00:10:83': 'Hewlett Packard',
            '00:11:4B': 'Francotyp-Postalia',
            '00:15:17': 'Intel Corporate',
            '00:15:5D': 'Microsoft Corporation',
            '00:1E:58': 'D-Link Corporation',
            '00:23:7D': 'Hewlett Packard',
            '04:D5:90': 'Fortinet',
            '10:E7:C6': 'Hewlett Packard',
            '14:2F:FD': 'LT Security',
            '4C:56:DF': 'Targus',
            '64:16:7F': 'Polycom',
            '74:83:C2': 'Ubiquiti Networks',
            '9C:7B:EF': 'Hewlett Packard',
            '9C:93:4E': 'Xerox Corporation',
            'B0:5A:DA': 'Hewlett Packard',
            'BC:A5:11': 'NETGEAR',
            'D0:94:66': 'Dell Inc.',
            'E4:38:83': 'Ubiquiti Networks',
            '00:00:0C': 'Cisco',
            '00:01:42': 'Cisco',
            '00:50:56': 'VMware',
            '08:00:27': 'Oracle VirtualBox',
            '00:0D:93': 'Apple',
            '00:25:00': 'Apple',
            'AC:DE:48': 'Apple',
            '00:1B:63': 'Apple',
            '00:C0:EE': 'Xerox',
            '00:00:AA': 'Xerox',
            '08:00:87': 'Xerox',
            '00:DD:00': 'Xerox',
            '00:DD:01': 'Xerox',
            '00:DD:02': 'Xerox',
            '00:DD:B0': 'Xerox',
            '00:DD:B1': 'Xerox',
            '00:DD:B2': 'Xerox',
            '00:DD:B3': 'Xerox',
            '08:00:2B': 'DEC',
            '00:50:C2': 'IEEE 802.11',
            '00:1D:09': 'HP',
            '00:1F:29': 'HP',
            '00:21:5A': 'HP',
            '00:26:55': 'Brother',
            '00:80:77': 'Brother',
            '00:1B:A9': 'Brother',
            '00:04:F2': 'Canon',
            '00:00:85': 'Canon',
            '9C:E6:5E': 'Canon',
            '44:65:0D': 'Canon',
            '00:12:FB': 'Samsung',
            '00:1E:C2': 'Dell',
            '00:14:22': 'Dell',
            'B8:CA:3A': 'Dell',
            '00:0A:95': 'Belkin',
            '94:10:3E': 'Belkin',
            '00:1A:70': 'Netgear',
            '00:09:5B': 'Netgear',
        }
        
        oui = ':'.join(mac.split(':')[:3])
        return oui_db.get(oui.upper(), "Unknown")
    
    def identify_device_type(self, ports, manufacturer, hostname):
        """Identify device type based on ports and other info"""
        ports_lower = ports.lower()
        manufacturer_lower = manufacturer.lower()
        hostname_lower = hostname.lower()
        
        # Check for printers
        printer_indicators = ['515', '631', '9100', 'lpr', 'ipp']
        printer_manufacturers = ['xerox', 'hp', 'canon', 'brother', 'epson', 'kyocera']
        
        if any(ind in ports_lower for ind in printer_indicators):
            return 'Printer'
        if any(mfg in manufacturer_lower for mfg in printer_manufacturers):
            return 'Printer'
        if 'print' in hostname_lower:
            return 'Printer'
        
        # Check for network equipment
        if any(mfg in manufacturer_lower for mfg in ['cisco', 'netgear', 'ubiquiti', 'd-link', 'fortinet']):
            return 'Network'
        
        # Check for computers
        if '3389' in ports or 'rdp' in ports_lower:
            return 'Computer'
        if any(mfg in manufacturer_lower for mfg in ['dell', 'hp', 'apple', 'microsoft']):
            return 'Computer'
        
        # Check for servers
        if '80' in ports or '443' in ports or 'http' in ports_lower:
            return 'Server/Web'
        
        return 'Unknown'
    
    def scan_ports(self, ip):
        """Scan common ports on the host"""
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
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    open_ports.append(f"{port}({service})")
            except:
                pass
        
        return ', '.join(open_ports) if open_ports else 'None'
    
    def ping_host(self, ip):
        """Ping and gather detailed information about a host"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1000', str(ip)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
            if result.returncode == 0:
                hostname = "Unknown"
                try:
                    hostname = socket.gethostbyaddr(str(ip))[0]
                except:
                    pass
                
                device_info = {
                    'ip': str(ip),
                    'hostname': hostname,
                    'mac': 'Unknown',
                    'manufacturer': 'Unknown',
                    'ports': 'Skipped',
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
                        device_info['ports'], 
                        device_info['manufacturer'],
                        hostname
                    )
                
                return device_info
        except:
            pass
        return None
    
    def add_device_to_tree(self, device):
        """Add a device to the treeview"""
        mac = device['mac']
        label = self.device_labels.get(mac, '')
        is_watched = '★' if mac in self.watch_list else ''
        
        # Determine tag based on device status
        tags = []
        if device.get('is_new', False):
            tags.append('new')
        if mac in self.watch_list:
            tags.append('watched')
        
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
        ), tags=tuple(tags))
        
        # Configure tag colors with better contrast for dark mode
        self.tree.tag_configure('new', background='#4A90E2', foreground='white')  # Blue background
        self.tree.tag_configure('watched', foreground='#FFD700')  # Gold text for watched
        
        self.found_devices.append(device)
    
    def apply_filter(self, *args):
        """Filter the treeview based on search term and type"""
        search_term = self.filter_var.get().lower()
        filter_type = self.filter_type.get()
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for device in self.found_devices:
            # Apply type filter
            if filter_type == 'printers' and device['type'] != 'Printer':
                continue
            elif filter_type == 'watched' and device['mac'] not in self.watch_list:
                continue
            elif filter_type == 'new' and not device.get('is_new', False):
                continue
            
            # Apply text search filter
            if search_term:
                mac = device['mac']
                label = self.device_labels.get(mac, '')
                searchable = f"{device['ip']} {device['hostname']} {mac} {device['manufacturer']} {device['type']} {device['ports']} {label}".lower()
                if search_term not in searchable:
                    continue
            
            # Add to tree
            is_watched = '★' if device['mac'] in self.watch_list else ''
            label = self.device_labels.get(device['mac'], '')
            
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
        
        # Reapply tag colors
        self.tree.tag_configure('new', background='#4A90E2', foreground='white')
    
    def set_device_label(self):
        """Set a custom label for the selected device"""
        selection = self.tree.selection()
        if not selection:
            self.log_message("Please select a device first")
            return
        
        item = selection[0]
        values = self.tree.item(item)['values']
        mac = values[4]
        current_label = self.device_labels.get(mac, '')
        
        new_label = simpledialog.askstring("Set Device Label", 
                                          "Enter label/nickname:",
                                          initialvalue=current_label)
        if new_label is not None:
            if new_label.strip():
                self.device_labels[mac] = new_label.strip()
            else:
                self.device_labels.pop(mac, None)
            
            self.save_data()
            self.apply_filter()
            self.log_message(f"Label set for {mac}")
    
    def add_to_watchlist(self):
        """Add selected device to watch list"""
        selection = self.tree.selection()
        if not selection:
            self.log_message("Please select a device first")
            return
        
        item = selection[0]
        values = self.tree.item(item)['values']
        mac = values[4]
        
        self.watch_list.add(mac)
        self.save_data()
        self.apply_filter()
        self.log_message(f"Added {mac} to watch list")
    
    def remove_from_watchlist(self):
        """Remove selected device from watch list"""
        selection = self.tree.selection()
        if not selection:
            self.log_message("Please select a device first")
            return
        
        item = selection[0]
        values = self.tree.item(item)['values']
        mac = values[4]
        
        self.watch_list.discard(mac)
        self.save_data()
        self.apply_filter()
        self.log_message(f"Removed {mac} from watch list")
    
    def toggle_monitoring(self):
        """Toggle network monitoring mode"""
        if not self.monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        """Start continuous monitoring"""
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
        """Stop continuous monitoring"""
        self.monitoring = False
        self.monitor_button.config(text="Start Monitoring")
        self.monitor_indicator.config(text="")
        self.log_message("Stopped monitoring")
    
    def monitor_loop(self):
        """Background monitoring loop"""
        import time
        while self.monitoring:
            # Check each watched device
            for mac in list(self.watch_list):
                if not self.monitoring:
                    break
                
                # Find device info
                device = next((d for d in self.found_devices if d['mac'] == mac), None)
                if device:
                    # Ping the device
                    ip = device['ip']
                    try:
                        result = subprocess.run(
                            ['ping', '-c', '1', '-W', '1000', ip],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=2
                        )
                        
                        label = self.device_labels.get(mac, ip)
                        
                        if result.returncode == 0:
                            # Device is online
                            device['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            # Device is offline
                            self.log_message(f"⚠️  ALERT: {label} ({ip}) is OFFLINE")
                            # You could add system notification here
                    except:
                        pass
            
            # Wait 60 seconds before next check
            for _ in range(60):
                if not self.monitoring:
                    break
                time.sleep(1)
    
    def compare_scans(self):
        """Compare current scan with previous scans"""
        if len(self.scan_history) < 2:
            messagebox.showinfo("Compare Scans", 
                              "Need at least 2 saved scans to compare.\n\n"
                              "Scans are automatically saved after each scan completes.")
            return
        
        # Create comparison dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Compare Scans")
        dialog.geometry("600x400")
        
        ttk.Label(dialog, text="Scan Comparison", font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Get last two scans
        current_scan = self.scan_history[-1]
        previous_scan = self.scan_history[-2]
        
        current_macs = set(d['mac'] for d in current_scan['devices'])
        previous_macs = set(d['mac'] for d in previous_scan['devices'])
        
        new_devices = current_macs - previous_macs
        missing_devices = previous_macs - current_macs
        
        # Show results
        result_text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD, height=20)
        result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        result_text.insert(tk.END, f"Current Scan: {current_scan['timestamp']}\n")
        result_text.insert(tk.END, f"Previous Scan: {previous_scan['timestamp']}\n\n")
        result_text.insert(tk.END, "=" * 60 + "\n\n")
        
        if new_devices:
            result_text.insert(tk.END, f"NEW DEVICES ({len(new_devices)}):\n")
            for mac in new_devices:
                device = next((d for d in current_scan['devices'] if d['mac'] == mac), None)
                if device:
                    label = self.device_labels.get(mac, '')
                    result_text.insert(tk.END, f"  + {device['ip']:15s} {mac:18s} {device['manufacturer']}")
                    if label:
                        result_text.insert(tk.END, f" ({label})")
                    result_text.insert(tk.END, "\n")
            result_text.insert(tk.END, "\n")
        else:
            result_text.insert(tk.END, "No new devices found.\n\n")
        
        if missing_devices:
            result_text.insert(tk.END, f"MISSING DEVICES ({len(missing_devices)}):\n")
            for mac in missing_devices:
                device = next((d for d in previous_scan['devices'] if d['mac'] == mac), None)
                if device:
                    label = self.device_labels.get(mac, '')
                    result_text.insert(tk.END, f"  - {device['ip']:15s} {mac:18s} {device['manufacturer']}")
                    if label:
                        result_text.insert(tk.END, f" ({label})")
                    result_text.insert(tk.END, "\n")
            result_text.insert(tk.END, "\n")
        else:
            result_text.insert(tk.END, "No devices went offline.\n\n")
        
        unchanged = current_macs & previous_macs
        result_text.insert(tk.END, f"UNCHANGED: {len(unchanged)} devices\n")
        
        result_text.config(state='disabled')
    
    def export_csv(self):
        """Export results to CSV file"""
        if not self.found_devices:
            messagebox.showwarning("No Data", "No scan results to export.")
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scan_results_{timestamp}.csv"
        
        try:
            with open(filename, 'w') as f:
                # Write header
                f.write("Label,IP,Hostname,MAC,Manufacturer,Type,Ports,Last Seen,Watched\n")
                
                # Write data
                for device in self.found_devices:
                    mac = device['mac']
                    label = self.device_labels.get(mac, '')
                    watched = 'Yes' if mac in self.watch_list else 'No'
                    
                    f.write(f'"{label}","{device["ip"]}","{device["hostname"]}",'
                           f'"{mac}","{device["manufacturer"]}","{device["type"]}",'
                           f'"{device["ports"]}","{device["last_seen"]}","{watched}"\n')
            
            self.log_message(f"Exported to {filename}")
            messagebox.showinfo("Export Complete", f"Results exported to:\n{filename}")
        except Exception as e:
            self.log_message(f"Export failed: {e}")
            messagebox.showerror("Export Failed", f"Could not export results:\n{e}")
    
    def show_context_menu(self, event):
        """Show right-click context menu"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def copy_field(self, field_name):
        """Copy a specific field to clipboard"""
        selection = self.tree.selection()
        if not selection:
            self.log_message("Please select a device first")
            return
        
        item = selection[0]
        values = self.tree.item(item)['values']
        
        field_map = {
            'IP': 2,
            'Hostname': 3,
            'MAC': 4,
            'Manufacturer': 5
        }
        
        if field_name in field_map:
            value = values[field_map[field_name]]
            self.root.clipboard_clear()
            self.root.clipboard_append(str(value))
            self.log_message(f"Copied {field_name}: {value}")
            self.status_var.set(f"Copied {field_name} to clipboard")
    
    def copy_all_info(self):
        """Copy all information about selected device"""
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
        self.status_var.set("Copied all device info to clipboard")
    
    def open_device_browser(self, event=None, protocol='http'):
        """Open device web interface in default browser"""
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
            self.status_var.set(f"Opened {url}")
        except Exception as e:
            self.log_message(f"Could not open browser: {e}")
    
    def ping_selected_device(self):
        """Ping the selected device"""
        selection = self.tree.selection()
        if not selection:
            self.log_message("Please select a device first")
            return
        
        item = selection[0]
        values = self.tree.item(item)['values']
        ip = values[2]
        
        self.log_message(f"Pinging {ip}...")
        
        try:
            result = subprocess.run(
                ['ping', '-c', '4', ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            output_lines = result.stdout.split('\n')
            for line in output_lines:
                if 'packets transmitted' in line or 'min/avg/max' in line:
                    self.log_message(line.strip())
            
            self.status_var.set(f"Ping to {ip} complete")
        except Exception as e:
            self.log_message(f"Ping failed: {e}")
    
    def scan_network(self):
        """Perform the network scan"""
        try:
            network = self.network_var.get()
            max_workers = int(self.threads_var.get())
            
            self.log_message("=" * 60)
            self.log_message(f"Starting scan of {network}")
            self.log_message(f"Deep scan: {'Enabled' if self.deep_scan_var.get() else 'Disabled'}")
            self.log_message(f"Using {max_workers} threads")
            self.log_message("=" * 60)
            
            net = ipaddress.ip_network(network, strict=False)
            total_ips = net.num_addresses - 2
            
            # Mark existing devices as not new
            for device in self.found_devices:
                device['is_new'] = False
            
            previous_macs = set(d['mac'] for d in self.found_devices)
            completed = 0
            found_count = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self.ping_host, ip): ip for ip in net.hosts()}
                
                for future in concurrent.futures.as_completed(futures):
                    if not self.scanning:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    
                    completed += 1
                    result = future.result()
                    
                    if result:
                        found_count += 1
                        
                        # Check if this is a new device
                        if result['mac'] not in previous_macs:
                            result['is_new'] = True
                            self.log_message(f"🆕 NEW: {result['ip']} - {result['manufacturer']}")
                        else:
                            result['is_new'] = False
                            # Update existing device
                            existing = next((d for d in self.found_devices if d['mac'] == result['mac']), None)
                            if existing:
                                self.found_devices.remove(existing)
                        
                        self.add_device_to_tree(result)
                    
                    progress = (completed / total_ips) * 100
                    self.progress_var.set(progress)
                    self.status_var.set(f"Scanning... {completed}/{total_ips} IPs | Found: {found_count} devices")
            
            if self.scanning:
                self.log_message("=" * 60)
                self.log_message(f"Scan complete! Found {found_count} active device(s)")
                self.log_message("=" * 60)
                self.status_var.set(f"Scan complete - {found_count} devices found")
                
                # Save scan to history
                scan_record = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'network': network,
                    'devices': [d.copy() for d in self.found_devices]
                }
                self.scan_history.append(scan_record)
                self.save_data()
            else:
                self.log_message("Scan stopped by user")
                self.status_var.set("Scan stopped")
            
        except ValueError as e:
            self.log_message(f"Error: Invalid network format - {e}")
            self.status_var.set("Error: Invalid network format")
        except Exception as e:
            self.log_message(f"Error: {e}")
            self.status_var.set(f"Error: {e}")
        finally:
            self.scanning = False
            self.scan_button.config(state='normal')
            self.stop_button.config(state='disabled')
    
    def start_scan(self):
        """Start the scan in a separate thread"""
        if not self.scanning:
            self.scanning = True
            self.scan_button.config(state='disabled')
            self.stop_button.config(state='normal')
            self.progress_var.set(0)
            
            self.scan_thread = threading.Thread(target=self.scan_network, daemon=True)
            self.scan_thread.start()
    
    def stop_scan(self):
        """Stop the current scan"""
        self.scanning = False
        self.status_var.set("Stopping scan...")
        self.stop_button.config(state='disabled')

def main():
    root = tk.Tk()
    app = IPScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()