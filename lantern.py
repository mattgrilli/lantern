#!/usr/bin/env python3
"""
Lantern - a network scanner with device labels, watch-list monitoring and scan history.

Runs on macOS, Windows and Linux using only the Python standard library.
Installing the optional `zeroconf` package adds mDNS printer discovery on every
platform (macOS already gets it through `dns-sd`).
"""

__version__ = "2.0.0"

import concurrent.futures
import csv
import ipaddress
import json
import os
import queue
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
import tkinter.font as tkfont

import netscan
from netscan import UNKNOWN, device_key

APP_DIR = Path(netscan.app_data_dir())
STATE_FILE = APP_DIR / "scanner_data.json"
HISTORY_LIMIT = 50
MONITOR_INTERVAL = 60         # seconds between watch-list checks
LARGE_SCAN_WARNING = 4096     # ask before scanning more hosts than this

COLUMNS = ("Status", "Label", "IP", "Hostname", "MAC", "Manufacturer", "Type", "Ports", "Last Seen")
HEADINGS = {"Status": "●", "IP": "IP Address", "MAC": "MAC Address", "Ports": "Open Ports"}
WIDTHS = {"Status": 40, "Label": 130, "IP": 115, "Hostname": 170, "MAC": 135,
          "Manufacturer": 130, "Type": 110, "Ports": 200, "Last Seen": 150}
DEVICE_TYPES = ("Computer", "Server", "Server/Web", "Printer", "Network", "NAS/Storage", "Mobile",
                "Smart Device", "IoT Device", "Virtual Machine")
FIELD_FOR_COLUMN = {"Label": None, "IP": "ip", "Hostname": "hostname", "MAC": "mac",
                    "Manufacturer": "manufacturer", "Type": "type", "Ports": "ports", "Last Seen": "last_seen"}


class LanternApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Lantern {__version__}")
        self.root.geometry("1250x820")
        self.root.minsize(900, 600)

        self.scanning = False
        self.monitoring = False
        self.stop_event = threading.Event()
        self.devices = {}             # device key -> device dict (insertion order = discovery order)
        self.device_labels = {}       # MAC or device key -> label
        self.device_notes = {}        # MAC or device key -> free-form notes
        self.type_overrides = {}      # MAC or device key -> device type chosen by the user
        self.watch_list = set()       # device keys
        self.scan_history = []        # [{'timestamp', 'network', 'devices': [...]}]
        self.profiles = {}            # name -> {'network', 'threads', 'deep_scan'}
        self.monitor_state = {}       # device key -> last known up/down
        self.sort_column, self.sort_reverse = "IP", False

        # Worker threads hand UI work to the main thread through this queue;
        # Tk itself must only be touched from the main thread.
        self._ui_queue = queue.Queue()

        APP_DIR.mkdir(parents=True, exist_ok=True)
        self.load_data()
        self.setup_ui()
        self.root.after(50, self._drain_ui_queue)
        self.detect_local_network()
        backend = netscan.mdns_backend()
        if backend:
            self.log_message(f"mDNS printer discovery: {backend}")
        else:
            self.log_message("mDNS printer discovery is off (optional: pip install zeroconf)")

    # ----------------- Thread-safe UI dispatch -----------------
    def ui(self, fn, *args, **kwargs):
        """Run `fn` on the Tk main thread."""
        if threading.current_thread() is threading.main_thread():
            fn(*args, **kwargs)
        else:
            self._ui_queue.put((fn, args, kwargs))

    def _drain_ui_queue(self):
        try:
            for _ in range(500):
                fn, args, kwargs = self._ui_queue.get_nowait()
                fn(*args, **kwargs)
        except queue.Empty:
            pass
        self.root.after(50, self._drain_ui_queue)

    # ----------------- UI setup -----------------
    def setup_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(5, weight=1)

        # Title
        title = ttk.Frame(main)
        title.grid(row=0, column=0, pady=(0, 10), sticky="w")
        title_font = tkfont.nametofont("TkDefaultFont").copy()
        title_font.configure(size=16, weight="bold")
        ttk.Label(title, text="🏮 Lantern", font=title_font).pack(side=tk.LEFT)
        ttk.Label(title, text=f"v{__version__}", foreground="gray").pack(side=tk.LEFT, padx=(8, 0), pady=(6, 0))
        self.monitor_indicator = ttk.Label(title, text="", foreground="red")
        self.monitor_indicator.pack(side=tk.LEFT, padx=(20, 0))

        # Scan configuration
        config = ttk.LabelFrame(main, text="Scan Configuration", padding=10)
        config.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        config.columnconfigure(1, weight=1)
        ttk.Label(config, text="Targets:").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.network_var = tk.StringVar(value="192.168.1.0/24")
        target_entry = ttk.Entry(config, textvariable=self.network_var)
        target_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5))
        target_entry.bind("<Return>", lambda e: self.start_scan())
        ttk.Button(config, text="Save Profile", command=self.save_profile).grid(row=0, column=2, padx=2)
        ttk.Button(config, text="Load Profile", command=self.load_profile_dialog).grid(row=0, column=3, padx=2)
        ttk.Label(config, text="Threads:").grid(row=0, column=4, sticky="w", padx=(15, 5))
        self.threads_var = tk.StringVar(value="50")
        ttk.Spinbox(config, from_=1, to=256, textvariable=self.threads_var, width=6).grid(row=0, column=5, sticky="w")
        ttk.Label(config, text="CIDR, range or list — e.g. 192.168.1.0/24, 10.0.0.1-50, 10.0.0.5",
                  foreground="gray").grid(row=1, column=1, sticky="w", pady=(4, 0))
        self.deep_scan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(config, text="Deep scan (MAC, manufacturer, open ports)",
                        variable=self.deep_scan_var).grid(row=2, column=0, columnspan=6, pady=(8, 0), sticky="w")

        # Controls
        buttons = ttk.Frame(main)
        buttons.grid(row=2, column=0, pady=(0, 10), sticky="w")
        self.scan_button = ttk.Button(buttons, text="▶ Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 5))
        self.stop_button = ttk.Button(buttons, text="■ Stop", command=self.stop_scan, state="disabled")
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.monitor_button = ttk.Button(buttons, text="👁 Start Monitoring", command=self.toggle_monitoring)
        self.monitor_button.pack(side=tk.LEFT, padx=5)
        ttk.Separator(buttons, orient="vertical").pack(side=tk.LEFT, fill="y", padx=10)
        ttk.Button(buttons, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons, text="📊 Compare Scans", command=self.compare_scans).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons, text="📄 Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=5)

        # Filters
        filters = ttk.Frame(main)
        filters.grid(row=3, column=0, pady=(0, 10), sticky="ew")
        ttk.Label(filters, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.refresh_tree())
        self.filter_entry = ttk.Entry(filters, textvariable=self.filter_var, width=30)
        self.filter_entry.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(filters, text="Show:").pack(side=tk.LEFT, padx=(10, 5))
        self.filter_type = tk.StringVar(value="all")
        for text, value in (("All", "all"), ("Printers", "printers"), ("Watched", "watched"),
                            ("New", "new"), ("Offline", "offline")):
            ttk.Radiobutton(filters, text=text, variable=self.filter_type, value=value,
                            command=self.refresh_tree).pack(side=tk.LEFT, padx=2)
        self.count_var = tk.StringVar()
        ttk.Label(filters, textvariable=self.count_var, foreground="gray").pack(side=tk.RIGHT)

        # Progress
        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(main, variable=self.progress_var, maximum=100).grid(row=4, column=0, sticky="ew", pady=(0, 10))

        # Results
        results = ttk.LabelFrame(main, text="Devices", padding=10)
        results.grid(row=5, column=0, sticky="nsew")
        results.columnconfigure(0, weight=1)
        results.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(results, columns=COLUMNS, show="headings", height=15)
        for col in COLUMNS:
            self.tree.heading(col, text=HEADINGS.get(col, col), command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=WIDTHS[col], anchor="center" if col == "Status" else "w",
                             stretch=col not in ("Status",))
        self.tree.tag_configure("new", background="#4A90E2", foreground="white")
        self.tree.tag_configure("watched", foreground="#B8860B")
        self.tree.tag_configure("offline", foreground="#999999")
        vsb = ttk.Scrollbar(results, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(results, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        # Right click is Button-3, except on macOS with Tk 8.6, which reports it as Button-2.
        self.tree.bind("<Button-3>", self.show_context_menu)
        if netscan.IS_MAC:
            self.tree.bind("<Button-2>", self.show_context_menu)
            self.tree.bind("<Control-Button-1>", self.show_context_menu)
        self.tree.bind("<Double-1>", lambda e: self.open_device_browser())

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Set Label…", command=self.set_device_label)
        menu.add_command(label="Edit Notes…", command=self.edit_device_notes)
        type_menu = tk.Menu(menu, tearoff=0)
        for dev_type in DEVICE_TYPES:
            type_menu.add_command(label=dev_type, command=lambda t=dev_type: self.set_device_type(t))
        type_menu.add_separator()
        type_menu.add_command(label="Automatic", command=lambda: self.set_device_type(None))
        menu.add_cascade(label="Set Type", menu=type_menu)
        menu.add_command(label="Toggle Watch List", command=self.toggle_watch)
        menu.add_separator()
        menu.add_command(label="Copy IP Address", command=lambda: self.copy_field("ip"))
        menu.add_command(label="Copy MAC Address", command=lambda: self.copy_field("mac"))
        menu.add_command(label="Copy Hostname", command=lambda: self.copy_field("hostname"))
        menu.add_command(label="Copy All Info", command=self.copy_all_info)
        menu.add_separator()
        menu.add_command(label="Open in Browser (HTTP)", command=lambda: self.open_device_browser("http"))
        menu.add_command(label="Open in Browser (HTTPS)", command=lambda: self.open_device_browser("https"))
        menu.add_command(label="Ping Device", command=self.ping_selected_device)
        self.context_menu = menu

        # Log & status
        log_frame = ttk.LabelFrame(main, text="Activity Log", padding=10)
        log_frame.grid(row=6, column=0, sticky="ew", pady=(10, 0))
        log_frame.columnconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=7, font="TkFixedFont")
        self.log_text.grid(row=0, column=0, sticky="ew")
        self.status_var = tk.StringVar(value="Ready to scan")
        ttk.Label(main, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w").grid(
            row=7, column=0, sticky="ew", pady=(10, 0))

        # Keyboard shortcuts (Cmd on macOS, Ctrl elsewhere)
        mod = "Command" if netscan.IS_MAC else "Control"
        self.root.bind(f"<{mod}-r>", lambda e: self.start_scan())
        self.root.bind(f"<{mod}-f>", lambda e: self.filter_entry.focus_set())
        self.root.bind(f"<{mod}-e>", lambda e: self.export_csv())
        self.root.bind("<Escape>", lambda e: self.stop_scan() if self.scanning else None)

    # ----------------- Persistence -----------------
    def load_data(self):
        if not STATE_FILE.exists():
            return
        try:
            with open(STATE_FILE, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            print(f"Could not load {STATE_FILE}: {e}")
            return
        # The old Windows build used different key names; read either.
        self.device_labels = data.get("labels", data.get("device_labels", {}))
        self.device_notes = data.get("notes", {})
        self.type_overrides = data.get("types", {})
        self.watch_list = set(data.get("watchlist", data.get("watch_list", [])))
        self.profiles = data.get("profiles", {})
        self.scan_history = data.get("history", data.get("scan_history", []))

    def save_data(self):
        data = {
            "version": __version__,
            "labels": self.device_labels,
            "notes": self.device_notes,
            "types": self.type_overrides,
            "watchlist": sorted(self.watch_list),
            "profiles": self.profiles,
            "history": self.scan_history[-HISTORY_LIMIT:],
        }
        try:
            tmp = STATE_FILE.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, STATE_FILE)  # atomic, so a crash can't leave half a file
        except OSError as e:
            self.log_message(f"Could not save data: {e}")

    # ----------------- Profiles -----------------
    def save_profile(self):
        name = simpledialog.askstring("Save Profile", "Profile name:", parent=self.root)
        if not name:
            return
        self.profiles[name] = {"network": self.network_var.get(), "threads": self.threads_var.get(),
                               "deep_scan": self.deep_scan_var.get()}
        self.save_data()
        self.log_message(f"Saved profile: {name}")

    def load_profile_dialog(self):
        if not self.profiles:
            messagebox.showinfo("No Profiles", "No saved profiles yet.")
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Load Profile")
        dialog.geometry("320x260")
        dialog.transient(self.root)
        ttk.Label(dialog, text="Select a profile:").pack(pady=10)
        listbox = tk.Listbox(dialog)
        listbox.pack(fill=tk.BOTH, expand=True, padx=10)
        names = sorted(self.profiles)
        for name in names:
            listbox.insert(tk.END, f"{name}  —  {self.profiles[name].get('network', '')}")

        def selected_name():
            sel = listbox.curselection()
            return names[sel[0]] if sel else None

        def load():
            name = selected_name()
            if name:
                profile = self.profiles[name]
                self.network_var.set(profile.get("network", ""))
                self.threads_var.set(profile.get("threads", "50"))
                self.deep_scan_var.set(profile.get("deep_scan", True))
                self.log_message(f"Loaded profile: {name}")
                dialog.destroy()

        def delete():
            name = selected_name()
            if name and messagebox.askyesno("Delete Profile", f"Delete profile '{name}'?", parent=dialog):
                del self.profiles[name]
                self.save_data()
                dialog.destroy()
                if self.profiles:
                    self.load_profile_dialog()

        listbox.bind("<Double-1>", lambda e: load())
        row = ttk.Frame(dialog)
        row.pack(pady=8)
        ttk.Button(row, text="Load", command=load).pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="Delete", command=delete).pack(side=tk.LEFT, padx=4)

    # ----------------- Network detection -----------------
    def detect_local_network(self):
        network, ip = netscan.detect_local_network()
        if network:
            self.network_var.set(str(network))
            self.log_message(f"Your IP: {ip} — scanning range set to {network}")
        else:
            self.log_message("Could not detect the local network; using 192.168.1.0/24")

    # ----------------- Logging -----------------
    def log_message(self, message):
        ts = datetime.now().strftime("%H:%M:%S")

        def _do():
            self.log_text.insert(tk.END, f"[{ts}] {message}\n")
            self.log_text.see(tk.END)
        self.ui(_do)

    def set_status(self, text):
        self.ui(self.status_var.set, text)

    # ----------------- Device helpers -----------------
    @staticmethod
    def _lookup(store, dev):
        """Per-device user data is stored under the MAC and the device key; either may match."""
        return store.get(dev.get("mac"), "") or store.get(device_key(dev["ip"], dev.get("mac")), "")

    @staticmethod
    def _store(store, dev, value):
        key = device_key(dev["ip"], dev.get("mac"))
        for k in {key, dev.get("mac")} - {None, UNKNOWN}:
            if value:
                store[k] = value
            else:
                store.pop(k, None)

    def label_for(self, dev):
        return self._lookup(self.device_labels, dev)

    def type_for(self, dev):
        return self._lookup(self.type_overrides, dev) or dev.get("type", UNKNOWN)

    def _row_values(self, dev):
        key = device_key(dev["ip"], dev.get("mac"))
        status = ("★ " if key in self.watch_list else "") + ("○" if dev.get("online") is False else "●")
        return (status, self.label_for(dev), dev["ip"], dev.get("hostname", UNKNOWN), dev.get("mac", UNKNOWN),
                dev.get("manufacturer", UNKNOWN), self.type_for(dev), dev.get("ports", ""), dev.get("last_seen", ""))

    def _row_tags(self, dev):
        key = device_key(dev["ip"], dev.get("mac"))
        tags = []
        if dev.get("online") is False:
            tags.append("offline")
        elif dev.get("is_new"):
            tags.append("new")
        if key in self.watch_list:
            tags.append("watched")
        return tuple(tags)

    def _matches_filter(self, key, dev):
        kind = self.filter_type.get()
        if kind == "printers" and self.type_for(dev) != "Printer":
            return False
        if kind == "watched" and key not in self.watch_list:
            return False
        if kind == "new" and not dev.get("is_new"):
            return False
        if kind == "offline" and dev.get("online") is not False:
            return False
        term = self.filter_var.get().strip().lower()
        if term:
            haystack = " ".join(str(v) for v in self._row_values(dev) + (self._lookup(self.device_notes, dev),)).lower()
            return term in haystack
        return True

    def _sort_key(self, dev):
        col = self.sort_column
        if col == "IP":
            return int(ipaddress.IPv4Address(dev["ip"]))
        if col == "Label":
            return (self.label_for(dev) == "", self.label_for(dev).lower())
        if col == "Type":
            return self.type_for(dev).lower()
        if col == "Status":
            key = device_key(dev["ip"], dev.get("mac"))
            return (key not in self.watch_list, dev.get("online") is False)
        return str(dev.get(FIELD_FOR_COLUMN[col], "")).lower()

    def refresh_tree(self):
        """Rebuild the table from self.devices using the current filter and sort."""
        selected = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        shown = [(k, d) for k, d in self.devices.items() if self._matches_filter(k, d)]
        shown.sort(key=lambda kd: self._sort_key(kd[1]), reverse=self.sort_reverse)
        for key, dev in shown:
            self.tree.insert("", tk.END, iid=key, values=self._row_values(dev), tags=self._row_tags(dev))
        keep = [k for k in selected if self.tree.exists(k)]
        if keep:
            self.tree.selection_set(keep)
        self._update_count(len(shown))

    def _update_count(self, shown=None):
        total = len(self.devices)
        shown = len(self.tree.get_children()) if shown is None else shown
        online = sum(1 for d in self.devices.values() if d.get("online") is not False)
        self.count_var.set(f"{shown} shown · {online} online · {total} total")

    def update_row(self, key):
        """Insert, update or remove one device's row without rebuilding the table."""
        dev = self.devices.get(key)
        if dev is None or not self._matches_filter(key, dev):
            if self.tree.exists(key):
                self.tree.delete(key)
        elif self.tree.exists(key):
            self.tree.item(key, values=self._row_values(dev), tags=self._row_tags(dev))
        else:
            self.tree.insert("", tk.END, iid=key, values=self._row_values(dev), tags=self._row_tags(dev))
        self._update_count()

    def sort_by(self, column):
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column, self.sort_reverse = column, False
        for col in COLUMNS:
            arrow = (" ▼" if self.sort_reverse else " ▲") if col == column else ""
            self.tree.heading(col, text=HEADINGS.get(col, col) + arrow)
        self.refresh_tree()

    def selected_device(self):
        sel = self.tree.selection()
        if not sel:
            self.set_status("Select a device first")
            return None, None
        return sel[0], self.devices.get(sel[0])

    def clear_results(self):
        self.devices.clear()
        self.refresh_tree()
        self.progress_var.set(0)
        self.set_status("Results cleared")

    # ----------------- Device actions -----------------
    def show_context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def set_device_label(self):
        key, dev = self.selected_device()
        if not dev:
            return
        new_label = simpledialog.askstring("Set Label", f"Label for {dev['ip']}:",
                                           initialvalue=self.label_for(dev), parent=self.root)
        if new_label is None:
            return
        new_label = new_label.strip()
        self._store(self.device_labels, dev, new_label)
        self.save_data()
        self.update_row(key)
        self.log_message(f"Label for {dev['ip']}: {new_label or '(cleared)'}")

    def edit_device_notes(self):
        key, dev = self.selected_device()
        if not dev:
            return
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Notes — {self.label_for(dev) or dev['ip']}")
        dialog.geometry("420x260")
        dialog.transient(self.root)
        box = scrolledtext.ScrolledText(dialog, wrap=tk.WORD, height=8)
        box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        box.insert("1.0", self._lookup(self.device_notes, dev))
        box.focus_set()

        def save():
            self._store(self.device_notes, dev, box.get("1.0", tk.END).strip())
            self.save_data()
            self.log_message(f"Notes saved for {dev['ip']}")
            dialog.destroy()
        ttk.Button(dialog, text="Save", command=save).pack(pady=(0, 10))

    def set_device_type(self, dev_type):
        key, dev = self.selected_device()
        if not dev:
            return
        self._store(self.type_overrides, dev, dev_type)
        self.save_data()
        self.update_row(key)
        self.log_message(f"Type for {dev['ip']}: {dev_type or 'automatic'}")

    def toggle_watch(self):
        key, dev = self.selected_device()
        if not dev:
            return
        if key in self.watch_list:
            self.watch_list.discard(key)
            self.monitor_state.pop(key, None)
            self.log_message(f"Removed from watch list: {dev['ip']}")
        else:
            self.watch_list.add(key)
            self.log_message(f"Added to watch list: {dev['ip']}")
        self.save_data()
        self.update_row(key)

    def copy_field(self, field):
        _, dev = self.selected_device()
        if not dev:
            return
        value = str(dev.get(field, ""))
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.set_status(f"Copied {value}")

    def copy_all_info(self):
        _, dev = self.selected_device()
        if not dev:
            return
        info = "\n".join([
            f"Label: {self.label_for(dev)}", f"IP Address: {dev['ip']}", f"Hostname: {dev.get('hostname')}",
            f"MAC Address: {dev.get('mac')}", f"Manufacturer: {dev.get('manufacturer')}",
            f"Type: {self.type_for(dev)}", f"Open Ports: {dev.get('ports')}", f"Last Seen: {dev.get('last_seen')}",
        ] + ([f"Notes: {self._lookup(self.device_notes, dev)}"] if self._lookup(self.device_notes, dev) else []))
        self.root.clipboard_clear()
        self.root.clipboard_append(info)
        self.set_status("Copied all device info")

    def open_device_browser(self, protocol="http"):
        _, dev = self.selected_device()
        if not dev:
            return
        url = f"{protocol}://{dev['ip']}"
        webbrowser.open(url)
        self.log_message(f"Opened {url}")

    def ping_selected_device(self):
        _, dev = self.selected_device()
        if not dev:
            return
        ip = dev["ip"]
        self.log_message(f"Pinging {ip}…")

        def work():
            try:
                for line in netscan.ping_summary(ip):
                    self.log_message(f"  {line}")
            except Exception as e:
                self.log_message(f"Ping failed: {e}")
        threading.Thread(target=work, daemon=True).start()

    # ----------------- Scanning -----------------
    def start_scan(self):
        if self.scanning:
            return
        target = self.network_var.get().strip()
        try:
            hosts = netscan.parse_targets(target)
        except ValueError as e:
            messagebox.showerror("Invalid Targets", f"Couldn't understand '{target}':\n{e}")
            return
        try:
            workers = max(1, min(256, int(self.threads_var.get())))
        except ValueError:
            messagebox.showerror("Invalid Threads", "Threads must be a whole number.")
            return
        if len(hosts) > LARGE_SCAN_WARNING and not messagebox.askyesno(
                "Large Scan", f"This will scan {len(hosts):,} addresses and may take a long time. Continue?"):
            return

        self.scanning = True
        self.stop_event.clear()
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress_var.set(0)
        deep = self.deep_scan_var.get()
        threading.Thread(target=self.scan_network, args=(target, hosts, workers, deep), daemon=True).start()

    def stop_scan(self):
        if self.scanning:
            self.stop_event.set()
            self.set_status("Stopping scan…")
            self.stop_button.config(state="disabled")

    def _previous_scan(self):
        """(keys, ips) seen in the last saved scan, used to flag new devices."""
        if not self.scan_history:
            return None, None
        devices = self.scan_history[-1]["devices"]
        return ({device_key(d["ip"], d.get("mac")) for d in devices}, {d["ip"] for d in devices})

    def _is_new(self, key, ip, prev_keys, prev_ips):
        if prev_keys is None:
            return False  # first scan ever: nothing to compare against
        if key.startswith("IP::"):
            return ip not in prev_ips
        return key not in prev_keys

    def scan_network(self, target, hosts, workers, deep):
        """Runs on a worker thread."""
        started = time.monotonic()
        self.log_message("=" * 50)
        self.log_message(f"Scanning {target} — {len(hosts):,} addresses, {workers} threads, "
                         f"deep scan {'on' if deep else 'off'}")

        printer_ips = set()
        if netscan.mdns_backend():
            self.set_status("Looking for printers via mDNS…")
            printer_ips = netscan.discover_printer_ips(seconds=2)
            if printer_ips:
                self.log_message(f"mDNS found {len(printer_ips)} printer(s): {', '.join(sorted(printer_ips))}")
                # Probe advertised printers first so they appear right away.
                first = [h for h in hosts if str(h) in printer_ips]
                hosts = first + [h for h in hosts if str(h) not in printer_ips]

        prev_keys, prev_ips = self._previous_scan()
        seen = {}
        completed = 0
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        try:
            futures = [executor.submit(self._probe, ip, deep, printer_ips) for ip in hosts]
            for future in concurrent.futures.as_completed(futures):
                if self.stop_event.is_set():
                    break
                completed += 1
                try:
                    dev = future.result()
                except Exception as e:
                    self.log_message(f"Probe error: {e}")
                    dev = None
                if dev:
                    key = device_key(dev["ip"], dev["mac"])
                    dev["is_new"] = self._is_new(key, dev["ip"], prev_keys, prev_ips)
                    dev["online"] = True
                    seen[key] = dev
                    if dev["is_new"]:
                        self.log_message(f"🆕 New device: {dev['ip']} {dev['hostname']} ({dev['manufacturer']})")
                    self.ui(self._record_device, key, dev)
                if completed % 4 == 0 or completed == len(hosts):
                    self.ui(self.progress_var.set, completed / len(hosts) * 100)
                    self.set_status(f"Scanning… {completed:,}/{len(hosts):,} addresses · {len(seen)} found")
        finally:
            # Don't wait for queued probes after a stop; running ones finish on their own.
            executor.shutdown(wait=False, cancel_futures=True)

        elapsed = time.monotonic() - started
        stopped = self.stop_event.is_set()
        self.ui(self._finish_scan, target, hosts, seen, stopped, elapsed)

    def _probe(self, ip, deep, printer_ips):
        if self.stop_event.is_set():
            return None
        return netscan.probe_host(ip, deep=deep, known_printers=printer_ips)

    def _record_device(self, key, dev):
        """Main thread: merge a freshly found device into the table."""
        # An IP now answering with a different identity replaces the stale entry
        # (e.g. the same host scanned before with deep scan off).
        for old_key in [k for k, d in self.devices.items() if d["ip"] == dev["ip"] and k != key]:
            del self.devices[old_key]
            if self.tree.exists(old_key):
                self.tree.delete(old_key)
        self.devices[key] = dev
        self.update_row(key)

    def _finish_scan(self, target, hosts, seen, stopped, elapsed):
        """Main thread: wrap up a scan."""
        self.scanning = False
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")
        if stopped:
            self.log_message(f"Scan stopped — {len(seen)} device(s) found so far")
            self.set_status("Scan stopped")
            self.refresh_tree()
            return

        # Anything from earlier in this session that's in range but didn't answer is offline now.
        scanned = {str(h) for h in hosts}
        gone = 0
        for key, dev in self.devices.items():
            if key not in seen and dev["ip"] in scanned and dev.get("online") is not False:
                dev["online"] = False
                gone += 1
        self.progress_var.set(100)
        self.refresh_tree()

        new = sum(1 for d in seen.values() if d.get("is_new"))
        summary = f"Scan complete in {elapsed:.0f}s — {len(seen)} device(s)"
        if new:
            summary += f", {new} new"
        if gone:
            summary += f", {gone} no longer responding"
        self.log_message(summary)
        self.set_status(summary)

        record = [{k: v for k, v in d.items() if k not in ("is_new", "online")} for d in seen.values()]
        self.scan_history.append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                  "network": target, "devices": record})
        self.scan_history = self.scan_history[-HISTORY_LIMIT:]
        self.save_data()

    # ----------------- Monitoring -----------------
    def toggle_monitoring(self):
        if self.monitoring:
            self.stop_monitoring()
        else:
            self.start_monitoring()

    def start_monitoring(self):
        if not self.watch_list:
            messagebox.showinfo("No Watched Devices",
                                "Right-click a device and choose 'Toggle Watch List' to watch it.")
            return
        self.monitoring = True
        self.monitor_state.clear()
        self.monitor_button.config(text="👁 Stop Monitoring")
        self.monitor_indicator.config(text="● MONITORING")
        self.log_message(f"Monitoring {len(self.watch_list)} device(s) every {MONITOR_INTERVAL}s")
        threading.Thread(target=self.monitor_loop, daemon=True).start()

    def stop_monitoring(self):
        self.monitoring = False
        self.monitor_button.config(text="👁 Start Monitoring")
        self.monitor_indicator.config(text="")
        self.log_message("Stopped monitoring")

    def _watched_ip(self, key):
        """Current IP for a watched device: this session's scan, else history, else the key itself."""
        dev = self.devices.get(key)
        if dev:
            return dev["ip"]
        for scan in reversed(self.scan_history):
            for d in scan["devices"]:
                if device_key(d["ip"], d.get("mac")) == key:
                    return d["ip"]
        return key[4:] if key.startswith("IP::") else None

    def monitor_loop(self):
        """Runs on a worker thread. Logs only when a device changes state."""
        while self.monitoring:
            for key in list(self.watch_list):
                if not self.monitoring:
                    return
                ip = self._watched_ip(key)
                if not ip:
                    continue
                up = netscan.ping(ip, timeout=1.5)
                was_up = self.monitor_state.get(key)
                self.monitor_state[key] = up
                if up == was_up:
                    continue
                name = self.device_labels.get(key) or ip
                if not up:
                    self.log_message(f"⚠️  ALERT: {name} ({ip}) is OFFLINE")
                    self.ui(self.root.bell)
                elif was_up is False:
                    self.log_message(f"✅ {name} ({ip}) is back online")
                self.ui(self._set_online, key, up)
            for _ in range(MONITOR_INTERVAL):
                if not self.monitoring:
                    return
                time.sleep(1)

    def _set_online(self, key, up):
        dev = self.devices.get(key)
        if dev:
            dev["online"] = up
            if up:
                dev["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.update_row(key)

    # ----------------- Compare / Export -----------------
    def compare_scans(self):
        if len(self.scan_history) < 2:
            messagebox.showinfo("Compare Scans", "Need at least 2 completed scans to compare.\n\n"
                                                 "Scans are saved automatically when they finish.")
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Compare Scans")
        dialog.geometry("760x520")
        dialog.transient(self.root)

        labels = [f"{s['timestamp']}  ·  {s.get('network', '')}  ·  {len(s['devices'])} devices"
                  for s in self.scan_history]
        pick = ttk.Frame(dialog, padding=10)
        pick.pack(fill=tk.X)
        ttk.Label(pick, text="Older:").grid(row=0, column=0, sticky="w")
        older = ttk.Combobox(pick, values=labels, state="readonly", width=70)
        older.grid(row=0, column=1, sticky="ew", pady=2)
        older.current(len(labels) - 2)
        ttk.Label(pick, text="Newer:").grid(row=1, column=0, sticky="w")
        newer = ttk.Combobox(pick, values=labels, state="readonly", width=70)
        newer.grid(row=1, column=1, sticky="ew", pady=2)
        newer.current(len(labels) - 1)

        text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD, font="TkFixedFont")
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        def render(*_):
            text.config(state="normal")
            text.delete("1.0", tk.END)
            text.insert(tk.END, self.comparison_report(self.scan_history[older.current()],
                                                       self.scan_history[newer.current()]))
            text.config(state="disabled")
        older.bind("<<ComboboxSelected>>", render)
        newer.bind("<<ComboboxSelected>>", render)
        render()

    def comparison_report(self, old, new):
        old_by = {device_key(d["ip"], d.get("mac")): d for d in old["devices"]}
        new_by = {device_key(d["ip"], d.get("mac")): d for d in new["devices"]}
        added = sorted(set(new_by) - set(old_by), key=lambda k: int(ipaddress.IPv4Address(new_by[k]["ip"])))
        missing = sorted(set(old_by) - set(new_by), key=lambda k: int(ipaddress.IPv4Address(old_by[k]["ip"])))
        moved = [(k, old_by[k]["ip"], new_by[k]["ip"]) for k in set(old_by) & set(new_by)
                 if old_by[k]["ip"] != new_by[k]["ip"]]

        def line(sign, d):
            label = self.label_for(d)
            return (f"  {sign} {d['ip']:<15} {d.get('mac', ''):<18} {d.get('manufacturer', '')}"
                    + (f"  ({label})" if label else "") + "\n")

        out = [f"Older: {old['timestamp']}\nNewer: {new['timestamp']}\n\n"]
        out.append(f"NEW DEVICES ({len(added)}):\n" if added else "No new devices.\n")
        out += [line("+", new_by[k]) for k in added]
        out.append(f"\nMISSING DEVICES ({len(missing)}):\n" if missing else "\nNo missing devices.\n")
        out += [line("-", old_by[k]) for k in missing]
        if moved:
            out.append(f"\nIP CHANGES ({len(moved)}):\n")
            out += [f"  ~ {a:<15} → {b:<15} {k}\n" for k, a, b in moved]
        out.append(f"\nUNCHANGED: {len(set(old_by) & set(new_by)) - len(moved)} device(s)\n")
        return "".join(out)

    def export_csv(self):
        if not self.devices:
            messagebox.showwarning("No Data", "No scan results to export.")
            return
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Export Scan Results", defaultextension=".csv",
            initialfile=f"lantern_scan_{datetime.now():%Y%m%d_%H%M%S}.csv",
            initialdir=str(Path.home()), filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Label", "IP", "Hostname", "MAC", "Manufacturer", "Type",
                                 "Ports", "Last Seen", "Online", "Watched", "Notes"])
                for key, dev in sorted(self.devices.items(), key=lambda kd: int(ipaddress.IPv4Address(kd[1]["ip"]))):
                    writer.writerow([self.label_for(dev), dev["ip"], dev.get("hostname"), dev.get("mac"),
                                     dev.get("manufacturer"), self.type_for(dev), dev.get("ports"),
                                     dev.get("last_seen"), "No" if dev.get("online") is False else "Yes",
                                     "Yes" if key in self.watch_list else "No", self._lookup(self.device_notes, dev)])
            self.log_message(f"Exported {len(self.devices)} device(s) to {path}")
        except OSError as e:
            messagebox.showerror("Export Failed", f"Could not write {path}:\n{e}")


def main():
    root = tk.Tk()
    LanternApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
