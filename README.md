# 🏮 Lantern

**A powerful network scanner for macOS with device monitoring and management**

Lantern illuminates your network - discover devices, identify manufacturers, monitor uptime, and manage your network infrastructure with an intuitive GUI.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS-lightgrey.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

## ✨ Features

### Core Scanning
- 🔍 **Fast Network Scanning** - Multi-threaded scanning with configurable speed
- 🏷️ **Device Identification** - Automatic manufacturer detection via MAC address
- 🔬 **Deep Scanning** - Port scanning, hostname resolution, service detection
- 🎯 **Smart Device Types** - Automatically identifies Printers, Computers, Servers, IoT devices, and more

### Device Management
- 📝 **Custom Labels** - Name your devices (e.g., "Office Xerox", "Living Room TV")
- ⭐ **Watch List** - Mark important devices for monitoring
- 📋 **Device Notes** - Add documentation for each device
- 🏷️ **Type Override** - Manually set device types when auto-detection isn't perfect

### Monitoring & History
- 👁️ **Live Monitoring** - Continuous monitoring of watched devices with offline alerts
- 📊 **Scan Comparison** - Compare scans to see what's new or missing
- 📈 **Scan History** - Automatically saves last 50 scans
- ⏰ **Last Seen** - Track when devices were last active

### Profiles & Export
- 💾 **Network Profiles** - Save and switch between different network configurations
- 📄 **CSV Export** - Export all results with labels, notes, and metadata
- 📋 **Quick Actions** - One-click copy IP/MAC, open web interfaces, ping devices

### Advanced Filtering
- 🔍 **Text Search** - Search by IP, MAC, hostname, manufacturer, label, or notes
- 🖨️ **Type Filters** - Show only Printers, Computers, Watched devices, or New devices
- 🎨 **Visual Indicators** - Color-coded new devices, starred watched devices

## 🚀 Quick Start

### Option 1: Run Directly (Requires Python 3)

```bash
# Clone the repository
git clone https://github.com/yourusername/lantern.git
cd lantern

# Run Lantern
python3 lantern.py
```

That's it! No dependencies needed - uses only Python standard library.

### Option 2: Standalone App (No Python Required)

Download the latest `.app` bundle from [Releases](https://github.com/yourusername/lantern/releases) and drag to Applications.

> **Note for macOS Gatekeeper:** First time opening, right-click the app and select "Open" to bypass Gatekeeper warnings.

## 📖 Usage Guide

### First Scan
1. **Launch Lantern** - It auto-detects your network range
2. **Click "▶️ Start Scan"** - Scanning begins immediately
3. **Review Results** - Devices appear in real-time as they're found

### Label Your Devices
- **Right-click any device** → "Set Label/Nickname"
- Give it a friendly name like "Office Printer" or "Bob's Laptop"
- Labels are saved and persist across scans

### Monitor Important Devices
1. **Right-click a device** → "Add to Watch List"
2. **Click "👁️ Start Monitoring"** to begin continuous monitoring
3. Get alerts in the log if watched devices go offline

### Compare Scans
- Run multiple scans throughout the day
- Click **"📊 Compare"** to see:
  - 🆕 New devices that appeared
  - 📴 Devices that went offline
  - Summary statistics

### Save Network Profiles
- Set up your network range and threads
- Click **"💾 Save Profile"**
- Quickly switch between Home, Office, Guest networks

### Export Results
- Click **"📄 Export CSV"** to save all results
- Includes labels, notes, watch status, and full device info
- Import into Excel, Numbers, or database tools

## 🎯 Use Cases

### Home Users
- Find that printer you can't remember the IP for
- Identify unknown devices on your WiFi
- Monitor when kids' devices come online
- Track smart home device uptime

### IT Professionals
- Quick network audits
- Device inventory management
- Troubleshoot network issues
- Monitor critical infrastructure
- Compare network states before/after changes

### Small Business
- Track office equipment
- Monitor printer availability
- Document network infrastructure
- Identify unauthorized devices

## 🔧 Advanced Features

### Deep Scan Mode
Enable "🔬 Deep Scan" to detect:
- Open ports and services
- MAC addresses
- Device manufacturers
- Device type classification

**Scanned Ports:**
- 21 (FTP), 22 (SSH), 23 (Telnet)
- 80 (HTTP), 443 (HTTPS), 8080 (HTTP-Alt)
- 445 (SMB), 139 (NetBIOS)
- 515 (LPR), 631 (IPP), 9100 (Printer)
- 3389 (RDP), 161 (SNMP), 5000 (UPnP)

### Thread Control
- **10 threads** = Slow but thorough (stealth mode)
- **50 threads** = Balanced (default)
- **100+ threads** = Fast scans for large networks



## 📊 Supported Devices

Lantern can identify devices from 60+ manufacturers including:

**Printers:** Xerox, HP, Brother, Canon, Epson, Kyocera, Lexmark  
**Computers:** Apple, Dell, HP, Lenovo, Microsoft  
**Network:** Cisco, Ubiquiti, Netgear, D-Link, Fortinet  
**IoT/Other:** Samsung, Polycom, VMware, and more

Don't see your device manufacturer? It will still be detected - just shown as "Unknown" manufacturer. You can manually set labels and types!

## 🐛 Troubleshooting

### "No devices found"
- Check that you're on the correct network
- Verify network range (e.g., `192.168.1.0/24`)
- Try increasing thread count
- Some devices block ICMP ping - they won't be detected

### "Unknown manufacturer"
- MAC address OUI not in our database
- Still functional - use custom labels!
- Feel free to submit OUI additions via PR

### Slow scanning
- Reduce thread count if network is unstable
- Large networks (/16) take longer - consider scanning /24 subnets
- Deep scan adds ~0.5s per device

### Monitoring not alerting
- Ensure devices are in Watch List (⭐ icon)
- Check that device IPs haven't changed (DHCP)
- Monitoring checks every 60 seconds

## 💾 Data Storage

Lantern saves your data locally in `scanner_data.json`:
- Device labels and nicknames
- Custom device types
- Device notes
- Watch list
- Saved profiles
- Last 50 scan history

**Location:** Same directory as `lantern.py`  
**Format:** Human-readable JSON

## 🤝 Contributing

Contributions are welcome! Areas we'd love help with:

- [ ] Additional manufacturer OUI database entries
- [ ] Device type detection improvements  
- [ ] Keyboard shortcut implementation
- [ ] Dark mode theme optimization
- [ ] Additional export formats (JSON, XML)
- [ ] SNMP device querying
- [ ] Network topology visualization

## 📜 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

Built with Python's tkinter and standard library - no external dependencies!

Inspired by the lack of good, free network scanners for macOS.

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/mattgrilli/lantern/issues)
- **Discussions:** [GitHub Discussions](https://github.com/mattgrilli/lantern/discussions)

---

**Made with ☕ for macOS network admins and power users**
