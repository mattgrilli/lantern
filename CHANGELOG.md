# Changelog

## [2.0.0] - 2026-10-19

One app for every platform: the separate macOS, Windows and cross-platform scripts are merged into `lantern.py`.

### Added
- Windows and Linux support alongside macOS, from a single codebase
- Scan targets can be IP ranges (`10.0.0.1-50`) and comma-separated lists, not just CIDRs
- Device notes and manual type override (right-click a device)
- Optional `zeroconf` support for mDNS printer discovery on all platforms
- Larger manufacturer table (585 prefixes) and detection of private/randomized MACs
- More device types: NAS, Mobile, Smart Device, IoT, Virtual Machine
- Devices that stop answering are marked offline; new "Offline" filter
- Monitoring logs when a device comes back online, and only alerts on changes
- Compare any two saved scans, not just the last two
- Sortable columns, device counts, profile deletion, keyboard shortcuts
- CSV export asks where to save and handles commas and quotes properly
- Unit tests for the network parsing and classification code

### Fixed
- Hosts that replied "unreachable" were counted as online on macOS
- Windows treated "Destination host unreachable" replies as online
- Stopping a scan now stops right away instead of waiting for every queued ping
- Rescanning no longer duplicates rows in the table
- Scan history only records devices seen in that scan, so "missing devices" in Compare works
- Single-digit macOS MAC octets (e.g. `3c:7:54:…`) are normalized so manufacturer lookup works
- Linux ping used `-t` (TTL) where a timeout was intended
- New-device highlighting compares against the last saved scan, so the first scan of a session isn't all blue
- Pinging a device no longer freezes the window
- All Tk updates now happen on the main thread
- State is saved atomically

### Changed
- Requires Python 3.9+
- Run with `python3 lantern.py`

## [1.1.0] - 2025-10-14

### Added
- Bonjour/mDNS printer pre-discovery for instant printer detection
- IP change detection in scan comparison
- Thread-safe UI updates for stability

### Fixed
- Stable device tracking with MAC/IP fallback keys
- Better macOS compatibility (ping timeout, right-click binding)
- Improved state persistence to ~/Library/Application Support

### Changed
- One-time Treeview tag configuration for better performance

## [1.0.0] - 2025-10-14
- Initial release