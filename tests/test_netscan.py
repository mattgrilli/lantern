import ipaddress
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import netscan
from oui import lookup_manufacturer


def ips(*addrs):
    return [ipaddress.IPv4Address(a) for a in addrs]


class ParseTargetsTest(unittest.TestCase):
    def test_cidr_excludes_network_and_broadcast(self):
        hosts = netscan.parse_targets("192.168.1.0/30")
        self.assertEqual(hosts, ips("192.168.1.1", "192.168.1.2"))

    def test_single_address(self):
        self.assertEqual(netscan.parse_targets("10.0.0.7"), ips("10.0.0.7"))

    def test_short_range(self):
        self.assertEqual(netscan.parse_targets("10.0.0.8-10"), ips("10.0.0.8", "10.0.0.9", "10.0.0.10"))

    def test_full_range_across_octets(self):
        hosts = netscan.parse_targets("10.0.0.254-10.0.1.1")
        self.assertEqual(hosts, ips("10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"))

    def test_list_is_deduplicated_and_sorted(self):
        hosts = netscan.parse_targets("10.0.0.5, 10.0.0.1-3, 10.0.0.2")
        self.assertEqual(hosts, ips("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.5"))

    def test_host_bits_in_cidr_are_ignored(self):
        self.assertEqual(len(netscan.parse_targets("192.168.1.77/24")), 254)

    def test_invalid(self):
        for bad in ("", "nonsense", "10.0.0.9-3", "300.1.1.1", "10.0.0.0/33"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                netscan.parse_targets(bad)


class PrefixDetectionTest(unittest.TestCase):
    def test_linux_ip_addr(self):
        out = ("1: lo    inet 127.0.0.1/8 scope host lo\n"
               "3: wlo1    inet 192.168.1.13/24 brd 192.168.1.255 scope global wlo1\n")
        self.assertEqual(netscan.parse_prefix_for_ip(out, "192.168.1.13"), 24)

    def test_macos_ifconfig_hex_netmask(self):
        out = ("en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500\n"
               "\tinet6 fe80::1c%en0 prefixlen 64 secured scopeid 0x6\n"
               "\tinet 10.20.30.40 netmask 0xfffff000 broadcast 10.20.31.255\n")
        self.assertEqual(netscan.parse_prefix_for_ip(out, "10.20.30.40"), 20)

    def test_linux_ifconfig_dotted_netmask(self):
        out = "eth0: flags=4163<UP>  mtu 1500\n        inet 172.16.5.9  netmask 255.255.0.0  broadcast 172.16.255.255\n"
        self.assertEqual(netscan.parse_prefix_for_ip(out, "172.16.5.9"), 16)

    def test_windows_ipconfig(self):
        out = ("Ethernet adapter Ethernet 2:\r\n\r\n   Media State . . . . . . . . . . . : Media disconnected\r\n\r\n"
               "Wireless LAN adapter Wi-Fi:\r\n\r\n"
               "   Connection-specific DNS Suffix  . : lan\r\n"
               "   IPv4 Address. . . . . . . . . . . : 192.168.0.23(Preferred)\r\n"
               "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n"
               "   Default Gateway . . . . . . . . . : 192.168.0.1\r\n")
        self.assertEqual(netscan.parse_prefix_for_ip(out, "192.168.0.23"), 24)

    def test_windows_ipconfig_localized(self):
        out = ("   IPv4-Adresse  . . . . . . . . . . : 192.168.178.20\r\n"
               "   Subnetzmaske  . . . . . . . . . . : 255.255.255.0\r\n")
        self.assertEqual(netscan.parse_prefix_for_ip(out, "192.168.178.20"), 24)

    def test_does_not_match_longer_address(self):
        out = "inet 192.168.1.130/25 brd 192.168.1.255\n"
        self.assertIsNone(netscan.parse_prefix_for_ip(out, "192.168.1.13"))


class ArpParsingTest(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(netscan.normalize_mac("a4:2b:b0:1:2:3"), "A4:2B:B0:01:02:03")
        self.assertEqual(netscan.normalize_mac("00-1A-2b-3C-4d-5E"), "00:1A:2B:3C:4D:5E")
        self.assertEqual(netscan.normalize_mac("garbage"), netscan.UNKNOWN)

    def test_macos_arp(self):
        out = "? (192.168.1.20) at 3c:7:54:a:b:c on en0 ifscope [ethernet]\n"
        self.assertEqual(netscan.parse_arp_output(out, "192.168.1.20"), "3C:07:54:0A:0B:0C")

    def test_macos_incomplete(self):
        out = "? (192.168.1.21) at (incomplete) on en0 ifscope [ethernet]\n"
        self.assertEqual(netscan.parse_arp_output(out, "192.168.1.21"), netscan.UNKNOWN)

    def test_windows_arp(self):
        out = ("\r\nInterface: 192.168.0.23 --- 0x7\r\n"
               "  Internet Address      Physical Address      Type\r\n"
               "  192.168.0.1           f4-ec-38-11-22-33     dynamic\r\n")
        self.assertEqual(netscan.parse_arp_output(out, "192.168.0.1"), "F4:EC:38:11:22:33")

    def test_interface_line_is_not_a_match(self):
        out = "Interface: 192.168.0.1 --- 0x7\r\n  192.168.0.10   aa-bb-cc-dd-ee-ff   dynamic\r\n"
        self.assertEqual(netscan.parse_arp_output(out, "192.168.0.1"), netscan.UNKNOWN)

    def test_proc_net_arp(self):
        text = ("IP address       HW type     Flags       HW address            Mask     Device\n"
                "192.168.1.167    0x1         0x2         d8:bb:c1:8b:84:32     *        wlo1\n"
                "192.168.1.176    0x1         0x0         00:00:00:00:00:00     *        wlo1\n")
        self.assertEqual(netscan.parse_proc_net_arp(text, "192.168.1.167"), "D8:BB:C1:8B:84:32")
        self.assertEqual(netscan.parse_proc_net_arp(text, "192.168.1.176"), netscan.UNKNOWN)
        self.assertEqual(netscan.parse_proc_net_arp(text, "192.168.1.16"), netscan.UNKNOWN)


class ClassifyTest(unittest.TestCase):
    def test_printer_ports(self):
        self.assertEqual(netscan.classify_device("Unknown", "HP", [80, 9100]), "Printer")

    def test_hp_computer_is_not_a_printer(self):
        self.assertEqual(netscan.classify_device("Unknown", "HP", [139, 445]), "Computer")

    def test_vm(self):
        self.assertEqual(netscan.classify_device("Unknown", "VMware", [22]), "Virtual Machine")

    def test_router_by_vendor(self):
        self.assertEqual(netscan.classify_device("Unknown", "TP-Link", [80]), "Network")

    def test_phone_by_hostname(self):
        self.assertEqual(netscan.classify_device("Matts-iPhone.lan", "Unknown", []), "Mobile")

    def test_server(self):
        self.assertEqual(netscan.classify_device("Unknown", "Unknown", [22, 53]), "Server")

    def test_web_only(self):
        self.assertEqual(netscan.classify_device("Unknown", "Unknown", [443]), "Server/Web")

    def test_unknown_hostname_does_not_match_keywords(self):
        self.assertEqual(netscan.classify_device("Unknown", "Unknown", None), "Unknown")


class MiscTest(unittest.TestCase):
    def test_device_key(self):
        self.assertEqual(netscan.device_key("10.0.0.1", "AA:BB:CC:DD:EE:FF"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(netscan.device_key("10.0.0.1", netscan.UNKNOWN), "IP::10.0.0.1")

    def test_format_ports(self):
        self.assertEqual(netscan.format_ports(None), "Skipped")
        self.assertEqual(netscan.format_ports([]), "None")
        self.assertEqual(netscan.format_ports([22, 12345]), "22 (SSH), 12345")

    def test_oui_lookup(self):
        self.assertEqual(lookup_manufacturer("52:54:00:12:34:56"), "QEMU/KVM")
        self.assertEqual(lookup_manufacturer("b8:27:eb:00:00:01"), "Raspberry Pi")
        self.assertEqual(lookup_manufacturer("Unknown"), "Unknown")
        self.assertEqual(lookup_manufacturer("2A:80:26:F5:1C:6F"), "Private (randomized)")
        self.assertEqual(lookup_manufacturer("9C:B6:54:15:02:50"), "Unknown")

    def test_ping_command_has_target_last(self):
        cmd = netscan.ping_command("10.0.0.1", 1, 1.0)
        self.assertEqual(cmd[0], "ping")
        self.assertEqual(cmd[-1], "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
