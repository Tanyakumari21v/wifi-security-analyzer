#!/usr/bin/env python3
"""
Wi-Fi Security Analyzer
A tool to scan Wi-Fi networks for vulnerabilities, weak encryption, and unauthorized devices.
"""

import subprocess
import re
import time
import sys
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import *
except ImportError:
    print("Please install scapy: pip install scapy")
    sys.exit(1)

class WiFiSecurityAnalyzer:
    def __init__(self, interface="wlan0"):
        self.interface = interface
        self.networks = {}
        self.clients = defaultdict(list)
        self.vulnerable_networks = []
        
    def check_monitor_mode(self):
        """Check if interface is in monitor mode"""
        try:
            result = subprocess.run(['iwconfig', self.interface], 
                                  capture_output=True, text=True)
            return 'Mode:Monitor' in result.stdout
        except:
            return False
    
    def enable_monitor_mode(self):
        """Enable monitor mode on the interface"""
        print(f"[*] Enabling monitor mode on {self.interface}...")
        try:
            subprocess.run(['sudo', 'ifconfig', self.interface, 'down'], check=True)
            subprocess.run(['sudo', 'iwconfig', self.interface, 'mode', 'monitor'], check=True)
            subprocess.run(['sudo', 'ifconfig', self.interface, 'up'], check=True)
            print(f"[+] Monitor mode enabled on {self.interface}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[-] Failed to enable monitor mode: {e}")
            return False
    
    def packet_handler(self, pkt):
        """Handle captured packets"""
        if pkt.haslayer(Dot11Beacon):
            self.process_beacon(pkt)
        elif pkt.haslayer(Dot11ProbeReq):
            self.process_probe_request(pkt)
        elif pkt.haslayer(Dot11):
            self.process_data_packet(pkt)
    
    def process_beacon(self, pkt):
        """Process beacon frames to discover networks"""
        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
        
        if not ssid or bssid in self.networks:
            return
        
        # Extract network information
        channel = int(ord(pkt[Dot11Elt:3].info))
        stats = pkt[Dot11Beacon].network_stats()
        
        # Determine encryption type
        encryption = self.get_encryption_type(pkt)
        
        network_info = {
            'ssid': ssid,
            'bssid': bssid,
            'channel': channel,
            'encryption': encryption,
            'signal_strength': pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 'N/A',
            'discovered_at': datetime.now().strftime('%H:%M:%S')
        }
        
        self.networks[bssid] = network_info
        self.analyze_security(network_info)
        
    def get_encryption_type(self, pkt):
        """Determine the encryption type of the network"""
        try:
            crypto = set()
            p = pkt[Dot11Elt]
            
            while isinstance(p, Dot11Elt):
                if p.ID == 48:  # RSN (WPA2)
                    crypto.add("WPA2")
                elif p.ID == 221 and p.info.startswith(b'\x00\x50\xf2\x01\x01\x00'):
                    crypto.add("WPA")
                p = p.payload
            
            cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
            if 'privacy' in cap.lower() and not crypto:
                crypto.add("WEP")
            elif not crypto:
                return "Open"
            
            return "/".join(crypto) if crypto else "Unknown"
        except:
            return "Unknown"
    
    def process_probe_request(self, pkt):
        """Process probe requests to detect clients"""
        if pkt.haslayer(Dot11ProbeReq):
            client_mac = pkt[Dot11].addr2
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore') if pkt[Dot11Elt].info else "<Hidden>"
            
            if client_mac not in self.clients:
                self.clients[client_mac].append({
                    'probing_for': ssid,
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                })
    
    def process_data_packet(self, pkt):
        """Process data packets to detect connected clients"""
        if pkt.haslayer(Dot11) and pkt.type == 2:  # Data frame
            bssid = pkt.addr1 if pkt.FCfield & 0x1 else pkt.addr2
            client_mac = pkt.addr2 if pkt.FCfield & 0x1 else pkt.addr1
            
            if bssid in self.networks and client_mac != bssid:
                if 'connected_clients' not in self.networks[bssid]:
                    self.networks[bssid]['connected_clients'] = set()
                self.networks[bssid]['connected_clients'].add(client_mac)
    
    def analyze_security(self, network_info):
        """Analyze network security and identify vulnerabilities"""
        vulnerabilities = []
        
        # Check for weak/no encryption
        if network_info['encryption'] == "Open":
            vulnerabilities.append("No encryption - network is completely open")
        elif "WEP" in network_info['encryption']:
            vulnerabilities.append("WEP encryption is deprecated and easily crackable")
        elif "WPA" in network_info['encryption'] and "WPA2" not in network_info['encryption']:
            vulnerabilities.append("WPA (without WPA2) has known vulnerabilities")
        
        # Check if WPA3 is not being used
        if "WPA3" not in network_info['encryption'] and network_info['encryption'] != "Open":
            vulnerabilities.append("Not using WPA3 - consider upgrading for better security")
        
        if vulnerabilities:
            self.vulnerable_networks.append({
                'network': network_info,
                'vulnerabilities': vulnerabilities
            })
    
    def scan_networks(self, duration=60):
        """Scan for Wi-Fi networks"""
        print(f"\n[*] Starting Wi-Fi security scan on {self.interface}")
        print(f"[*] Scanning for {duration} seconds...\n")
        
        try:
            sniff(iface=self.interface, prn=self.packet_handler, 
                  timeout=duration, store=False)
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        except Exception as e:
            print(f"[-] Error during scan: {e}")
    
    def generate_report(self):
        """Generate comprehensive security report"""
        print("\n" + "="*80)
        print(" "*20 + "Wi-Fi SECURITY ANALYSIS REPORT")
        print("="*80)
        
        print(f"\n[+] Discovered Networks: {len(self.networks)}")
        print("-"*80)
        
        for bssid, info in self.networks.items():
            print(f"\nSSID: {info['ssid']}")
            print(f"BSSID: {info['bssid']}")
            print(f"Channel: {info['channel']}")
            print(f"Encryption: {info['encryption']}")
            print(f"Signal Strength: {info['signal_strength']} dBm")
            print(f"Discovered at: {info['discovered_at']}")
            
            if 'connected_clients' in info:
                print(f"Connected Clients: {len(info['connected_clients'])}")
                for client in list(info['connected_clients'])[:5]:
                    print(f"  - {client}")
            print("-"*80)
        
        print(f"\n[!] SECURITY VULNERABILITIES FOUND: {len(self.vulnerable_networks)}")
        print("="*80)
        
        if self.vulnerable_networks:
            for vuln in self.vulnerable_networks:
                net = vuln['network']
                print(f"\n⚠️  Network: {net['ssid']} ({net['bssid']})")
                print(f"   Encryption: {net['encryption']}")
                print("   Vulnerabilities:")
                for v in vuln['vulnerabilities']:
                    print(f"   - {v}")
                print("-"*80)
        else:
            print("\n✓ No critical vulnerabilities detected!")
        
        print(f"\n[+] Active Clients Detected: {len(self.clients)}")
        if self.clients:
            print("-"*80)
            for client, probes in list(self.clients.items())[:10]:
                print(f"Client: {client}")
                for probe in probes[:3]:
                    print(f"  - Probing for: {probe['probing_for']} at {probe['timestamp']}")
        
        print("\n" + "="*80)
        print("RECOMMENDATIONS:")
        print("="*80)
        print("1. Use WPA3 encryption if supported by your router")
        print("2. Disable WPS (Wi-Fi Protected Setup)")
        print("3. Use strong, unique passwords (12+ characters)")
        print("4. Regularly update router firmware")
        print("5. Disable remote management features")
        print("6. Hide SSID if necessary for added obscurity")
        print("7. Enable MAC address filtering")
        print("8. Monitor for unauthorized devices regularly")
        print("="*80 + "\n")

def main():
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║          Wi-Fi Security Analyzer v1.0                    ║
    ║  Scan networks for vulnerabilities and security issues   ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    if os.geteuid() != 0:
        print("[-] This script requires root privileges!")
        print("[-] Please run with: sudo python3 wifi_analyzer.py")
        sys.exit(1)
    
    # Get available interfaces
    print("[*] Available network interfaces:")
    interfaces = subprocess.run(['iwconfig'], capture_output=True, text=True)
    print(interfaces.stdout)
    
    interface = input("\n[?] Enter wireless interface name (e.g., wlan0): ").strip()
    duration = int(input("[?] Enter scan duration in seconds (default 60): ") or "60")
    
    analyzer = WiFiSecurityAnalyzer(interface)
    
    if not analyzer.check_monitor_mode():
        if not analyzer.enable_monitor_mode():
            print("[-] Failed to enable monitor mode. Exiting...")
            sys.exit(1)
    
    analyzer.scan_networks(duration)
    analyzer.generate_report()

if __name__ == "__main__":
    main()
