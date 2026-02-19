#!/usr/bin/env python3
"""
Palo Alto Networks Firewall DDNS Refresh Script
Forces a DDNS refresh for a specified Layer 3 interface
"""

import requests
import urllib3
import xml.etree.ElementTree as ET
import sys
import argparse
from datetime import datetime
import os

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PaloAltoDDNS:
    def __init__(self, hostname, api_key, verify_ssl=False):
        self.hostname = hostname
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{hostname}/api/"
        
    def get_interfaces(self):
        """Get list of Layer 3 interfaces with DDNS enabled"""
        params = {
            'type': 'config',
            'action': 'get',
            'xpath': '/config/devices/entry[@name="localhost.localdomain"]/network/interface/ethernet',
            'key': self.api_key
        }
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()
            
            root = ET.fromstring(response.content)
            if root.attrib.get('status') == 'success':
                interfaces = []
                for entry in root.findall('.//entry'):
                    if_name = entry.get('name')
                    # Check if it's a Layer 3 interface with DDNS enabled
                    layer3 = entry.find('.//layer3')
                    if layer3 is not None:
                        ddns_config = layer3.find('.//ddns-config')
                        if ddns_config is not None:
                            ddns_enabled = ddns_config.find('.//ddns-enabled')
                            if ddns_enabled is not None and ddns_enabled.text == 'yes':
                                interfaces.append(if_name)
                return interfaces
            else:
                print("✗ Failed to retrieve interface information")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"✗ Connection error: {e}")
            return None
        except ET.ParseError as e:
            print(f"✗ XML parsing error: {e}")
            return None
    
    def refresh_ddns(self, interface_name):
        """Force DDNS refresh for specified interface"""
        # Operational command to refresh DDNS using the correct XML structure
        cmd = f'<test><dns-proxy><ddns><update><interface><name>{interface_name}</name></interface></update></ddns></dns-proxy></test>'
        
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': self.api_key
        }
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()
            
            root = ET.fromstring(response.content)
            
            if root.attrib.get('status') == 'success':
                result = root.find('.//result/msg')
                if result is not None and result.text:
                    print(f"✓ {result.text}")
                else:
                    print(f"✓ DDNS refresh initiated for interface {interface_name}")
                    
                return True
            else:
                error_msg = root.find('.//msg')
                if error_msg is not None:
                    print(f"✗ DDNS refresh failed: {error_msg.text}")
                else:
                    print("✗ DDNS refresh failed: Unknown error")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"✗ Connection error: {e}")
            return False
        except ET.ParseError as e:
            print(f"✗ XML parsing error: {e}")
            return False
    
    def get_ddns_status(self, interface_name):
        """Get DDNS status for specified interface"""
        cmd = f'<show><ddns><interface>{interface_name}</interface></ddns></show>'
        
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': self.api_key
        }
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()
            
            root = ET.fromstring(response.content)
            
            if root.attrib.get('status') == 'success':
                print(f"DDNS Status for interface {interface_name}:")
                result = root.find('.//result')
                if result is not None:
                    print(result.text if result.text else "No status information available")
                return True
            else:
                print(f"✗ Failed to get DDNS status for {interface_name}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"✗ Connection error: {e}")
            return False
        except ET.ParseError as e:
            print(f"✗ XML parsing error: {e}")
            return False

def log_output(firewall_ip, message, log_filename=None):
    """Log output to a file with timestamp"""
    if log_filename is None:
        # Create logs directory if it doesn't exist
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Create filename with firewall IP and current date (YYYYMMDD)
        current_date = datetime.now().strftime("%Y%m%d")
        # Replace dots in IP with underscores for filename compatibility
        safe_ip = firewall_ip.replace(".", "_")
        log_filename = os.path.join(log_dir, f"{safe_ip}_{current_date}.log")
    
    # Write to log file (append mode)
    with open(log_filename, 'a') as log_file:
        log_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"[{log_timestamp}] {message}\n")
    
    return log_filename

def main():
    # Configuration - Update these values
    # List of firewalls to process - each entry contains IP and API key
    firewalls = [
        {"ip": "192.168.1.1", "api_key": "YOUR_API_KEY_HERE"},
        {"ip": "192.168.1.2", "api_key": "YOUR_API_KEY_HERE"},
        # Add more firewalls as needed
    ]
    
    parser = argparse.ArgumentParser(description='Force DDNS refresh on Palo Alto firewall(s)')
    parser.add_argument('--interface', help='Interface name (e.g., ethernet1/2) - will auto-detect if not specified')
    parser.add_argument('--list-interfaces', action='store_true', 
                       help='List all Layer 3 interfaces with DDNS enabled')
    parser.add_argument('--status', action='store_true', 
                       help='Show DDNS status for the interface')
    parser.add_argument('--verify-ssl', action='store_true', 
                       help='Verify SSL certificates (default: False)')
    parser.add_argument('--firewall', help='Process only a specific firewall IP (default: all firewalls)')
    
    args = parser.parse_args()
    
    # Filter firewalls if specific one requested
    if args.firewall:
        firewalls = [fw for fw in firewalls if fw["ip"] == args.firewall]
        if not firewalls:
            print(f"✗ Firewall {args.firewall} not found in configuration")
            sys.exit(1)
    
    # Process each firewall
    for idx, firewall in enumerate(firewalls):
        firewall_ip = firewall["ip"]
        api_key = firewall["api_key"]
        
        if len(firewalls) > 1:
            print(f"\n{'='*60}")
            print(f"Processing Firewall {idx + 1}/{len(firewalls)}: {firewall_ip}")
            print(f"{'='*60}")
        
        # Initialize log file - create once at the start
        log_file = log_output(firewall_ip, f"{'='*60}", None)
        log_output(firewall_ip, "Script execution started", log_file)
        
        try:
            # Create PaloAltoDDNS instance with API key
            pa = PaloAltoDDNS(firewall_ip, api_key, args.verify_ssl)
            
            print(f"Connected to {firewall_ip}")
            log_output(firewall_ip, f"Connected to {firewall_ip}", log_file)
            
            # List interfaces if requested
            if args.list_interfaces:
                print("\nLayer 3 interfaces with DDNS enabled:")
                log_output(firewall_ip, "Listing DDNS-enabled interfaces", log_file)
                interfaces = pa.get_interfaces()
                if interfaces:
                    for interface in interfaces:
                        print(f"  - {interface}")
                        log_output(firewall_ip, f"Found interface: {interface}", log_file)
                else:
                    print("  No Layer 3 interfaces with DDNS found")
                    log_output(firewall_ip, "No DDNS-enabled interfaces found", log_file)
                
                if log_file:
                    print(f"\nLog saved to: {log_file}")
                continue
            
            # Determine which interface to use
            if args.interface:
                target_interface = args.interface
                log_output(firewall_ip, f"Using manually specified interface: {target_interface}", log_file)
            else:
                # Auto-detect interface with DDNS enabled
                print("Auto-detecting interface with DDNS enabled...")
                log_output(firewall_ip, "Auto-detecting DDNS-enabled interface", log_file)
                interfaces = pa.get_interfaces()
                if interfaces and len(interfaces) > 0:
                    target_interface = interfaces[0]
                    print(f"Found DDNS-enabled interface: {target_interface}")
                    log_output(firewall_ip, f"Auto-detected interface: {target_interface}", log_file)
                    if len(interfaces) > 1:
                        print(f"Note: Multiple DDNS interfaces found ({', '.join(interfaces)}), using {target_interface}")
                        log_output(firewall_ip, f"Multiple interfaces found: {', '.join(interfaces)}, using {target_interface}", log_file)
                else:
                    print("✗ No interfaces with DDNS enabled found")
                    log_output(firewall_ip, "ERROR: No DDNS-enabled interfaces found", log_file)
                    print("Use --list-interfaces to check configuration")
                    if log_file:
                        print(f"\nLog saved to: {log_file}")
                    continue
            
            # Show status if requested
            if args.status:
                log_output(firewall_ip, f"Checking DDNS status for interface: {target_interface}", log_file)
                pa.get_ddns_status(target_interface)
                if log_file:
                    print(f"\nLog saved to: {log_file}")
                continue
            
            # Force DDNS refresh
            print(f"\nInitiating DDNS refresh for interface {target_interface}...")
            log_output(firewall_ip, f"Initiating DDNS refresh for interface: {target_interface}", log_file)
            
            if pa.refresh_ddns(target_interface):
                print("✓ DDNS refresh command completed successfully")
                log_output(firewall_ip, f"SUCCESS: DDNS refresh completed for {target_interface}", log_file)
            else:
                print("✗ DDNS refresh failed")
                log_output(firewall_ip, f"ERROR: DDNS refresh failed for {target_interface}", log_file)
            
            if log_file:
                print(f"\nLog saved to: {log_file}")
                
        except Exception as e:
            print(f"✗ Error processing firewall {firewall_ip}: {e}")
            log_output(firewall_ip, f"ERROR: Exception occurred - {e}", log_file)
            if log_file:
                print(f"\nLog saved to: {log_file}")
            continue

if __name__ == "__main__":
    main()
