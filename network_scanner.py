#!/usr/bin/env python3
"""
LEVIWIFITE - Module de Scan Réseau Avancé
Scan ultra-rapide et précis des réseaux WiFi
"""

import os
import sys
import subprocess
import json
import time
import threading
from datetime import datetime
import argparse
import re

class NetworkScanner:
    def __init__(self, interface, output_dir):
        self.interface = interface
        self.output_dir = output_dir
        self.networks = []
        self.clients = []
        
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{level}] {message}")
    
    def start_monitor_mode(self):
        self.log("Activation du mode monitor")
        result = subprocess.run(f"airmon-ng start {self.interface}", shell=True, capture_output=True)
        return result.returncode == 0
    
    def scan_networks_fast(self, duration=30):
        self.log(f"Scan rapide des réseaux (durée: {duration}s)")
        
        scan_file = os.path.join(self.output_dir, "network_scan")
        command = f"airodump-ng {self.interface} --output-format csv --write {scan_file}"
        
        process = subprocess.Popen(command, shell=True)
        time.sleep(duration)
        process.terminate()
        
        # Parser les résultats
        csv_file = f"{scan_file}-01.csv"
        if os.path.exists(csv_file):
            self.parse_network_csv(csv_file)
        
        return self.networks
    
    def parse_network_csv(self, csv_file):
        with open(csv_file, 'r') as f:
            content = f.read()
        
        lines = content.split('\n')
        for line in lines:
            if line.strip() and ',' in line:
                parts = line.split(',')
                if len(parts) >= 14 and parts[0].strip():
                    try:
                        bssid = parts[0].strip()
                        essid = parts[13].strip()
                        channel = parts[3].strip()
                        power = parts[8].strip()
                        encryption = parts[6].strip()
                        
                        if bssid and bssid != 'BSSID' and bssid != 'Station MAC':
                            if len(bssid) == 17:  # Format MAC valide
                                self.networks.append({
                                    'bssid': bssid,
                                    'essid': essid,
                                    'channel': channel,
                                    'power': power,
                                    'encryption': encryption,
                                    'timestamp': datetime.now().isoformat()
                                })
                    except IndexError:
                        continue
    
    def scan_clients(self, target_bssid, channel):
        self.log(f"Scan des clients connectés à {target_bssid}")
        
        client_file = os.path.join(self.output_dir, "client_scan")
        command = f"airodump-ng -c {channel} --bssid {target_bssid} --output-format csv --write {client_file} {self.interface}"
        
        process = subprocess.Popen(command, shell=True)
        time.sleep(15)
        process.terminate()
        
        # Parser les clients
        csv_file = f"{client_file}-01.csv"
        if os.path.exists(csv_file):
            self.parse_client_csv(csv_file)
        
        return self.clients
    
    def parse_client_csv(self, csv_file):
        with open(csv_file, 'r') as f:
            content = f.read()
        
        lines = content.split('\n')
        for line in lines:
            if line.strip() and ',' in line:
                parts = line.split(',')
                if len(parts) >= 6 and parts[0].strip():
                    try:
                        mac = parts[0].strip()
                        power = parts[2].strip()
                        packets = parts[3].strip()
                        
                        if mac and mac != 'Station MAC' and len(mac) == 17:
                            self.clients.append({
                                'mac': mac,
                                'power': power,
                                'packets': packets,
                                'timestamp': datetime.now().isoformat()
                            })
                    except IndexError:
                        continue
    
    def generate_scan_report(self):
        self.log("Génération du rapport de scan")
        
        report = {
            'scan_time': datetime.now().isoformat(),
            'interface': self.interface,
            'networks_found': len(self.networks),
            'clients_found': len(self.clients),
            'networks': self.networks,
            'clients': self.clients
        }
        
        report_file = os.path.join(self.output_dir, "network_scan_report.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report_file

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='LEVIWIFITE - Scanner Réseau')
    parser.add_argument('--interface', required=True, help='Interface WiFi')
    parser.add_argument('--output', required=True, help='Répertoire de sortie')
    parser.add_argument('--duration', type=int, default=30, help='Durée du scan')
    
    args = parser.parse_args()
    
    scanner = NetworkScanner(args.interface, args.output)
    scanner.start_monitor_mode()
    networks = scanner.scan_networks_fast(args.duration)
    
    print(f"Scan terminé: {len(networks)} réseaux trouvés")
    for network in networks:
        print(f"  {network['essid']} - {network['bssid']} (Canal {network['channel']})")
