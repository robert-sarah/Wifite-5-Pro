#!/usr/bin/env python3
"""
LEVIWIFITE - Module d'Analyse Réseau Avancé
Analyse approfondie des réseaux WiFi
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

class NetworkAnalyzer:
    def __init__(self, interface, output_dir):
        self.interface = interface
        self.output_dir = output_dir
        self.networks = []
        self.clients = []
        self.vulnerabilities = []
        
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{level}] {message}")
    
    def start_monitor_mode(self):
        self.log("Activation du mode monitor pour analyse")
        result = subprocess.run(f"airmon-ng start {self.interface}", shell=True, capture_output=True)
        return result.returncode == 0
    
    def analyze_network_security(self, network):
        self.log(f"Analyse de sécurité pour {network['essid']}")
        
        vulns = []
        
        # Vérifier le chiffrement
        encryption = network.get('encryption', '').lower()
        if 'wep' in encryption:
            vulns.append('WEP - Chiffrement faible et vulnérable')
        elif 'wpa' in encryption and 'wpa2' not in encryption:
            vulns.append('WPA1 - Chiffrement obsolète')
        elif 'open' in encryption:
            vulns.append('Réseau ouvert - Aucune sécurité')
        
        # Vérifier la puissance du signal
        try:
            power = int(network.get('power', '0'))
            if power > -30:
                vulns.append('Signal très fort - Facile à intercepter')
        except:
            pass
        
        # Vérifier le canal
        try:
            channel = int(network.get('channel', '0'))
            if channel in [1, 6, 11]:
                vulns.append('Canal standard - Plus de trafic')
        except:
            pass
        
        return vulns
    
    def scan_network_detailed(self, target_bssid, channel, duration=60):
        self.log(f"Scan détaillé du réseau {target_bssid}")
        
        scan_file = os.path.join(self.output_dir, f"detailed_scan_{target_bssid.replace(':', '')}")
        command = f"airodump-ng -c {channel} --bssid {target_bssid} --output-format csv --write {scan_file} {self.interface}"
        
        process = subprocess.Popen(command, shell=True)
        time.sleep(duration)
        process.terminate()
        
        # Analyser les résultats
        csv_file = f"{scan_file}-01.csv"
        if os.path.exists(csv_file):
            self.analyze_detailed_scan(csv_file, target_bssid)
        
        return self.clients
    
    def analyze_detailed_scan(self, csv_file, target_bssid):
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
                            # Analyser le client
                            client_vulns = self.analyze_client_security(mac, power, packets)
                            
                            self.clients.append({
                                'mac': mac,
                                'power': power,
                                'packets': packets,
                                'vulnerabilities': client_vulns,
                                'timestamp': datetime.now().isoformat(),
                                'target_network': target_bssid
                            })
                    except IndexError:
                        continue
    
    def analyze_client_security(self, mac, power, packets):
        vulns = []
        
        # Vérifier la puissance du signal
        try:
            power_val = int(power)
            if power_val > -40:
                vulns.append('Signal très fort - Facile à intercepter')
            elif power_val > -60:
                vulns.append('Signal fort - Interception possible')
        except:
            pass
        
        # Vérifier le nombre de paquets
        try:
            packet_count = int(packets)
            if packet_count > 1000:
                vulns.append('Trafic élevé - Plus de données à intercepter')
        except:
            pass
        
        # Vérifier l'adresse MAC
        if mac.lower() in ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00']:
            vulns.append('Adresse MAC suspecte')
        
        return vulns
    
    def generate_analysis_report(self):
        self.log("Génération du rapport d'analyse")
        
        report = {
            'analysis_time': datetime.now().isoformat(),
            'interface': self.interface,
            'networks_analyzed': len(self.networks),
            'clients_found': len(self.clients),
            'total_vulnerabilities': len(self.vulnerabilities),
            'networks': [],
            'clients': self.clients,
            'vulnerabilities': self.vulnerabilities
        }
        
        # Analyser chaque réseau
        for network in self.networks:
            network_vulns = self.analyze_network_security(network)
            network['vulnerabilities'] = network_vulns
            report['networks'].append(network)
            self.vulnerabilities.extend(network_vulns)
        
        report_file = os.path.join(self.output_dir, "network_analysis_report.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report_file
    
    def run_full_analysis(self, duration=60):
        self.log("🚀 Début de l'analyse réseau complète")
        
        try:
            if not self.start_monitor_mode():
                return False
            
            # Scan des réseaux
            scan_file = os.path.join(self.output_dir, "analysis_scan")
            command = f"airodump-ng {self.interface} --output-format csv --write {scan_file}"
            
            process = subprocess.Popen(command, shell=True)
            time.sleep(duration)
            process.terminate()
            
            # Parser les résultats
            csv_file = f"{scan_file}-01.csv"
            if os.path.exists(csv_file):
                self.parse_network_csv(csv_file)
            
            # Analyser chaque réseau en détail
            for network in self.networks:
                try:
                    channel = int(network.get('channel', '1'))
                    self.scan_network_detailed(network['bssid'], channel, 30)
                except:
                    continue
            
            # Générer le rapport
            self.generate_analysis_report()
            
            self.log("✅ Analyse réseau complète terminée")
            return True
            
        except Exception as e:
            self.log(f"Erreur lors de l'analyse: {e}", "ERROR")
            return False
    
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
                        
                        if bssid and bssid != 'BSSID' and len(bssid) == 17:
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='LEVIWIFITE - Analyseur Réseau')
    parser.add_argument('--interface', required=True, help='Interface WiFi')
    parser.add_argument('--output', required=True, help='Répertoire de sortie')
    parser.add_argument('--duration', type=int, default=60, help='Durée de l\'analyse')
    
    args = parser.parse_args()
    
    analyzer = NetworkAnalyzer(args.interface, args.output)
    success = analyzer.run_full_analysis(args.duration)
    
    if success:
        print(f"Analyse terminée: {len(analyzer.networks)} réseaux, {len(analyzer.clients)} clients analysés")
        print(f"Rapport généré: {args.output}/network_analysis_report.json")
    else:
        print("Analyse échouée")
        sys.exit(1)
