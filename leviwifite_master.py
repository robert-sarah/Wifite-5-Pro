#!/usr/bin/env python3
"""
LEVIWIFITE MASTER - Fichier Principal Ultra-Avancé
Coordination de tous les composants Python, Ruby et Bash
"""

import os
import sys
import json
import time
import subprocess
import argparse
import signal
import threading
from datetime import datetime

# Import des modules locaux
from network_scanner import NetworkScanner
from advanced_attacks import AdvancedAttacks
from report_generator import ReportGenerator

class LeviWifiteMaster:
    def __init__(self):
        self.config = self.load_config()
        self.scanner = None
        self.attacker = None
        self.report_generator = None
        self.results = []
        self.attack_processes = []
        
    def load_config(self):
        try:
            with open('config.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                "interface": "wlan0",
                "monitor_mode": True,
                "attack_timeout": 300,
                "wordlist_path": "/usr/share/wordlists/rockyou.txt",
                "output_dir": "results",
                "log_level": "INFO"
            }
    
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{level}] {message}")
    
    def check_prerequisites(self):
        self.log("Vérification des prérequis...")
        
        tools = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "python3", "ruby"]
        missing = []
        
        for tool in tools:
            if not self.check_tool(tool):
                missing.append(tool)
        
        if missing:
            self.log(f"Outils manquants: {missing}", "ERROR")
            return False
        
        self.log("Tous les prérequis sont satisfaits")
        return True
    
    def check_tool(self, tool_name):
        try:
            subprocess.run([tool_name, '--help'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def start_monitor_mode(self):
        self.log("Activation du mode monitor...")
        try:
            subprocess.run(['airmon-ng', 'start', self.config['interface']], check=True)
            self.log("Mode monitor activé")
            return True
        except:
            self.log("Échec de l'activation du mode monitor", "ERROR")
            return False
    
    def scan_networks(self):
        self.log("Début du scan des réseaux...")
        
        self.scanner = NetworkScanner(self.config['interface'], self.config['output_dir'])
        self.scanner.start_monitor_mode()
        
        networks = self.scanner.scan_networks_fast(30)
        
        if networks:
            self.log(f"Scan terminé: {len(networks)} réseaux trouvés")
            return networks
        else:
            self.log("Aucun réseau trouvé", "WARNING")
            return []
    
    def select_target(self, networks):
        if not networks:
            return None
        
        print("\n📡 Réseaux WiFi détectés:")
        for i, network in enumerate(networks):
            print(f"  {i+1}. {network.get('essid', 'SSID Caché')} - {network['bssid']} (Canal {network['channel']})")
        
        try:
            choice = int(input(f"\n🎯 Choisissez une cible (1-{len(networks)}): ")) - 1
            if 0 <= choice < len(networks):
                return networks[choice]
        except ValueError:
            pass
        
        return None
    
    def run_advanced_attacks(self, target):
        self.log(f"Lancement des attaques avancées sur {target['essid']}")
        
        self.attacker = AdvancedAttacks(
            interface=self.config['interface'],
            target_bssid=target['bssid'],
            target_essid=target['essid'],
            output_dir=self.config['output_dir']
        )
        
        # Lancer toutes les attaques
        success = self.attacker.run_all_attacks()
        
        if success:
            self.results.extend(self.attacker.results)
            self.log("Attaques avancées terminées avec succès")
        else:
            self.log("Certaines attaques ont échoué", "WARNING")
        
        return success
    
    def run_ruby_attacks(self, target):
        self.log("Lancement des attaques Ruby...")
        
        try:
            command = [
                'ruby', 'ruby_attack.rb',
                '-i', self.config['interface'],
                '-t', target['bssid'],
                '-e', target['essid'],
                '-o', self.config['output_dir']
            ]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                self.log("Attaques Ruby terminées avec succès")
                return True
            else:
                self.log("Attaques Ruby échouées", "WARNING")
                return False
                
        except Exception as e:
            self.log(f"Erreur lors des attaques Ruby: {e}", "ERROR")
            return False
    
    def run_bash_attacks(self, target):
        self.log("Lancement des attaques Bash...")
        
        try:
            command = [
                './leviwifite.sh',
                '-i', self.config['interface'],
                '-t', target['bssid'],
                '--auto'
            ]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                self.log("Attaques Bash terminées avec succès")
                return True
            else:
                self.log("Attaques Bash échouées", "WARNING")
                return False
                
        except Exception as e:
            self.log(f"Erreur lors des attaques Bash: {e}", "ERROR")
            return False
    
    def generate_final_report(self, scan_data):
        self.log("Génération du rapport final...")
        
        self.report_generator = ReportGenerator(self.config['output_dir'])
        
        # Préparer les données de scan
        scan_report = {
            'networks_found': len(scan_data),
            'networks': scan_data,
            'scan_time': datetime.now().isoformat()
        }
        
        # Générer le rapport principal
        report_file = self.report_generator.generate_main_report(scan_report, self.results)
        
        self.log(f"Rapport final généré: {report_file}")
        return report_file
    
    def cleanup(self):
        self.log("Nettoyage en cours...")
        
        # Arrêter tous les processus
        for process in self.attack_processes:
            try:
                process.terminate()
            except:
                pass
        
        # Désactiver le mode monitor
        try:
            subprocess.run(['airmon-ng', 'stop', self.config['interface']], check=True)
            self.log("Mode monitor désactivé")
        except:
            pass
    
    def run_full_pentest(self):
        self.log("🚀 Début du pentest WiFi complet LEVIWIFITE")
        
        try:
            # 1. Vérifications
            if not self.check_prerequisites():
                return False
            
            # 2. Mode monitor
            if not self.start_monitor_mode():
                return False
            
            # 3. Scan des réseaux
            networks = self.scan_networks()
            if not networks:
                self.log("Aucun réseau disponible", "ERROR")
                return False
            
            # 4. Sélection de la cible
            target = self.select_target(networks)
            if not target:
                self.log("Aucune cible sélectionnée", "ERROR")
                return False
            
            self.log(f"Cible sélectionnée: {target['essid']} ({target['bssid']})")
            
            # 5. Attaques Python avancées
            self.run_advanced_attacks(target)
            
            # 6. Attaques Ruby
            self.run_ruby_attacks(target)
            
            # 7. Attaques Bash
            self.run_bash_attacks(target)
            
            # 8. Génération du rapport final
            self.generate_final_report(networks)
            
            self.log("🎉 Pentest WiFi complet terminé avec succès!")
            return True
            
        except KeyboardInterrupt:
            self.log("Interruption utilisateur", "WARNING")
            return False
        except Exception as e:
            self.log(f"Erreur lors du pentest: {e}", "ERROR")
            return False
        finally:
            self.cleanup()

def signal_handler(signum, frame):
    print("\n[!] Signal d'arrêt reçu. Nettoyage...")
    if hasattr(signal_handler, 'master'):
        signal_handler.master.cleanup()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='LEVIWIFITE MASTER - Pentest WiFi Ultra-Avancé')
    parser.add_argument('-i', '--interface', default='wlan0', help='Interface WiFi')
    parser.add_argument('-a', '--auto', action='store_true', help='Mode automatique')
    parser.add_argument('--config', help='Fichier de configuration')
    
    args = parser.parse_args()
    
    # Configuration des signaux
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialisation
    master = LeviWifiteMaster()
    signal_handler.master = master
    
    if args.interface:
        master.config['interface'] = args.interface
    
    if args.config:
        try:
            with open(args.config, 'r') as f:
                master.config.update(json.load(f))
        except:
            pass
    
    # Bannière
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    🚀 LEVIWIFITE MASTER 🚀                 ║
    ║              Pentest WiFi Ultra-Avancé                     ║
    ║              Coordination Multi-Langage                     ║
    ║                    Python + Ruby + Bash                    ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Exécution du pentest complet
    success = master.run_full_pentest()
    
    if success:
        print("\n🎉 LEVIWIFITE MASTER terminé avec succès!")
        print(f"📊 Consultez le rapport: {master.config['output_dir']}/rapport_final.html")
    else:
        print("\n💥 LEVIWIFITE MASTER a rencontré des erreurs")
        sys.exit(1)

if __name__ == "__main__":
    main()