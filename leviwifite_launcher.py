#!/usr/bin/env python3
"""
LEVIWIFITE LAUNCHER - Lanceur Principal Ultra-Avancé
Coordination complète de tous les modules et composants
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

class LeviWifiteLauncher:
    def __init__(self):
        self.config = self.load_config()
        self.modules = {}
        self.results = {}
        self.current_operation = None
        
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
                "log_level": "INFO",
                "modules": {
                    "network_scanner": True,
                    "advanced_attacks": True,
                    "ultra_attacks": True,
                    "network_analyzer": True,
                    "ruby_attacks": True,
                    "bash_attacks": True
                }
            }
    
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{level}] {message}")
    
    def check_prerequisites(self):
        self.log("🔍 Vérification des prérequis...")
        
        tools = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "python3", "ruby"]
        missing = []
        
        for tool in tools:
            if not self.check_tool(tool):
                missing.append(tool)
        
        if missing:
            self.log(f"❌ Outils manquants: {missing}", "ERROR")
            return False
        
        self.log("✅ Tous les prérequis sont satisfaits")
        return True
    
    def check_tool(self, tool_name):
        try:
            subprocess.run([tool_name, '--help'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def start_monitor_mode(self):
        self.log("🚀 Activation du mode monitor...")
        try:
            subprocess.run(['airmon-ng', 'start', self.config['interface']], check=True)
            self.log("✅ Mode monitor activé")
            return True
        except:
            self.log("❌ Échec de l'activation du mode monitor", "ERROR")
            return False
    
    def run_network_scanner(self):
        self.log("📡 Lancement du scanner réseau...")
        
        try:
            from network_scanner import NetworkScanner
            scanner = NetworkScanner(self.config['interface'], self.config['output_dir'])
            scanner.start_monitor_mode()
            networks = scanner.scan_networks_fast(30)
            
            if networks:
                self.results['network_scan'] = {
                    'networks': networks,
                    'count': len(networks),
                    'timestamp': datetime.now().isoformat()
                }
                self.log(f"✅ Scan terminé: {len(networks)} réseaux trouvés")
                return networks
            else:
                self.log("⚠️ Aucun réseau trouvé", "WARNING")
                return []
                
        except Exception as e:
            self.log(f"❌ Erreur scanner réseau: {e}", "ERROR")
            return []
    
    def run_advanced_attacks(self, target):
        self.log("⚔️ Lancement des attaques avancées...")
        
        try:
            from advanced_attacks import AdvancedAttacks
            attacker = AdvancedAttacks(
                interface=self.config['interface'],
                target_bssid=target['bssid'],
                target_essid=target['essid'],
                output_dir=self.config['output_dir']
            )
            
            success = attacker.run_all_attacks()
            
            if success:
                self.results['advanced_attacks'] = {
                    'target': target,
                    'results': attacker.results,
                    'success': True,
                    'timestamp': datetime.now().isoformat()
                }
                self.log("✅ Attaques avancées terminées")
                return True
            else:
                self.log("⚠️ Certaines attaques avancées ont échoué", "WARNING")
                return False
                
        except Exception as e:
            self.log(f"❌ Erreur attaques avancées: {e}", "ERROR")
            return False
    
    def run_ultra_attacks(self, target):
        self.log("🚀 Lancement des attaques ultra-avancées...")
        
        try:
            from ultra_attacks import UltraAttacks
            attacker = UltraAttacks(
                interface=self.config['interface'],
                target_bssid=target['bssid'],
                target_essid=target['essid'],
                output_dir=self.config['output_dir']
            )
            
            success = attacker.run_all_ultra_attacks()
            
            if success:
                self.results['ultra_attacks'] = {
                    'target': target,
                    'results': attacker.results,
                    'success': True,
                    'timestamp': datetime.now().isoformat()
                }
                self.log("✅ Attaques ultra-avancées terminées")
                return True
            else:
                self.log("⚠️ Certaines attaques ultra ont échoué", "WARNING")
                return False
                
        except Exception as e:
            self.log(f"❌ Erreur attaques ultra: {e}", "ERROR")
            return False
    
    def run_network_analyzer(self):
        self.log("🔍 Lancement de l'analyseur réseau...")
        
        try:
            from network_analyzer import NetworkAnalyzer
            analyzer = NetworkAnalyzer(self.config['interface'], self.config['output_dir'])
            
            success = analyzer.run_full_analysis(60)
            
            if success:
                self.results['network_analysis'] = {
                    'networks': analyzer.networks,
                    'clients': analyzer.clients,
                    'vulnerabilities': analyzer.vulnerabilities,
                    'timestamp': datetime.now().isoformat()
                }
                self.log("✅ Analyse réseau terminée")
                return True
            else:
                self.log("⚠️ Analyse réseau échouée", "WARNING")
                return False
                
        except Exception as e:
            self.log(f"❌ Erreur analyseur réseau: {e}", "ERROR")
            return False
    
    def run_ruby_attacks(self, target):
        self.log("💎 Lancement des attaques Ruby...")
        
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
                self.results['ruby_attacks'] = {
                    'target': target,
                    'success': True,
                    'timestamp': datetime.now().isoformat()
                }
                self.log("✅ Attaques Ruby terminées")
                return True
            else:
                self.log("⚠️ Attaques Ruby échouées", "WARNING")
                return False
                
        except Exception as e:
            self.log(f"❌ Erreur attaques Ruby: {e}", "ERROR")
            return False
    
    def run_bash_attacks(self, target):
        self.log("🐚 Lancement des attaques Bash...")
        
        try:
            command = [
                './leviwifite.sh',
                '-i', self.config['interface'],
                '-t', target['bssid'],
                '--auto'
            ]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                self.results['bash_attacks'] = {
                    'target': target,
                    'success': True,
                    'timestamp': datetime.now().isoformat()
                }
                self.log("✅ Attaques Bash terminées")
                return True
            else:
                self.log("⚠️ Attaques Bash échouées", "WARNING")
                return False
                
        except Exception as e:
            self.log(f"❌ Erreur attaques Bash: {e}", "ERROR")
            return False
    
    def select_target(self, networks):
        if not networks:
            return None
        
        print("\n📡 RÉSEAUX WIFI DÉTECTÉS:")
        print("══════════════════════════════════════════════════════════════")
        
        for i, network in enumerate(networks):
            essid = network.get('essid', 'SSID Caché')
            bssid = network['bssid']
            channel = network['channel']
            encryption = network.get('encryption', 'N/A')
            power = network.get('power', 'N/A')
            
            print(f"  {i+1}. {essid}")
            print(f"     BSSID: {bssid}")
            print(f"     Canal: {channel} | Chiffrement: {encryption} | Puissance: {power}")
            print()
        
        try:
            choice = int(input(f"🎯 Choisissez une cible (1-{len(networks)}): ")) - 1
            if 0 <= choice < len(networks):
                return networks[choice]
        except ValueError:
            pass
        
        return None
    
    def generate_master_report(self):
        self.log("📊 Génération du rapport maître...")
        
        try:
            from report_generator import ReportGenerator
            generator = ReportGenerator(self.config['output_dir'])
            
            # Préparer les données
            scan_data = self.results.get('network_scan', {})
            attack_results = []
            
            # Collecter tous les résultats d'attaques
            for module, result in self.results.items():
                if 'attacks' in module and result.get('success'):
                    if 'results' in result:
                        attack_results.extend(result['results'])
                    else:
                        attack_results.append({
                            'target': result.get('target', {}).get('essid', 'N/A'),
                            'bssid': result.get('target', {}).get('bssid', 'N/A'),
                            'timestamp': result.get('timestamp', 'N/A'),
                            'success': True,
                            'attack_type': module.replace('_', ' ').title()
                        })
            
            # Générer le rapport
            report_file = generator.generate_main_report(scan_data, attack_results)
            
            self.log(f"✅ Rapport maître généré: {report_file}")
            return report_file
            
        except Exception as e:
            self.log(f"❌ Erreur génération rapport: {e}", "ERROR")
            return None
    
    def cleanup(self):
        self.log("🧹 Nettoyage en cours...")
        
        # Désactiver le mode monitor
        try:
            subprocess.run(['airmon-ng', 'stop', self.config['interface']], check=True)
            self.log("✅ Mode monitor désactivé")
        except:
            pass
        
        # Sauvegarder les résultats
        results_file = os.path.join(self.config['output_dir'], "master_results.json")
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.log(f"💾 Résultats sauvegardés: {results_file}")
    
    def run_complete_pentest(self):
        self.log("🚀 DÉBUT DU PENTEST WIFI COMPLET LEVIWIFITE")
        
        try:
            # 1. Vérifications
            if not self.check_prerequisites():
                return False
            
            # 2. Mode monitor
            if not self.start_monitor_mode():
                return False
            
            # 3. Scan des réseaux
            networks = self.run_network_scanner()
            if not networks:
                self.log("❌ Aucun réseau disponible", "ERROR")
                return False
            
            # 4. Sélection de la cible
            target = self.select_target(networks)
            if not target:
                self.log("❌ Aucune cible sélectionnée", "ERROR")
                return False
            
            self.log(f"🎯 Cible sélectionnée: {target['essid']} ({target['bssid']})")
            
            # 5. Attaques avancées
            if self.config['modules'].get('advanced_attacks', True):
                self.run_advanced_attacks(target)
            
            # 6. Attaques ultra-avancées
            if self.config['modules'].get('ultra_attacks', True):
                self.run_ultra_attacks(target)
            
            # 7. Analyseur réseau
            if self.config['modules'].get('network_analyzer', True):
                self.run_network_analyzer()
            
            # 8. Attaques Ruby
            if self.config['modules'].get('ruby_attacks', True):
                self.run_ruby_attacks(target)
            
            # 9. Attaques Bash
            if self.config['modules'].get('bash_attacks', True):
                self.run_bash_attacks(target)
            
            # 10. Génération du rapport maître
            self.generate_master_report()
            
            self.log("🎉 PENTEST WIFI COMPLET TERMINÉ AVEC SUCCÈS!")
            return True
            
        except KeyboardInterrupt:
            self.log("⚠️ Interruption utilisateur", "WARNING")
            return False
        except Exception as e:
            self.log(f"❌ Erreur lors du pentest: {e}", "ERROR")
            return False
        finally:
            self.cleanup()

def signal_handler(signum, frame):
    print("\n[!] Signal d'arrêt reçu. Nettoyage...")
    if hasattr(signal_handler, 'launcher'):
        signal_handler.launcher.cleanup()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='LEVIWIFITE LAUNCHER - Pentest WiFi Ultra-Avancé')
    parser.add_argument('-i', '--interface', default='wlan0', help='Interface WiFi')
    parser.add_argument('-a', '--auto', action='store_true', help='Mode automatique')
    parser.add_argument('--config', help='Fichier de configuration')
    parser.add_argument('--modules', help='Modules à activer (séparés par des virgules)')
    
    args = parser.parse_args()
    
    # Configuration des signaux
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialisation
    launcher = LeviWifiteLauncher()
    signal_handler.launcher = launcher
    
    if args.interface:
        launcher.config['interface'] = args.interface
    
    if args.config:
        try:
            with open(args.config, 'r') as f:
                launcher.config.update(json.load(f))
        except:
            pass
    
    if args.modules:
        module_list = args.modules.split(',')
        for module in launcher.config['modules']:
            launcher.config['modules'][module] = module in module_list
    
    # Bannière
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                🚀 LEVIWIFITE LAUNCHER 🚀                   ║
    ║              Pentest WiFi Ultra-Avancé                     ║
    ║              Coordination Multi-Modules                     ║
    ║              Python + Ruby + Bash + Analyse                ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Exécution du pentest complet
    success = launcher.run_complete_pentest()
    
    if success:
        print("\n🎉 LEVIWIFITE LAUNCHER terminé avec succès!")
        print(f"📊 Consultez le rapport: {launcher.config['output_dir']}/rapport_final.html")
        print(f"💾 Résultats complets: {launcher.config['output_dir']}/master_results.json")
    else:
        print("\n💥 LEVIWIFITE LAUNCHER a rencontré des erreurs")
        sys.exit(1)

if __name__ == "__main__":
    main()
