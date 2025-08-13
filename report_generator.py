#!/usr/bin/env python3
"""
LEVIWIFITE - Générateur de Rapports Avancés
Rapports HTML détaillés et professionnels
"""

import os
import json
import time
from datetime import datetime
import argparse

class ReportGenerator:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.reports = []
        
    def generate_main_report(self, scan_data, attack_results):
        self.log("Génération du rapport principal")
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>LEVIWIFITE - Rapport de Pentest WiFi</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a0a; color: #ffffff; line-height: 1.6; }}
                .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px; border-radius: 15px; text-align: center; margin-bottom: 30px; }}
                .header h1 {{ font-size: 3em; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.5); }}
                .header p {{ font-size: 1.2em; opacity: 0.9; }}
                .section {{ background: #1a1a1a; padding: 25px; border-radius: 10px; margin-bottom: 25px; border-left: 5px solid #667eea; }}
                .section h2 {{ color: #667eea; margin-bottom: 20px; font-size: 1.8em; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 25px; }}
                .stat-card {{ background: #2a2a2a; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #333; }}
                .stat-number {{ font-size: 2.5em; font-weight: bold; color: #667eea; }}
                .stat-label {{ color: #ccc; margin-top: 5px; }}
                .network-list {{ display: grid; gap: 15px; }}
                .network-item {{ background: #2a2a2a; padding: 20px; border-radius: 8px; border: 1px solid #333; }}
                .network-item h3 {{ color: #667eea; margin-bottom: 10px; }}
                .network-details {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }}
                .detail {{ background: #333; padding: 10px; border-radius: 5px; }}
                .detail strong {{ color: #667eea; }}
                .attack-results {{ margin-top: 20px; }}
                .attack-item {{ background: #2a2a2a; padding: 15px; border-radius: 8px; margin-bottom: 15px; border-left: 4px solid #27ae60; }}
                .attack-item.failure {{ border-left-color: #e74c3c; }}
                .timestamp {{ color: #888; font-size: 0.9em; }}
                .footer {{ text-align: center; margin-top: 40px; padding: 20px; color: #666; border-top: 1px solid #333; }}
                .success {{ color: #27ae60; }}
                .failure {{ color: #e74c3c; }}
                .warning {{ color: #f39c12; }}
                .info {{ color: #3498db; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚀 LEVIWIFITE</h1>
                    <p>Rapport de Pentest WiFi Avancé - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div class="section">
                    <h2>📊 Statistiques Générales</h2>
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-number">{scan_data.get('networks_found', 0)}</div>
                            <div class="stat-label">Réseaux Détectés</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{len(attack_results)}</div>
                            <div class="stat-label">Attaques Effectuées</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{len([r for r in attack_results if r.get('success', False)])}</div>
                            <div class="stat-label">Attaques Réussies</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{len([r for r in attack_results if not r.get('success', False)])}</div>
                            <div class="stat-label">Attaques Échouées</div>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>📡 Réseaux WiFi Détectés</h2>
                    <div class="network-list">
        """
        
        for network in scan_data.get('networks', []):
            html_content += f"""
                        <div class="network-item">
                            <h3>{network.get('essid', 'SSID Caché')}</h3>
                            <div class="network-details">
                                <div class="detail">
                                    <strong>BSSID:</strong> {network.get('bssid', 'N/A')}
                                </div>
                                <div class="detail">
                                    <strong>Canal:</strong> {network.get('channel', 'N/A')}
                                </div>
                                <div class="detail">
                                    <strong>Puissance:</strong> {network.get('power', 'N/A')}
                                </div>
                                <div class="detail">
                                    <strong>Chiffrement:</strong> {network.get('encryption', 'N/A')}
                                </div>
                            </div>
                        </div>
            """
        
        html_content += """
                    </div>
                </div>
                
                <div class="section">
                    <h2>⚔️ Résultats des Attaques</h2>
                    <div class="attack-results">
        """
        
        for result in attack_results:
            status_class = "attack-item" if result.get('success', False) else "attack-item failure"
            status_icon = "✅" if result.get('success', False) else "❌"
            
            html_content += f"""
                        <div class="{status_class}">
                            <h3>{status_icon} {result.get('attack_type', 'Attaque')}</h3>
                            <p><strong>Cible:</strong> {result.get('target', 'N/A')}</p>
                            <p><strong>BSSID:</strong> {result.get('bssid', 'N/A')}</p>
            """
            
            if result.get('password'):
                html_content += f'<p><strong>Mot de passe:</strong> <span class="success">{result["password"]}</span></p>'
            
            if result.get('wps_pin'):
                html_content += f'<p><strong>PIN WPS:</strong> <span class="success">{result["wps_pin"]}</span></p>'
            
            html_content += f"""
                            <p class="timestamp">Timestamp: {result.get('timestamp', 'N/A')}</p>
                        </div>
            """
        
        html_content += """
                    </div>
                </div>
                
                <div class="footer">
                    <p>Rapport généré automatiquement par LEVIWIFITE</p>
                    <p>🚀 Outil de Pentest WiFi Ultra-Avancé</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        report_file = os.path.join(self.output_dir, "rapport_final.html")
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.log(f"Rapport principal généré: {report_file}")
        return report_file
    
    def log(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {message}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='LEVIWIFITE - Générateur de Rapports')
    parser.add_argument('--output', required=True, help='Répertoire de sortie')
    parser.add_argument('--scan-data', help='Fichier de données de scan JSON')
    parser.add_argument('--attack-results', help='Fichier de résultats d\'attaques JSON')
    
    args = parser.parse_args()
    
    generator = ReportGenerator(args.output)
    
    # Charger les données
    scan_data = {}
    attack_results = []
    
    if args.scan_data and os.path.exists(args.scan_data):
        with open(args.scan_data, 'r') as f:
            scan_data = json.load(f)
    
    if args.attack_results and os.path.exists(args.attack_results):
        with open(args.attack_results, 'r') as f:
            attack_results = json.load(f)
    
    generator.generate_main_report(scan_data, attack_results)
