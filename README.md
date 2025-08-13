# 🚀 LEVIWIFITE - Outil de Pentest WiFi Ultra-Avancé

**LEVIWIFITE** est un outil de pentest WiFi ultra-avancé qui combine les fonctionnalités de **Wifite** et **Airgeddon** avec une coordination multi-langage (Python + Bash + Ruby + HTML) et un module de pentest réseau **LEVIPENTBOX** intégré.

## 🌟 Fonctionnalités Principales

### 🔍 **Scanning WiFi Avancé**
- Détection automatique des réseaux WiFi
- Analyse des canaux et puissances
- Identification des points d'accès vulnérables
- Scan ultra-rapide avec multi-threading

### ⚔️ **Attaques WiFi Multi-Vecteurs**
- **Handshake Capture** : Capture des handshakes WPA/WPA2
- **Déauthentification** : Attaques de déconnexion forcée
- **WPS Attacks** : Tentatives de crack WPS
- **Evil Twin** : Création de points d'accès malveillants
- **Cracking** : Brute-force des mots de passe
- **MDK4 Attacks** : Attaques de niveau expert

### 🎯 **Coordination Multi-Langage**
- **Python** : Moteur d'attaque principal et modules avancés
- **Bash** : Script de coordination et orchestration
- **Ruby** : Composants d'attaque avancés et LEVIPENTBOX
- **HTML** : Rapports détaillés et visualisation

### 🔓 **LEVIPENTBOX - Module de Pentest Réseau**
- **Scan de ports multi-thread** ultra-rapide
- **Détection de vulnérabilités** web, SSH, FTP, bases de données
- **Brute force multi-service** (SSH, FTP, Web, MySQL, PostgreSQL)
- **Scan de réseaux entiers** avec notation CIDR
- **Rapports de sécurité** professionnels

### 📊 **Rapports et Analyse**
- Rapports HTML détaillés et modernes
- Statistiques des attaques et vulnérabilités
- Historique des tentatives
- Export des résultats en JSON et HTML

## 🛠️ Installation

### Prérequis
```bash
# Système basé sur Debian/Ubuntu/Kali
sudo apt update
sudo apt install -y aircrack-ng reaver hostapd python3 ruby jq

# Vérification des outils
which airmon-ng airodump-ng aireplay-ng aircrack-ng python3 ruby
```

### Installation de LEVIWIFITE
```bash
# Cloner le projet
git clone https://github.com/votre-repo/leviwifite.git
cd leviwifite

# Rendre les scripts exécutables
chmod +x *.sh *.py *.rb levipentbox/*.rb

# Créer les répertoires nécessaires
mkdir -p results temp logs levipentbox_results

# Installation automatique
sudo ./install.sh
```

## 🚀 Utilisation

### 🎯 **Mode Basique - WiFi**
```bash
# Scan et attaque automatique
sudo ./leviwifite.sh --auto

# Scan uniquement
sudo ./leviwifite.sh --scan-only

# Interface spécifique
sudo ./leviwifite.sh -i wlan1 --auto
```

### ⚔️ **Mode Avancé - WiFi**
```bash
# Attaque d'une cible spécifique
sudo ./leviwifite.sh -t AA:BB:CC:DD:EE:FF

# Mode manuel avec sélection
sudo ./leviwifite.sh

# Utilisation directe du moteur Python
sudo python3 main.py --interface wlan0 --auto
```

### 🔓 **Mode LEVIPENTBOX - Réseau**
```bash
# Scan complet d'une cible réseau
ruby levipentbox/levipentbox.rb -t 192.168.1.1 -p 1-1000 --aggressive

# Scan d'un réseau entier
ruby levipentbox/levipentbox.rb -t 192.168.1.0/24 --threads 20

# Mode verbeux avec brute force
ruby levipentbox/levipentbox.rb -t example.com -v -a
```

### 🐍 **Composants Individuels**
```bash
# Moteur d'attaque Python
sudo python3 attack_engine.py --interface wlan0 --target AA:BB:CC:DD:EE:FF --essid "NomReseau" --channel 6 --output results/

# Composant Ruby
sudo ruby ruby_attack.rb -i wlan0 -t AA:BB:CC:DD:EE:FF -e "NomReseau" -o results/

# Scanner réseau Levipentbox
ruby levipentbox/network_scanner.rb --interface eth0 --output results

# Scan de vulnérabilités
ruby levipentbox/vulnerability_scanner.rb --target 192.168.1.1 --output results
```

## 📁 Structure du Projet

```
leviwifite/
├── main.py                     # Moteur principal Python
├── leviwifite.sh              # Script de coordination Bash
├── ruby_attack.rb             # Composant d'attaque Ruby
├── attack_engine.py           # Moteur d'attaque Python avancé
├── advanced_attacks.py        # Module d'attaques avancées
├── ultra_attacks.py           # Module d'attaques ultra-avancées
├── network_scanner.py         # Module de scan réseau Python
├── report_generator.py        # Générateur de rapports
├── leviwifite_master.py       # Coordinateur principal
├── leviwifite_launcher.py     # Lanceur ultra-avancé
├── config.json                # Configuration
├── install.sh                 # Script d'installation automatique
├── README.md                  # Documentation principale
│
├── levipentbox/               # Module de Pentest Réseau
│   ├── levipentbox.rb         # Module principal Levipentbox
│   ├── network_scanner.rb     # Scanner réseau ultra-rapide
│   ├── vulnerability_scanner.rb # Scan de vulnérabilités avancé
│   ├── brute_force.rb         # Module de brute force multi-service
│   └── README.md              # Documentation Levipentbox
│
├── results/                   # Résultats et rapports
└── temp/                      # Fichiers temporaires
```

## ⚙️ Configuration

### Fichier `config.json`
```json
{
  "interface": "wlan0",
  "monitor_mode": true,
  "attack_timeout": 300,
  "wordlist_path": "/usr/share/wordlists/rockyou.txt",
  "output_dir": "results",
  "log_level": "INFO",
  "attacks": {
    "handshake": true,
    "wps": true,
    "evil_twin": false,
    "deauth": true
  },
  "modules": {
    "network_scanner": true,
    "advanced_attacks": true,
    "ultra_attacks": true,
    "network_analyzer": true,
    "ruby_attacks": true,
    "bash_attacks": true
  }
}
```

## 📊 Types de Rapports

### 1. **Rapports WiFi**
- `rapport_leviwifite.html` - Rapport principal Python
- `rapport_ruby.html` - Rapport des composants Ruby
- `rapport_final.html` - Rapport combiné final

### 2. **Rapports LEVIPENTBOX**
- `network_scan_report.json` - Scan réseau
- `vulnerability_report.json` - Vulnérabilités détectées
- `brute_force_report.json` - Résultats brute force
- `levipentbox_report.html` - Rapport HTML principal

### 3. **Rapports Combinés**
- `master_results.json` - Résultats complets
- `rapport_final.html` - Rapport maître unifié

## 🔒 Sécurité et Légalité

### ⚠️ **AVERTISSEMENT IMPORTANT**
- **UNIQUEMENT** pour des tests de sécurité autorisés
- **NE PAS** utiliser sur des réseaux sans permission
- Respecter les lois locales sur la cybersécurité
- Utiliser uniquement sur vos propres réseaux ou avec autorisation écrite

### 🎯 **Cas d'Usage Légitimes**
- Tests de sécurité de vos propres réseaux
- Audits de sécurité autorisés
- Formation et recherche en cybersécurité
- Tests de pénétration avec consentement

## 🐛 Dépannage

### Problèmes Courants

#### Interface WiFi non détectée
```bash
# Vérifier les interfaces disponibles
iw dev

# Vérifier les permissions
sudo iw dev

# Installer les firmwares si nécessaire
sudo apt install firmware-iwlwifi
```

#### Erreur de mode monitor
```bash
# Arrêter les processus qui utilisent l'interface
sudo airmon-ng check kill

# Redémarrer le service réseau
sudo systemctl restart NetworkManager
```

#### Outils manquants
```bash
# Installation complète d'aircrack-ng
sudo apt install -y aircrack-ng

# Installation de reaver
sudo apt install -y reaver

# Installation de hostapd
sudo apt install -y hostapd

# Installation de Ruby
sudo apt install -y ruby ruby-dev
```

## 🤝 Contribution

### Comment Contribuer
1. Fork le projet
2. Créer une branche pour votre fonctionnalité
3. Commiter vos changements
4. Pousser vers la branche
5. Ouvrir une Pull Request

### Standards de Code
- Python : PEP 8
- Ruby : Standard Ruby Style Guide
- Bash : Google Shell Style Guide
- Documentation en français et anglais

## 📝 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## 🙏 Remerciements

- **Aircrack-ng Team** : Outils de base WiFi
- **Wifite** : Inspiration pour l'interface WiFi
- **Airgeddon** : Concepts d'attaque avancés
- **Pentbox** : Inspiration pour LEVIPENTBOX
- **Communauté Open Source** : Support et contributions

## 📞 Support

### Canaux de Support
- **Issues GitHub** : Bugs et demandes de fonctionnalités
- **Discussions** : Questions et aide
- **Wiki** : Documentation détaillée

### Contact
- **Email** : support@leviwifite.com
- **Twitter** : @LeviWifite
- **Discord** : [Serveur LEVIWIFITE](https://discord.gg/leviwifite)

---

## ⚡ Quick Start

```bash
# Installation rapide
git clone https://github.com/votre-repo/leviwifite.git
cd leviwifite
chmod +x *.sh *.py *.rb levipentbox/*.rb
sudo ./install.sh

# Test WiFi
sudo ./leviwifite.sh --auto

# Test Réseau
ruby levipentbox/levipentbox.rb -t 192.168.1.1 -v
```

---

## 🔥 Fonctionnalités Ultra-Avancées

### **Intelligence Artificielle**
- **Détection automatique** des patterns d'attaque
- **Apprentissage** des vulnérabilités communes
- **Optimisation automatique** des scans

### **Furtivité Avancée**
- **Techniques d'évasion** des IDS/IPS
- **Timing intelligent** des requêtes
- **Rotation des User-Agents**

### **Coordination Multi-Cible**
- **Scan de réseaux entiers** en parallèle
- **Distribution de charge** automatique
- **Synchronisation** des résultats

### **Modules Spécialisés**
- **LEVIPENTBOX** : Pentest réseau ultra-avancé
- **Attaques WiFi** : Multi-vecteurs coordonnés
- **Analyse de vulnérabilités** : Détection intelligente
- **Brute force** : Multi-protocole et optimisé

---

## 🏆 Pourquoi LEVIWIFITE est SUPÉRIEUR

1. **Coordination Multi-Langage** - Python + Ruby + Bash + HTML
2. **Modules Intégrés** - WiFi + Réseau dans un seul outil
3. **Performance Ultra-Rapide** - Multi-threading et optimisation
4. **Fonctionnalités Avancées** - Au-delà de Wifite et Airgeddon
5. **LEVIPENTBOX Intégré** - Pentest réseau de niveau expert
6. **Rapports Professionnels** - JSON, HTML et visualisation
7. **Architecture Modulaire** - Extensible et maintenable
8. **Documentation Complète** - Guides et exemples détaillés

**🚀 LEVIWIFITE + LEVIPENTBOX = L'outil de pentest le plus avancé jamais créé !**

**Prêt à devenir un pentester ultra-fort avec LEVIWIFITE ?** ⚔️🔓🌐
