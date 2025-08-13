# 🚀 LEVIWIFITE - Outil de Pentest WiFi Avancé

**LEVIWIFITE** est un outil de pentest WiFi ultra-avancé qui combine les fonctionnalités de **Wifite** et **Airgeddon** avec une coordination multi-langage (Python + Bash + Ruby + HTML).

## 🌟 Fonctionnalités

### 🔍 **Scanning Avancé**
- Détection automatique des réseaux WiFi
- Analyse des canaux et puissances
- Identification des points d'accès vulnérables

### ⚔️ **Attaques Multi-Vecteurs**
- **Handshake Capture** : Capture des handshakes WPA/WPA2
- **Déauthentification** : Attaques de déconnexion forcée
- **WPS Attacks** : Tentatives de crack WPS
- **Evil Twin** : Création de points d'accès malveillants
- **Cracking** : Brute-force des mots de passe

### 🎯 **Coordination Multi-Langage**
- **Python** : Moteur d'attaque principal
- **Bash** : Script de coordination et orchestration
- **Ruby** : Composants d'attaque avancés
- **HTML** : Rapports détaillés et visualisation

### 📊 **Rapports et Analyse**
- Rapports HTML détaillés
- Statistiques des attaques
- Historique des tentatives
- Export des résultats

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
chmod +x leviwifite.sh
chmod +x main.py
chmod +x ruby_attack.rb

# Créer les répertoires nécessaires
mkdir -p results temp
```

## 🚀 Utilisation

### 🎯 **Mode Basique**
```bash
# Scan et attaque automatique
sudo ./leviwifite.sh --auto

# Scan uniquement
sudo ./leviwifite.sh --scan-only

# Interface spécifique
sudo ./leviwifite.sh -i wlan1 --auto
```

### ⚔️ **Mode Avancé**
```bash
# Attaque d'une cible spécifique
sudo ./leviwifite.sh -t AA:BB:CC:DD:EE:FF

# Mode manuel avec sélection
sudo ./leviwifite.sh

# Utilisation directe du moteur Python
sudo python3 main.py --interface wlan0 --auto
```

### 🐍 **Composants Individuels**
```bash
# Moteur d'attaque Python
sudo python3 attack_engine.py --interface wlan0 --target AA:BB:CC:DD:EE:FF --essid "NomReseau" --channel 6 --output results/

# Composant Ruby
sudo ruby ruby_attack.rb -i wlan0 -t AA:BB:CC:DD:EE:FF -e "NomReseau" -o results/
```

## 📁 Structure du Projet

```
leviwifite/
├── main.py                 # Moteur principal Python
├── leviwifite.sh          # Script de coordination Bash
├── ruby_attack.rb         # Composant d'attaque Ruby
├── attack_engine.py       # Moteur d'attaque Python avancé
├── config.json            # Configuration
├── README.md              # Documentation
├── results/               # Résultats et rapports
└── temp/                  # Fichiers temporaires
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
  }
}
```

## 📊 Rapports

### Types de Rapports
1. **Rapport Python** : Détails des attaques Python
2. **Rapport Ruby** : Résultats des composants Ruby
3. **Rapport Final** : Combinaison de tous les résultats

### Localisation des Rapports
- `results/rapport_python.html`
- `results/rapport_ruby.html`
- `results/rapport_final.html`

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

- **Aircrack-ng Team** : Outils de base
- **Wifite** : Inspiration pour l'interface
- **Airgeddon** : Concepts d'attaque avancés
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
chmod +x *.sh *.py *.rb
sudo ./leviwifite.sh --auto
```

**🚀 Prêt à devenir un pentester WiFi ultra-fort avec LEVIWIFITE !**
