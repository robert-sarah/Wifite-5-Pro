# 🔓 LEVIPENTBOX - Outil de Pentest Réseau Ultra-Avancé

**LEVIPENTBOX** est un outil de pentest réseau ultra-avancé écrit en Ruby, inspiré de Pentbox mais avec des fonctionnalités encore plus puissantes et modernes.

## 🌟 Fonctionnalités Ultra-Avancées

### 🔍 **Scan Réseau Intelligent**
- **Scan de ports multi-thread** ultra-rapide
- **Détection automatique des services** (SSH, FTP, HTTP, MySQL, PostgreSQL)
- **Scan de plages réseau** avec notation CIDR
- **Détection des hôtes actifs** avec timeout optimisé

### ⚔️ **Scan de Vulnérabilités Avancé**
- **Test des en-têtes de sécurité** manquants
- **Détection des méthodes HTTP** dangereuses (TRACE, OPTIONS, PUT, DELETE)
- **Test de directory traversal** avec payloads multiples
- **Détection SQL Injection** avec payloads avancés
- **Test XSS** avec vecteurs d'attaque modernes
- **Scan SSH/FTP** avec détection de versions vulnérables
- **Test des bases de données** (MySQL, PostgreSQL)

### 🔓 **Brute Force Multi-Service**
- **SSH brute force** avec gestion des threads
- **FTP brute force** avec test de connexion
- **Web brute force** avec détection automatique des formulaires
- **Base de données brute force** (MySQL, PostgreSQL)
- **Gestion intelligente des wordlists** avec fallback automatique

### 📊 **Rapports Professionnels**
- **Rapports JSON** détaillés et structurés
- **Rapports HTML** avec interface moderne
- **Statistiques de vulnérabilités** par niveau de sévérité
- **Historique des scans** avec timestamps

## 🛠️ Installation

### Prérequis
```bash
# Système basé sur Debian/Ubuntu/Kali
sudo apt update
sudo apt install -y ruby ruby-dev build-essential

# Vérification
ruby --version
gem --version
```

### Installation de Levipentbox
```bash
# Rendre les scripts exécutables
chmod +x levipentbox/*.rb

# Créer le répertoire de sortie
mkdir -p levipentbox_results
```

## 🚀 Utilisation

### 🎯 **Scan Complet d'une Cible**
```bash
# Scan complet avec toutes les fonctionnalités
ruby levipentbox/levipentbox.rb -t 192.168.1.1 -p 1-1000 --aggressive

# Scan avec interface spécifique
ruby levipentbox/levipentbox.rb -t 192.168.1.1 -i eth1

# Mode verbeux
ruby levipentbox/levipentbox.rb -t 192.168.1.1 -v
```

### 🔍 **Modules Individuels**

#### Scanner Réseau
```bash
ruby levipentbox/network_scanner.rb --interface eth0 --output results
```

#### Scan de Vulnérabilités
```bash
ruby levipentbox/vulnerability_scanner.rb --target 192.168.1.1 --output results
```

#### Brute Force
```bash
ruby levipentbox/brute_force.rb --target 192.168.1.1 --output results
```

## 📁 Structure du Projet

```
levipentbox/
├── levipentbox.rb           # Module principal et coordinateur
├── network_scanner.rb       # Scanner réseau ultra-rapide
├── vulnerability_scanner.rb # Scan de vulnérabilités avancé
├── brute_force.rb          # Module de brute force multi-service
└── README.md               # Documentation complète
```

## ⚙️ Configuration

### Options de Levipentbox
- `-t, --target` : Cible (IP ou domaine)
- `-i, --interface` : Interface réseau
- `-p, --ports` : Plage de ports (ex: 1-1000)
- `--threads` : Nombre de threads
- `-o, --output` : Répertoire de sortie
- `-v, --verbose` : Mode verbeux
- `-a, --aggressive` : Mode agressif

### Exemples de Configuration
```bash
# Scan complet d'un réseau
ruby levipentbox/levipentbox.rb -t 192.168.1.0/24 -p 1-65535 --threads 20

# Scan d'une cible spécifique avec ports communs
ruby levipentbox/levipentbox.rb -t example.com -p 21,22,23,25,53,80,110,143,443,993,995,3306,5432

# Mode agressif avec brute force
ruby levipentbox/levipentbox.rb -t 192.168.1.1 --aggressive -v
```

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

## 📊 Types de Rapports

### 1. **Rapport de Scan Réseau**
- Liste des hôtes actifs
- Ports ouverts et services détectés
- Statistiques de scan

### 2. **Rapport de Vulnérabilités**
- Vulnérabilités par niveau de sévérité
- Détails techniques des vulnérabilités
- Recommandations de correction

### 3. **Rapport de Brute Force**
- Credentials trouvées par service
- Statistiques de succès/échec
- Logs détaillés des tentatives

### 4. **Rapport Principal**
- Synthèse de tous les modules
- Vue d'ensemble de la sécurité
- Interface HTML moderne

## 🐛 Dépannage

### Problèmes Courants

#### Ruby non installé
```bash
sudo apt install -y ruby ruby-dev
```

#### Permissions insuffisantes
```bash
# Pour le scan de ports bas
sudo ruby levipentbox/levipentbox.rb -t 192.168.1.1
```

#### Wordlists manquantes
```bash
sudo apt install -y wordlists
# Ou créer des wordlists personnalisées
```

## 🤝 Contribution

### Comment Contribuer
1. Fork le projet
2. Créer une branche pour votre fonctionnalité
3. Commiter vos changements
4. Pousser vers la branche
5. Ouvrir une Pull Request

### Standards de Code
- Ruby : Standard Ruby Style Guide
- Documentation en français et anglais
- Tests unitaires pour les nouvelles fonctionnalités

## 📝 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## 🙏 Remerciements

- **Pentbox** : Inspiration pour l'architecture
- **Ruby Community** : Support et bibliothèques
- **Communauté Open Source** : Contributions et améliorations

## 📞 Support

### Canaux de Support
- **Issues GitHub** : Bugs et demandes de fonctionnalités
- **Discussions** : Questions et aide
- **Wiki** : Documentation détaillée

---

## ⚡ Quick Start

```bash
# Installation rapide
chmod +x levipentbox/*.rb
mkdir -p levipentbox_results

# Premier scan
ruby levipentbox/levipentbox.rb -t 192.168.1.1 -v
```

**🚀 Prêt à devenir un pentester réseau ultra-fort avec LEVIPENTBOX !**

---

## 🔥 Fonctionnalités Avancées

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

**LEVIPENTBOX est l'outil de pentest réseau le plus avancé jamais créé !** 🔓⚔️
