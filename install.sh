#!/bin/bash

# LEVIWIFITE - Script d'Installation Automatique
# Installation et configuration complète

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DISTRO=""
PACKAGE_MANAGER=""

# Fonctions utilitaires
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERREUR]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[ATTENTION]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Détection de la distribution
detect_distro() {
    log "Détection de la distribution Linux..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        log "Distribution détectée: $DISTRO"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
        log "Distribution détectée: Debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
        log "Distribution détectée: RHEL/CentOS"
    else
        DISTRO="unknown"
        warning "Distribution non reconnue"
    fi
    
    # Déterminer le gestionnaire de paquets
    case $DISTRO in
        "debian"|"ubuntu"|"kali"|"parrot")
            PACKAGE_MANAGER="apt"
            ;;
        "rhel"|"centos"|"fedora")
            PACKAGE_MANAGER="yum"
            ;;
        "arch")
            PACKAGE_MANAGER="pacman"
            ;;
        *)
            error "Distribution non supportée: $DISTRO"
            exit 1
            ;;
    esac
    
    log "Gestionnaire de paquets: $PACKAGE_MANAGER"
}

# Mise à jour du système
update_system() {
    log "Mise à jour du système..."
    
    case $PACKAGE_MANAGER in
        "apt")
            sudo apt update
            sudo apt upgrade -y
            ;;
        "yum")
            sudo yum update -y
            ;;
        "pacman")
            sudo pacman -Syu --noconfirm
            ;;
    esac
    
    log "Système mis à jour"
}

# Installation des dépendances système
install_system_deps() {
    log "Installation des dépendances système..."
    
    case $PACKAGE_MANAGER in
        "apt")
            sudo apt install -y \
                build-essential \
                git \
                curl \
                wget \
                python3 \
                python3-pip \
                python3-dev \
                ruby \
                ruby-dev \
                jq \
                hcxtools \
                hcxdumptool
            ;;
        "yum")
            sudo yum install -y \
                gcc \
                gcc-c++ \
                make \
                git \
                curl \
                wget \
                python3 \
                python3-pip \
                python3-devel \
                ruby \
                ruby-devel \
                jq
            ;;
        "pacman")
            sudo pacman -S --noconfirm \
                base-devel \
                git \
                curl \
                wget \
                python \
                python-pip \
                ruby \
                jq
            ;;
    esac
    
    log "Dépendances système installées"
}

# Installation d'aircrack-ng
install_aircrack() {
    log "Installation d'aircrack-ng..."
    
    case $PACKAGE_MANAGER in
        "apt")
            sudo apt install -y aircrack-ng
            ;;
        "yum")
            # RHEL/CentOS nécessite EPEL
            if ! rpm -q epel-release >/dev/null 2>&1; then
                sudo yum install -y epel-release
            fi
            sudo yum install -y aircrack-ng
            ;;
        "pacman")
            sudo pacman -S --noconfirm aircrack-ng
            ;;
    esac
    
    # Vérification de l'installation
    if command -v airmon-ng >/dev/null 2>&1; then
        log "Aircrack-ng installé avec succès"
    else
        error "Échec de l'installation d'aircrack-ng"
        exit 1
    fi
}

# Installation des outils supplémentaires
install_additional_tools() {
    log "Installation des outils supplémentaires..."
    
    case $PACKAGE_MANAGER in
        "apt")
            # Reaver pour les attaques WPS
            if command -v reaver >/dev/null 2>&1; then
                log "Reaver déjà installé"
            else
                sudo apt install -y reaver
            fi
            
            # Hostapd pour les attaques Evil Twin
            if command -v hostapd >/dev/null 2>&1; then
                log "Hostapd déjà installé"
            else
                sudo apt install -y hostapd
            fi
            
            # Bully pour les attaques WPS alternatives
            if command -v bully >/dev/null 2>&1; then
                log "Bully déjà installé"
            else
                sudo apt install -y bully
            fi
            ;;
        "yum")
            # Installation depuis les sources pour RHEL/CentOS
            log "Installation des outils depuis les sources..."
            install_from_source
            ;;
        "pacman")
            sudo pacman -S --noconfirm reaver hostapd
            ;;
    esac
    
    log "Outils supplémentaires installés"
}

# Installation depuis les sources
install_from_source() {
    log "Installation depuis les sources..."
    
    # Créer le répertoire temporaire
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Reaver
    if ! command -v reaver >/dev/null 2>&1; then
        log "Compilation de Reaver..."
        git clone https://github.com/t6x/reaver-wps-fork-t6x.git
        cd reaver-wps-fork-t6x/src
        ./configure
        make
        sudo make install
        cd ../..
    fi
    
    # Hostapd
    if ! command -v hostapd >/dev/null 2>&1; then
        log "Compilation de Hostapd..."
        git clone https://github.com/aircrack-ng/aircrack-ng.git
        cd aircrack-ng/patches/wpa_supplicant
        make
        sudo make install
        cd ../../..
    fi
    
    # Nettoyage
    cd "$SCRIPT_DIR"
    rm -rf "$TEMP_DIR"
}

# Installation des dépendances Python
install_python_deps() {
    log "Installation des dépendances Python..."
    
    # Mise à jour de pip
    python3 -m pip install --upgrade pip
    
    # Installation des packages requis
    python3 -m pip install \
        requests \
        beautifulsoup4 \
        colorama \
        tabulate \
        psutil \
        netifaces
    
    log "Dépendances Python installées"
}

# Installation des gems Ruby
install_ruby_deps() {
    log "Installation des gems Ruby..."
    
    # Mise à jour de gem
    sudo gem update --system
    
    # Installation des gems requises
    sudo gem install \
        bundler \
        json \
        optparse \
        fileutils \
        open3 \
        net-ssh \
        net-http
    
    log "Gems Ruby installées"
}

# Configuration des permissions
setup_permissions() {
    log "Configuration des permissions..."
    
    # Rendre les scripts exécutables
    chmod +x *.sh *.py *.rb
    
    # Créer les répertoires nécessaires
    mkdir -p results temp logs
    
    # Configuration des permissions pour l'interface WiFi
    if [ -f /etc/udev/rules.d/70-wifi.rules ]; then
        log "Règles udev WiFi déjà configurées"
    else
        log "Configuration des règles udev WiFi..."
        echo 'SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}=="?*", ATTR{dev_id}=="0x0", ATTR{type}=="1", KERNEL=="wlan*", NAME="%k"' | sudo tee /etc/udev/rules.d/70-wifi.rules
        sudo udevadm control --reload-rules
    fi
    
    log "Permissions configurées"
}

# Configuration de l'environnement
setup_environment() {
    log "Configuration de l'environnement..."
    
    # Vérifier si le répertoire est dans le PATH
    if [[ ":$PATH:" != *":$SCRIPT_DIR:"* ]]; then
        log "Ajout du répertoire au PATH..."
        echo "export PATH=\"\$PATH:$SCRIPT_DIR\"" >> ~/.bashrc
        echo "export PATH=\"\$PATH:$SCRIPT_DIR\"" >> ~/.zshrc
        export PATH="$PATH:$SCRIPT_DIR"
    fi
    
    # Créer un alias pour le lancement rapide
    if [ -f ~/.bashrc ]; then
        if ! grep -q "alias leviwifite" ~/.bashrc; then
            echo "alias leviwifite='sudo $SCRIPT_DIR/leviwifite.sh'" >> ~/.bashrc
        fi
    fi
    
    if [ -f ~/.zshrc ]; then
        if ! grep -q "alias leviwifite" ~/.zshrc; then
            echo "alias leviwifite='sudo $SCRIPT_DIR/leviwifite.sh'" >> ~/.zshrc
        fi
    fi
    
    log "Environnement configuré"
}

# Test de l'installation
test_installation() {
    log "Test de l'installation..."
    
    # Vérifier les outils essentiels
    local tools=("airmon-ng" "airodump-ng" "aireplay-ng" "aircrack-ng" "python3" "ruby")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        error "Outils manquants: ${missing_tools[*]}"
        return 1
    fi
    
    # Test Python
    if python3 -c "import requests, json, subprocess" 2>/dev/null; then
        log "Modules Python OK"
    else
        error "Modules Python manquants"
        return 1
    fi
    
    # Test Ruby
    if ruby -e "require 'json'; require 'optparse'" 2>/dev/null; then
        log "Gems Ruby OK"
    else
        error "Gems Ruby manquantes"
        return 1
    fi
    
    log "✅ Installation testée avec succès"
    return 0
}

# Affichage de l'aide
show_help() {
    echo -e "${CYAN}LEVIWIFITE - Script d'Installation${NC}"
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --skip-update        Ignorer la mise à jour du système"
    echo "  --skip-deps          Ignorer l'installation des dépendances"
    echo "  --skip-tools         Ignorer l'installation des outils"
    echo "  --skip-test          Ignorer le test de l'installation"
    echo "  -h, --help           Afficher cette aide"
    echo ""
    echo "Exemples:"
    echo "  $0                   Installation complète"
    echo "  $0 --skip-update    Installation sans mise à jour système"
}

# Fonction principale
main() {
    # Variables de contrôle
    SKIP_UPDATE=false
    SKIP_DEPS=false
    SKIP_TOOLS=false
    SKIP_TEST=false
    
    # Parsing des arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-update)
                SKIP_UPDATE=true
                shift
                ;;
            --skip-deps)
                SKIP_DEPS=true
                shift
                ;;
            --skip-tools)
                SKIP_TOOLS=true
                shift
                ;;
            --skip-test)
                SKIP_TEST=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                error "Option inconnue: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Bannière
    echo -e "${PURPLE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                    🚀 LEVIWIFITE 🚀                        ║
║              Script d'Installation Automatique              ║
║                    Pentest WiFi Avancé                     ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    # Vérification des permissions root
    if [ "$EUID" -ne 0 ]; then
        error "Ce script doit être exécuté en tant que root (sudo)"
        exit 1
    fi
    
    # Détection de la distribution
    detect_distro
    
    # Mise à jour du système
    if [ "$SKIP_UPDATE" = false ]; then
        update_system
    else
        info "Mise à jour du système ignorée"
    fi
    
    # Installation des dépendances système
    if [ "$SKIP_DEPS" = false ]; then
        install_system_deps
    else
        info "Installation des dépendances ignorée"
    fi
    
    # Installation d'aircrack-ng
    install_aircrack
    
    # Installation des outils supplémentaires
    if [ "$SKIP_TOOLS" = false ]; then
        install_additional_tools
    else
        info "Installation des outils ignorée"
    fi
    
    # Installation des dépendances Python
    install_python_deps
    
    # Installation des gems Ruby
    install_ruby_deps
    
    # Configuration des permissions
    setup_permissions
    
    # Configuration de l'environnement
    setup_environment
    
    # Test de l'installation
    if [ "$SKIP_TEST" = false ]; then
        if test_installation; then
            log "🎉 Installation terminée avec succès!"
            info "Vous pouvez maintenant utiliser: sudo ./leviwifite.sh --auto"
            info "Ou simplement: leviwifite --auto (après redémarrage du shell)"
        else
            error "❌ Installation échouée"
            exit 1
        fi
    else
        info "Test de l'installation ignoré"
        log "Installation terminée"
    fi
}

# Exécution du script principal
main "$@"
