#!/bin/bash

# LEVIWIFITE - Script Principal Bash
# Coordination des composants Python, Ruby et HTML

set -e

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.json"
LOG_FILE="$SCRIPT_DIR/leviwifite.log"
RESULTS_DIR="$SCRIPT_DIR/results"
TEMP_DIR="$SCRIPT_DIR/temp"

# Fonctions utilitaires
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERREUR]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[ATTENTION]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

# Vérification des prérequis
check_prerequisites() {
    log "Vérification des prérequis..."
    
    # Vérifier les outils essentiels
    local tools=("airmon-ng" "airodump-ng" "aireplay-ng" "aircrack-ng" "python3" "ruby")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        error "Outils manquants: ${missing_tools[*]}"
        error "Installez aircrack-ng suite et les autres dépendances"
        exit 1
    fi
    
    # Vérifier les permissions root
    if [ "$EUID" -ne 0 ]; then
        error "Ce script doit être exécuté en tant que root (sudo)"
        exit 1
    fi
    
    log "Tous les prérequis sont satisfaits"
}

# Initialisation de l'environnement
init_environment() {
    log "Initialisation de l'environnement..."
    
    # Créer les répertoires nécessaires
    mkdir -p "$RESULTS_DIR" "$TEMP_DIR"
    
    # Nettoyer les fichiers temporaires
    rm -rf "$TEMP_DIR"/*
    
    # Vérifier l'interface WiFi
    if [ -z "$WIFI_INTERFACE" ]; then
        WIFI_INTERFACE=$(iw dev | grep Interface | head -1 | awk '{print $2}')
        if [ -z "$WIFI_INTERFACE" ]; then
            error "Aucune interface WiFi trouvée"
            exit 1
        fi
        info "Interface WiFi détectée: $WIFI_INTERFACE"
    fi
    
    log "Environnement initialisé"
}

# Scan des réseaux WiFi
scan_networks() {
    log "Début du scan des réseaux WiFi..."
    
    # Activer le mode monitor
    info "Activation du mode monitor sur $WIFI_INTERFACE..."
    airmon-ng start "$WIFI_INTERFACE" > /dev/null 2>&1
    
    # Attendre que l'interface soit prête
    sleep 2
    
    # Scanner les réseaux
    local scan_file="$TEMP_DIR/scan_output.csv"
    info "Scan en cours (30 secondes)..."
    
    timeout 30 airodump-ng "$WIFI_INTERFACE" --output-format csv --write "$TEMP_DIR/scan" > /dev/null 2>&1 || true
    
    # Parser les résultats
    if [ -f "$TEMP_DIR/scan-01.csv" ]; then
        python3 "$SCRIPT_DIR/parse_scan.py" "$TEMP_DIR/scan-01.csv" > "$TEMP_DIR/networks.json"
        local network_count=$(jq length "$TEMP_DIR/networks.json" 2>/dev/null || echo "0")
        log "Scan terminé: $network_count réseaux détectés"
    else
        error "Échec du scan des réseaux"
        return 1
    fi
}

# Affichage des réseaux
display_networks() {
    if [ ! -f "$TEMP_DIR/networks.json" ]; then
        error "Aucun résultat de scan disponible"
        return 1
    fi
    
    echo -e "\n${CYAN}📡 RÉSEAUX WIFI DÉTECTÉS:${NC}"
    echo "══════════════════════════════════════════════════════════════"
    
    python3 "$SCRIPT_DIR/display_networks.py" "$TEMP_DIR/networks.json"
}

# Sélection de la cible
select_target() {
    local network_count=$(jq length "$TEMP_DIR/networks.json" 2>/dev/null || echo "0")
    
    if [ "$network_count" -eq "0" ]; then
        error "Aucun réseau disponible pour l'attaque"
        return 1
    fi
    
    echo -e "\n${YELLOW}🎯 SÉLECTION DE LA CIBLE:${NC}"
    
    if [ "$AUTO_MODE" = "true" ]; then
        TARGET_INDEX=0
        info "Mode automatique: première cible sélectionnée"
    else
        read -p "Choisissez une cible (1-$network_count): " TARGET_INDEX
        TARGET_INDEX=$((TARGET_INDEX - 1))
        
        if [ "$TARGET_INDEX" -lt 0 ] || [ "$TARGET_INDEX" -ge "$network_count" ]; then
            error "Index de cible invalide"
            return 1
        fi
    fi
    
    # Extraire les informations de la cible
    TARGET_BSSID=$(jq -r ".[$TARGET_INDEX].bssid" "$TEMP_DIR/networks.json")
    TARGET_ESSID=$(jq -r ".[$TARGET_INDEX].essid" "$TEMP_DIR/networks.json")
    TARGET_CHANNEL=$(jq -r ".[$TARGET_INDEX].channel" "$TEMP_DIR/networks.json")
    
    log "Cible sélectionnée: $TARGET_ESSID ($TARGET_BSSID) - Canal $TARGET_CHANNEL"
}

# Exécution de l'attaque
execute_attack() {
    log "Début de l'attaque sur $TARGET_ESSID..."
    
    # Changer sur le canal de la cible
    info "Changement vers le canal $TARGET_CHANNEL..."
    iw dev "$WIFI_INTERFACE" set channel "$TARGET_CHANNEL"
    
    # Lancer l'attaque Python
    info "Lancement de l'attaque Python..."
    python3 "$SCRIPT_DIR/attack_engine.py" \
        --interface "$WIFI_INTERFACE" \
        --target "$TARGET_BSSID" \
        --essid "$TARGET_ESSID" \
        --channel "$TARGET_CHANNEL" \
        --output "$RESULTS_DIR"
    
    if [ $? -eq 0 ]; then
        log "Attaque Python terminée avec succès"
    else
        warning "Attaque Python échouée"
    fi
    
    # Lancer l'attaque Ruby
    info "Lancement de l'attaque Ruby..."
    ruby "$SCRIPT_DIR/ruby_attack.rb" \
        --interface "$WIFI_INTERFACE" \
        --target "$TARGET_BSSID" \
        --essid "$TARGET_ESSID" \
        --output "$RESULTS_DIR"
    
    if [ $? -eq 0 ]; then
        log "Attaque Ruby terminée avec succès"
    else
        warning "Attaque Ruby échouée"
    fi
    
    # Analyser les résultats
    analyze_results
}

# Analyse des résultats
analyze_results() {
    log "Analyse des résultats..."
    
    # Générer le rapport HTML
    info "Génération du rapport HTML..."
    python3 "$SCRIPT_DIR/generate_report.py" \
        --scan "$TEMP_DIR/networks.json" \
        --results "$RESULTS_DIR" \
        --output "$RESULTS_DIR/rapport_leviwifite.html"
    
    # Générer le rapport Ruby
    info "Génération du rapport Ruby..."
    ruby "$SCRIPT_DIR/generate_ruby_report.rb" \
        --scan "$TEMP_DIR/networks.json" \
        --results "$RESULTS_DIR" \
        --output "$RESULTS_DIR/rapport_ruby.html"
    
    # Combiner les rapports
    info "Combinaison des rapports..."
    python3 "$SCRIPT_DIR/merge_reports.py" \
        --python "$RESULTS_DIR/rapport_leviwifite.html" \
        --ruby "$RESULTS_DIR/rapport_ruby.html" \
        --output "$RESULTS_DIR/rapport_final.html"
    
    log "Rapport final généré: $RESULTS_DIR/rapport_final.html"
}

# Nettoyage
cleanup() {
    log "Nettoyage en cours..."
    
    # Arrêter tous les processus en arrière-plan
    pkill -f "airodump-ng" 2>/dev/null || true
    pkill -f "aireplay-ng" 2>/dev/null || true
    pkill -f "aircrack-ng" 2>/dev/null || true
    
    # Désactiver le mode monitor
    if [ -n "$WIFI_INTERFACE" ]; then
        info "Désactivation du mode monitor..."
        airmon-ng stop "$WIFI_INTERFACE" > /dev/null 2>&1 || true
    fi
    
    # Nettoyer les fichiers temporaires
    rm -rf "$TEMP_DIR"/*
    
    log "Nettoyage terminé"
}

# Gestionnaire de signal
signal_handler() {
    echo -e "\n${YELLOW}[!] Signal d'arrêt reçu. Nettoyage...${NC}"
    cleanup
    exit 0
}

# Affichage de l'aide
show_help() {
    echo -e "${CYAN}LEVIWIFITE - Outil de Pentest WiFi Avancé${NC}"
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -i, --interface INTERFACE    Interface WiFi à utiliser"
    echo "  -a, --auto                   Mode automatique"
    echo "  -s, --scan-only              Scan uniquement (pas d'attaque)"
    echo "  -t, --target BSSID           Cible spécifique par BSSID"
    echo "  -h, --help                   Afficher cette aide"
    echo ""
    echo "Exemples:"
    echo "  $0 -i wlan1                  Utiliser l'interface wlan1"
    echo "  $0 --auto                    Mode automatique"
    echo "  $0 --scan-only               Scan uniquement"
    echo "  $0 -t AA:BB:CC:DD:EE:FF     Attaquer une cible spécifique"
}

# Fonction principale
main() {
    # Configuration des signaux
    trap signal_handler INT TERM
    
    # Variables par défaut
    WIFI_INTERFACE=""
    AUTO_MODE="false"
    SCAN_ONLY="false"
    TARGET_BSSID=""
    
    # Parsing des arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--interface)
                WIFI_INTERFACE="$2"
                shift 2
                ;;
            -a|--auto)
                AUTO_MODE="true"
                shift
                ;;
            -s|--scan-only)
                SCAN_ONLY="true"
                shift
                ;;
            -t|--target)
                TARGET_BSSID="$2"
                shift 2
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
║              Outil de Pentest WiFi Avancé                  ║
║              Wifite + Airgeddon + Coordination             ║
║                    Python + Bash + Ruby                    ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    # Vérifications et initialisation
    check_prerequisites
    init_environment
    
    # Scan des réseaux
    if ! scan_networks; then
        error "Échec du scan des réseaux"
        cleanup
        exit 1
    fi
    
    # Affichage des résultats
    display_networks
    
    if [ "$SCAN_ONLY" = "true" ]; then
        info "Mode scan uniquement - Arrêt"
        cleanup
        exit 0
    fi
    
    # Sélection de la cible
    if ! select_target; then
        error "Échec de la sélection de la cible"
        cleanup
        exit 1
    fi
    
    # Exécution de l'attaque
    execute_attack
    
    # Nettoyage final
    cleanup
    
    log "LEVIWIFITE terminé avec succès!"
    info "Consultez le rapport final: $RESULTS_DIR/rapport_final.html"
}

# Exécution du script principal
main "$@"
