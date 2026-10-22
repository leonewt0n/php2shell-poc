#!/usr/bin/env bash
# PHP2Shell - Lab Setup Script
# Bootstraps the full test environment with all CMS targets.
#
# Usage:
#   chmod +x setup.sh && ./setup.sh
#
# DISCLAIMER: For authorized security testing only.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
cat << 'EOF'
 ██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗
 ██╔══██╗██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║
 ██████╔╝███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║
 ██╔═══╝ ██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║
 ██║     ██║  ██║██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
 ╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                        Lab Setup Script
EOF
}

check_deps() {
    echo -e "${CYAN}[*] Checking dependencies...${NC}"
    for cmd in docker docker-compose python3; do
        if command -v "$cmd" &>/dev/null; then
            echo -e "  ${GREEN}[+]${NC} $cmd: $(command -v "$cmd")"
        else
            echo -e "  ${RED}[-]${NC} $cmd: NOT FOUND"
            echo -e "  ${YELLOW}[!]${NC} Install $cmd before continuing."
            exit 1
        fi
    done
    echo
}

start_lab() {
    echo -e "${CYAN}[*] Starting lab environment...${NC}"
    mkdir -p proof
    docker-compose up -d
    echo

    echo -e "${CYAN}[*] Waiting for services to become healthy...${NC}"
    for i in $(seq 1 30); do
        wp_status=$(curl -so /dev/null -w "%{http_code}" http://127.0.0.1:9080/ 2>/dev/null || echo "000")
        if [ "$wp_status" = "200" ] || [ "$wp_status" = "302" ]; then
            echo -e "  ${GREEN}[+]${NC} WordPress is up (HTTP $wp_status)"
            break
        fi
        sleep 2
    done

    # Surum sapmasi kontrolu: resmi imaj ayni etikette yeniden insa
    # edildiyse PHP 8.4.26 yerine yamali surum gelmis olabilir.
    wp_php=$(docker-compose exec -T wordpress php -r 'echo PHP_VERSION;' 2>/dev/null || echo "bilinmiyor")
    if [ "$wp_php" != "8.4.26" ]; then
        echo -e "  ${YELLOW}[!] UYARI:${NC} WordPress PHP surumu '$wp_php' (beklenen 8.4.26)."
        echo -e "      Imaj sapmasi olabilir; exploit 'patched' davranisi gosterebilir."
    else
        echo -e "  ${GREEN}[+]${NC} WordPress PHP: $wp_php (savunmasiz, dogru)"
    fi

    echo
    echo -e "${GREEN}[+] Lab is ready!${NC}"
    echo -e "    WordPress : ${CYAN}http://127.0.0.1:9080${NC}"
    echo -e "    Drupal    : ${CYAN}http://127.0.0.1:9081${NC}"
    echo -e "    Joomla    : ${CYAN}http://127.0.0.1:9082${NC}"
    echo
}

build_836() {
    echo -e "${CYAN}[*] Building PHP 8.3.6 lab...${NC}"
    docker build -t php836-lab -f Dockerfile.836 ..
    echo -e "${GREEN}[+]${NC} PHP 8.3.6 lab built. Run: docker run --rm -it php836-lab"
    echo
}

usage() {
    echo "Usage: $0 [all|lab|836|stop|status]"
    echo "  all    - Start CMS lab + build 8.3.6 lab"
    echo "  lab    - Start CMS lab only (WordPress + Drupal + Joomla)"
    echo "  836    - Build PHP 8.3.6 isolated lab"
    echo "  stop   - Stop all containers"
    echo "  status - Show running containers"
}

main() {
    banner
    check_deps

    case "${1:-all}" in
        all)
            start_lab
            build_836
            ;;
        lab)
            start_lab
            ;;
        836)
            build_836
            ;;
        stop)
            echo -e "${CYAN}[*] Stopping all containers...${NC}"
            docker-compose down -v
            echo -e "${GREEN}[+]${NC} Done."
            ;;
        status)
            docker-compose ps
            ;;
        *)
            usage
            exit 1
            ;;
    esac

    echo -e "${YELLOW}[!] DISCLAIMER: For authorized security testing only.${NC}"
}

main "$@"
