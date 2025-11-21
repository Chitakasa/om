#!/usr/bin/env bash
# OM - Program Manager Installation Script
# Universal installer for all Linux distributions

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
INSTALL_DIR=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIN_GCC_VERSION=10
MIN_CLANG_VERSION=12

# Detect OS and package manager
detect_system() {
    # Detect OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_NAME=$NAME
    else
        OS=$(uname -s)
        OS_NAME=$OS
    fi
    
    # Detect package manager
    if command -v pacman >/dev/null 2>&1; then
        PKG_MGR="pacman"
    elif command -v apt >/dev/null 2>&1; then
        PKG_MGR="apt"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MGR="yum"
    elif command -v zypper >/dev/null 2>&1; then
        PKG_MGR="zypper"
    elif command -v apk >/dev/null 2>&1; then
        PKG_MGR="apk"
    elif command -v xbps-install >/dev/null 2>&1; then
        PKG_MGR="xbps"
    else
        PKG_MGR="unknown"
    fi
    
    echo -e "${BLUE}System:${NC} $OS_NAME"
    echo -e "${BLUE}Package Manager:${NC} $PKG_MGR"
}

# Get dependency package names for current distro
get_dependency_packages() {
    case "$PKG_MGR" in
        pacman)
            echo "gcc make nlohmann-json cli11"
            ;;
        apt)
            echo "g++ make nlohmann-json3-dev libcli11-dev"
            ;;
        dnf|yum)
            echo "gcc-c++ make json-devel CLI11-devel"
            ;;
        zypper)
            echo "gcc-c++ make nlohmann_json-devel cli11-devel"
            ;;
        apk)
            echo "g++ make nlohmann-json cli11"
            ;;
        xbps)
            echo "gcc make nlohmann-json cli11"
            ;;
        *)
            echo "g++ make nlohmann-json cli11"
            ;;
    esac
}

# Get install command for current package manager
get_install_command() {
    local packages=$(get_dependency_packages)
    
    case "$PKG_MGR" in
        pacman)
            echo "sudo pacman -S --needed $packages"
            ;;
        apt)
            echo "sudo apt update && sudo apt install -y $packages"
            ;;
        dnf)
            echo "sudo dnf install -y $packages"
            ;;
        yum)
            echo "sudo yum install -y $packages"
            ;;
        zypper)
            echo "sudo zypper install -y $packages"
            ;;
        apk)
            echo "sudo apk add $packages"
            ;;
        xbps)
            echo "sudo xbps-install -S $packages"
            ;;
        *)
            echo "# Install: $packages"
            ;;
    esac
}

# Check compiler version
check_compiler_version() {
    local compiler=$1
    local version
    
    if [ "$compiler" = "g++" ]; then
        version=$(g++ -dumpversion | cut -d. -f1)
        if [ "$version" -ge $MIN_GCC_VERSION ]; then
            return 0
        fi
    elif [ "$compiler" = "clang++" ]; then
        version=$(clang++ --version | grep -oP 'version \K[0-9]+' | head -1)
        if [ "$version" -ge $MIN_CLANG_VERSION ]; then
            return 0
        fi
    fi
    
    return 1
}

# Header
show_header() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║                                                       ║"
    echo "║     ██████╗ ███╗   ███╗                              ║"
    echo "║    ██╔═══██╗████╗ ████║                              ║"
    echo "║    ██║   ██║██╔████╔██║                              ║"
    echo "║    ██║   ██║██║╚██╔╝██║                              ║"
    echo "║    ╚██████╔╝██║ ╚═╝ ██║                              ║"
    echo "║     ╚═════╝ ╚═╝     ╚═╝                              ║"
    echo "║                                                       ║"
    echo "║    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║"
    echo "║                                                       ║"
    echo "║    PROGRAM MANAGER - INSTALLER                       ║"
    echo "║                                                       ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}\n"
}

# Ask installation type
ask_install_location() {
    echo -e "${BOLD}${CYAN}Choose installation type:${NC}\n"
    echo -e "  ${GREEN}1)${NC} System-wide installation ${YELLOW}(requires sudo)${NC}"
    echo -e "     Install to: ${CYAN}/usr/local${NC}"
    echo -e "     Available to: ${CYAN}All users${NC}"
    echo ""
    echo -e "  ${GREEN}2)${NC} User installation ${YELLOW}(no sudo required)${NC}"
    echo -e "     Install to: ${CYAN}\$HOME/.local${NC}"
    echo -e "     Available to: ${CYAN}Current user only${NC}"
    echo ""
    echo -e "  ${GREEN}3)${NC} Custom location"
    echo ""
    
    while true; do
        read -p "$(echo -e ${BOLD}Enter choice [1-3]: ${NC})" choice
        case $choice in
            1)
                INSTALL_DIR="/usr/local"
                echo -e "${GREEN}✓${NC} Selected: System-wide installation"
                break
                ;;
            2)
                INSTALL_DIR="$HOME/.local"
                echo -e "${GREEN}✓${NC} Selected: User installation"
                break
                ;;
            3)
                echo -e "${CYAN}Enter custom installation directory:${NC}"
                read -p "$(echo -e ${BOLD}Directory: ${NC})" custom_dir
                INSTALL_DIR="${custom_dir/#\~/$HOME}"
                echo -e "${GREEN}✓${NC} Selected: Custom installation to $INSTALL_DIR"
                break
                ;;
            *)
                echo -e "${RED}Invalid choice. Please enter 1, 2, or 3.${NC}"
                ;;
        esac
    done
    echo ""
}

# Confirm installation
confirm_installation() {
    echo -e "${YELLOW}Installation Summary:${NC}"
    echo -e "  Install location: ${CYAN}$INSTALL_DIR${NC}"
    echo -e "  Binary:          ${CYAN}$INSTALL_DIR/bin/om${NC}"
    echo -e "  Man page:        ${CYAN}$INSTALL_DIR/share/man/man1/om.1.gz${NC}"
    
    if [[ "$INSTALL_DIR" == /usr* ]] && [[ $EUID -ne 0 ]]; then
        echo -e "  Permissions:     ${YELLOW}Requires sudo${NC}"
    else
        echo -e "  Permissions:     ${GREEN}No sudo required${NC}"
    fi
    
    echo ""
    read -p "$(echo -e ${BOLD}Continue with installation? [Y/n]: ${NC})" confirm
    
    case $confirm in
        [Nn]*)
            echo -e "${YELLOW}Installation cancelled.${NC}"
            exit 0
            ;;
        *)
            echo -e "${GREEN}Proceeding with installation...${NC}\n"
            ;;
    esac
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check dependencies
install_dependencies() {
    echo -e "\n${YELLOW}Checking dependencies...${NC}"
    
    local missing_deps=()
    local has_compiler=false
    
    # Check C++ compiler
    if command_exists g++; then
        if check_compiler_version g++; then
            echo -e "${GREEN}✓${NC} g++ found ($(g++ -dumpversion))"
            has_compiler=true
        else
            echo -e "${YELLOW}⚠${NC} g++ version too old (need GCC $MIN_GCC_VERSION+)"
            missing_deps+=("modern g++")
        fi
    elif command_exists clang++; then
        if check_compiler_version clang++; then
            echo -e "${GREEN}✓${NC} clang++ found"
            has_compiler=true
        else
            echo -e "${YELLOW}⚠${NC} clang++ version too old (need Clang $MIN_CLANG_VERSION+)"
            missing_deps+=("modern clang++")
        fi
    else
        missing_deps+=("c++ compiler")
    fi
    
    # Check make
    if ! command_exists make; then
        missing_deps+=("make")
    else
        echo -e "${GREEN}✓${NC} make found"
    fi
    
    # Check for nlohmann-json
    if ! echo '#include <nlohmann/json.hpp>' | g++ -std=c++20 -x c++ -c - -o /dev/null 2>/dev/null; then
        missing_deps+=("nlohmann-json")
    else
        echo -e "${GREEN}✓${NC} nlohmann/json found"
    fi
    
    # Check for CLI11
    if ! echo '#include <CLI/CLI.hpp>' | g++ -std=c++20 -x c++ -c - -o /dev/null 2>/dev/null; then
        missing_deps+=("cli11")
    else
        echo -e "${GREEN}✓${NC} CLI11 found"
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "\n${RED}Missing dependencies:${NC} ${missing_deps[*]}"
        
        local install_cmd=$(get_install_command)
        
        if [ "$PKG_MGR" != "unknown" ]; then
            echo -e "\n${YELLOW}Install command for your system:${NC}"
            echo -e "${CYAN}$install_cmd${NC}"
            echo ""
            read -p "$(echo -e ${BOLD}Install dependencies now? [y/N]: ${NC})" install_deps
            
            case $install_deps in
                [Yy]*)
                    eval $install_cmd
                    echo -e "${GREEN}✓ Dependencies installed!${NC}"
                    ;;
                *)
                    echo -e "${YELLOW}Please install dependencies manually and run this script again.${NC}"
                    exit 1
                    ;;
            esac
        else
            echo -e "\n${YELLOW}Manual installation required:${NC}"
            echo -e "Please install the following and try again:"
            echo -e "  - C++20 compiler (GCC $MIN_GCC_VERSION+ or Clang $MIN_CLANG_VERSION+)"
            echo -e "  - make"
            echo -e "  - nlohmann-json (headers)"
            echo -e "  - CLI11 (headers)"
            exit 1
        fi
    else
        echo -e "${GREEN}All dependencies satisfied!${NC}"
    fi
}

# Build project
build_project() {
    echo -e "\n${YELLOW}Building OM...${NC}"
    
    cd "$SCRIPT_DIR"
    
    # Create necessary directories
    mkdir -p src completions
    
    # Check if source exists
    if [ ! -f src/om.cpp ]; then
        echo -e "${RED}Error: src/om.cpp not found!${NC}"
        echo -e "${YELLOW}Make sure you're running this from the project directory.${NC}"
        exit 1
    fi
    
    if [ -f Makefile ]; then
        make clean >/dev/null 2>&1 || true
        if make; then
            echo -e "${GREEN}✓ Build successful!${NC}"
        else
            echo -e "${RED}✗ Build failed!${NC}"
            exit 1
        fi
    else
        # Manual build
        echo -e "${YELLOW}No Makefile found, building manually...${NC}"
        
        # Determine compiler
        local CXX="g++"
        if ! command_exists g++ && command_exists clang++; then
            CXX="clang++"
        fi
        
        if $CXX -std=c++20 -O2 -Wall -Wextra -o om src/om.cpp; then
            echo -e "${GREEN}✓ Build successful!${NC}"
        else
            echo -e "${RED}✗ Build failed!${NC}"
            echo -e "${YELLOW}Try installing dependencies and run again.${NC}"
            exit 1
        fi
    fi
}

# Install program
install_program() {
    echo -e "\n${YELLOW}Installing OM...${NC}"
    
    local USE_SUDO=""
    if [[ "$INSTALL_DIR" == /usr* ]] && [[ $EUID -ne 0 ]]; then
        USE_SUDO="sudo"
    fi
    
    cd "$SCRIPT_DIR"
    
    if [ -f Makefile ]; then
        if $USE_SUDO make install PREFIX="$INSTALL_DIR"; then
            echo -e "${GREEN}✓ Installation successful!${NC}"
        else
            echo -e "${RED}✗ Installation failed!${NC}"
            exit 1
        fi
    else
        # Manual installation
        $USE_SUDO mkdir -p "$INSTALL_DIR/bin"
        $USE_SUDO install -m 755 om "$INSTALL_DIR/bin/om"
        echo -e "${GREEN}✓${NC} Installed binary"
        
        # Man page
        if [ -f om.1 ]; then
            $USE_SUDO mkdir -p "$INSTALL_DIR/share/man/man1"
            $USE_SUDO install -m 644 om.1 "$INSTALL_DIR/share/man/man1/om.1"
            $USE_SUDO gzip -f "$INSTALL_DIR/share/man/man1/om.1" 2>/dev/null || true
            echo -e "${GREEN}✓${NC} Installed man page"
        fi
        
        # Completions
        if [ -d completions ]; then
            for comp_file in completions/*; do
                if [ -f "$comp_file" ]; then
                    case "$comp_file" in
                        *.bash)
                            $USE_SUDO mkdir -p "$INSTALL_DIR/share/bash-completion/completions"
                            $USE_SUDO install -m 644 "$comp_file" "$INSTALL_DIR/share/bash-completion/completions/om"
                            ;;
                        *.zsh)
                            $USE_SUDO mkdir -p "$INSTALL_DIR/share/zsh/site-functions"
                            $USE_SUDO install -m 644 "$comp_file" "$INSTALL_DIR/share/zsh/site-functions/_om"
                            ;;
                        *.fish)
                            $USE_SUDO mkdir -p "$INSTALL_DIR/share/fish/vendor_completions.d"
                            $USE_SUDO install -m 644 "$comp_file" "$INSTALL_DIR/share/fish/vendor_completions.d/om.fish"
                            ;;
                    esac
                fi
            done
            echo -e "${GREEN}✓${NC} Installed shell completions"
        fi
    fi
}

# Test installation
test_installation() {
    echo -e "\n${YELLOW}Testing installation...${NC}"
    
    export PATH="$INSTALL_DIR/bin:$PATH"
    
    if command_exists om; then
        local version=$(om --version 2>&1 | head -n1)
        echo -e "${GREEN}✓${NC} $version"
        
        # Test man page
        if man -w om >/dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} Man page accessible"
        fi
        
        return 0
    else
        echo -e "${YELLOW}⚠${NC} 'om' not found in PATH"
        return 1
    fi
}

# Success message
show_success() {
    echo -e "\n${GREEN}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║                                                       ║"
    echo "║         INSTALLATION COMPLETE!                        ║"
    echo "║                                                       ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # PATH warning if needed
    if [[ ":$PATH:" != *":$INSTALL_DIR/bin:"* ]]; then
        echo -e "${YELLOW}⚠ Add to PATH:${NC}"
        echo -e "Add to your ${CYAN}~/.bashrc${NC} or ${CYAN}~/.zshrc${NC}:"
        echo -e "${CYAN}export PATH=\"$INSTALL_DIR/bin:\$PATH\"${NC}"
        echo ""
        echo -e "Then: ${CYAN}source ~/.bashrc${NC}"
        echo ""
    fi
    
    echo -e "${CYAN}Quick Start:${NC}"
    echo -e "  ${GREEN}om${NC}"
    echo -e "    Show logo"
    echo ""
    echo -e "  ${GREEN}om add ${YELLOW}<program_name> <path_to_program> <description>${NC}"
    echo -e "    Add a new program"
    echo -e "    Example: ${BLUE}om add browser /usr/bin/firefox \"Web browser\"${NC}"
    echo ""
    echo -e "  ${GREEN}om list${NC}"
    echo -e "    List all stored programs"
    echo ""
    echo -e "  ${GREEN}om ${YELLOW}<program_name>${NC} ${YELLOW}[args...]${NC}"
    echo -e "    Execute stored program"
    echo -e "    Example: ${BLUE}om browser --private-window${NC}"
    echo ""
    echo -e "  ${GREEN}om --help${NC}"
    echo -e "    Show detailed help"
    echo ""
    echo -e "  ${GREEN}man om${NC}"
    echo -e "    Read full manual"
    echo ""
    echo -e "${CYAN}Configuration:${NC}"
    echo -e "  Programs: ${YELLOW}~/.config/om/programs.json${NC}"
    echo ""
}

# Main
main() {
    show_header
    detect_system
    
    if [ -z "$INSTALL_DIR" ]; then
        ask_install_location
        confirm_installation
    fi
    
    install_dependencies
    build_project
    install_program
    test_installation && show_success
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --system) INSTALL_DIR="/usr/local"; shift ;;
        --user) INSTALL_DIR="$HOME/.local"; shift ;;
        --prefix) INSTALL_DIR="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--system|--user|--prefix DIR]"
            exit 0
            ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

main