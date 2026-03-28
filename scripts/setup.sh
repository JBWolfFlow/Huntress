#!/usr/bin/env bash
# =============================================================================
# Huntress — Security Tool Setup Script
# Installs all required security tools for the Huntress bug bounty platform.
#
# Usage:
#   ./scripts/setup.sh           # Install all tools
#   ./scripts/setup.sh --check   # Only check what is installed
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colors & helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info()    { printf "${BLUE}[*]${NC} %s\n" "$*"; }
success() { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn()    { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
error()   { printf "${RED}[-]${NC} %s\n" "$*"; }
header()  { printf "\n${BOLD}${CYAN}=== %s ===${NC}\n\n" "$*"; }

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
CHECK_ONLY=false
OS_TYPE="unknown"
INSTALL_RESULTS=()   # ("tool:status" pairs for summary)

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --check) CHECK_ONLY=true ;;
        -h|--help)
            echo "Usage: $0 [--check]"
            echo "  --check   Only check installed tools, do not install anything"
            exit 0
            ;;
        *)
            error "Unknown argument: $arg"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------
detect_os() {
    header "Detecting Operating System"

    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS_TYPE="macos"
        success "Detected macOS"
    elif [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        case "$ID" in
            kali)
                OS_TYPE="kali"
                success "Detected Kali Linux ($VERSION_ID)"
                ;;
            ubuntu)
                OS_TYPE="ubuntu"
                success "Detected Ubuntu ($VERSION_ID)"
                ;;
            debian)
                OS_TYPE="debian"
                success "Detected Debian ($VERSION_ID)"
                ;;
            *)
                OS_TYPE="other-linux"
                warn "Detected Linux ($ID) — some apt-based installs may not work"
                ;;
        esac
    else
        OS_TYPE="unknown"
        warn "Could not detect OS. Some installers will be skipped."
    fi
}

# ---------------------------------------------------------------------------
# Utility: check if a command exists
# ---------------------------------------------------------------------------
cmd_exists() {
    command -v "$1" &>/dev/null
}

# ---------------------------------------------------------------------------
# Record result for the summary table
# ---------------------------------------------------------------------------
record() {
    local tool="$1" status="$2"
    INSTALL_RESULTS+=("${tool}:${status}")
}

# ---------------------------------------------------------------------------
# Go check
# ---------------------------------------------------------------------------
check_go() {
    header "Checking Go Installation"

    if cmd_exists go; then
        local go_ver
        go_ver=$(go version | awk '{print $3}')
        success "Go is installed: $go_ver"
        return 0
    else
        error "Go is NOT installed. Go tools cannot be installed without it."
        warn "Install Go from https://go.dev/dl/ and ensure it is in your PATH."
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Ensure GOPATH/bin is on PATH
# ---------------------------------------------------------------------------
ensure_gopath() {
    local gobin
    gobin="$(go env GOPATH)/bin"
    if [[ ":$PATH:" != *":${gobin}:"* ]]; then
        export PATH="${gobin}:${PATH}"
        warn "Added $gobin to PATH for this session."
    fi
}

# ---------------------------------------------------------------------------
# Install / check a single Go tool
# ---------------------------------------------------------------------------
install_go_tool() {
    local name="$1" pkg="$2"

    if cmd_exists "$name"; then
        success "$name is already installed"
        record "$name" "installed"
        return
    fi

    if $CHECK_ONLY; then
        warn "$name is NOT installed"
        record "$name" "missing"
        return
    fi

    info "Installing $name ..."
    if go install -v "$pkg" 2>/dev/null; then
        # Re-check after install
        if cmd_exists "$name"; then
            success "$name installed successfully"
            record "$name" "installed"
        else
            error "$name binary not found after install — check your GOPATH/bin"
            record "$name" "failed"
        fi
    else
        error "Failed to install $name"
        record "$name" "failed"
    fi
}

# ---------------------------------------------------------------------------
# Install / check a single pip tool
# ---------------------------------------------------------------------------
install_pip_tool() {
    local name="$1" pkg="$2"

    if cmd_exists "$name"; then
        success "$name is already installed"
        record "$name" "installed"
        return
    fi

    if $CHECK_ONLY; then
        warn "$name is NOT installed"
        record "$name" "missing"
        return
    fi

    info "Installing $name via pip ..."
    if pip3 install --user "$pkg" 2>/dev/null; then
        if cmd_exists "$name"; then
            success "$name installed successfully"
            record "$name" "installed"
        else
            warn "$name installed but binary not on PATH — check ~/.local/bin"
            record "$name" "check-path"
        fi
    else
        error "Failed to install $name"
        record "$name" "failed"
    fi
}

# ---------------------------------------------------------------------------
# Install / check a single apt tool
# ---------------------------------------------------------------------------
install_apt_tool() {
    local name="$1" pkg="$2"

    if cmd_exists "$name"; then
        success "$name is already installed"
        record "$name" "installed"
        return
    fi

    if $CHECK_ONLY; then
        warn "$name is NOT installed"
        record "$name" "missing"
        return
    fi

    case "$OS_TYPE" in
        kali|ubuntu|debian)
            info "Installing $name via apt ..."
            if sudo apt-get install -y "$pkg" 2>/dev/null; then
                if cmd_exists "$name"; then
                    success "$name installed successfully"
                    record "$name" "installed"
                else
                    warn "$name package installed but binary not found"
                    record "$name" "check-path"
                fi
            else
                error "Failed to install $name"
                record "$name" "failed"
            fi
            ;;
        macos)
            info "Installing $name via brew ..."
            if brew install "$pkg" 2>/dev/null; then
                success "$name installed successfully"
                record "$name" "installed"
            else
                error "Failed to install $name via brew"
                record "$name" "failed"
            fi
            ;;
        *)
            warn "Skipping $name — no supported package manager for $OS_TYPE"
            record "$name" "skipped"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Install other tools (dalfox, feroxbuster, waybackurls)
# ---------------------------------------------------------------------------
install_other_tool() {
    local name="$1"

    if cmd_exists "$name"; then
        success "$name is already installed"
        record "$name" "installed"
        return
    fi

    if $CHECK_ONLY; then
        warn "$name is NOT installed"
        record "$name" "missing"
        return
    fi

    case "$name" in
        dalfox)
            # dalfox is a Go tool
            info "Installing dalfox via go install ..."
            if go install github.com/hahwul/dalfox/v2@latest 2>/dev/null; then
                if cmd_exists dalfox; then
                    success "dalfox installed successfully"
                    record "dalfox" "installed"
                else
                    error "dalfox binary not found after install"
                    record "dalfox" "failed"
                fi
            else
                error "Failed to install dalfox"
                record "dalfox" "failed"
            fi
            ;;
        feroxbuster)
            case "$OS_TYPE" in
                kali|ubuntu|debian)
                    info "Installing feroxbuster via apt ..."
                    if sudo apt-get install -y feroxbuster 2>/dev/null; then
                        success "feroxbuster installed successfully"
                        record "feroxbuster" "installed"
                    else
                        # Fallback: install via cargo or binary
                        warn "apt install failed, trying curl installer ..."
                        if curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | sudo bash 2>/dev/null; then
                            success "feroxbuster installed via script"
                            record "feroxbuster" "installed"
                        else
                            error "Failed to install feroxbuster"
                            record "feroxbuster" "failed"
                        fi
                    fi
                    ;;
                macos)
                    info "Installing feroxbuster via brew ..."
                    if brew install feroxbuster 2>/dev/null; then
                        success "feroxbuster installed successfully"
                        record "feroxbuster" "installed"
                    else
                        error "Failed to install feroxbuster"
                        record "feroxbuster" "failed"
                    fi
                    ;;
                *)
                    warn "Skipping feroxbuster — manual install required for $OS_TYPE"
                    record "feroxbuster" "skipped"
                    ;;
            esac
            ;;
        waybackurls)
            info "Installing waybackurls via go install ..."
            if go install github.com/tomnomnom/waybackurls@latest 2>/dev/null; then
                if cmd_exists waybackurls; then
                    success "waybackurls installed successfully"
                    record "waybackurls" "installed"
                else
                    error "waybackurls binary not found after install"
                    record "waybackurls" "failed"
                fi
            else
                error "Failed to install waybackurls"
                record "waybackurls" "failed"
            fi
            ;;
        *)
            warn "No installer defined for $name"
            record "$name" "skipped"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
print_summary() {
    header "Installation Summary"

    local installed=0 missing=0 failed=0 skipped=0
    local max_name_len=12

    # Find longest tool name for alignment
    for entry in "${INSTALL_RESULTS[@]}"; do
        local name="${entry%%:*}"
        if (( ${#name} > max_name_len )); then
            max_name_len=${#name}
        fi
    done

    printf "${BOLD}%-${max_name_len}s  %-12s${NC}\n" "TOOL" "STATUS"
    printf "%-${max_name_len}s  %-12s\n" "$(printf '%0.s-' $(seq 1 "$max_name_len"))" "------------"

    for entry in "${INSTALL_RESULTS[@]}"; do
        local name="${entry%%:*}"
        local status="${entry#*:}"
        local color

        case "$status" in
            installed)
                color="$GREEN"
                ((installed++))
                ;;
            missing)
                color="$YELLOW"
                ((missing++))
                ;;
            failed)
                color="$RED"
                ((failed++))
                ;;
            check-path)
                color="$YELLOW"
                ((missing++))
                ;;
            skipped)
                color="$CYAN"
                ((skipped++))
                ;;
            *)
                color="$NC"
                ;;
        esac

        printf "%-${max_name_len}s  ${color}%-12s${NC}\n" "$name" "$status"
    done

    echo ""
    printf "${GREEN}Installed: %d${NC}  |  " "$installed"
    printf "${YELLOW}Missing: %d${NC}  |  " "$missing"
    printf "${RED}Failed: %d${NC}  |  " "$failed"
    printf "${CYAN}Skipped: %d${NC}\n" "$skipped"

    local total=${#INSTALL_RESULTS[@]}
    if (( failed > 0 )); then
        echo ""
        error "Some tools failed to install. Check the output above for details."
        return 1
    elif (( missing > 0 )) && ! $CHECK_ONLY; then
        echo ""
        warn "Some tools could not be verified on PATH."
        return 0
    elif $CHECK_ONLY && (( missing > 0 )); then
        echo ""
        warn "Run without --check to install missing tools."
        return 0
    else
        echo ""
        success "All $total tools are installed and available."
        return 0
    fi
}

# ==========================================================================
# Main
# ==========================================================================
main() {
    header "Huntress Security Tool Setup"

    if $CHECK_ONLY; then
        info "Running in CHECK mode — nothing will be installed."
    else
        info "Running in INSTALL mode — missing tools will be installed."
    fi

    # ---- OS Detection ----
    detect_os

    # ---- Go Check ----
    local go_available=true
    if ! check_go; then
        go_available=false
        record "go" "missing"
    else
        record "go" "installed"
        ensure_gopath
    fi

    # ---- Go Security Tools ----
    header "Go Security Tools"

    if $go_available; then
        install_go_tool "nuclei"            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        install_go_tool "subfinder"         "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        install_go_tool "httpx"             "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        install_go_tool "katana"            "github.com/projectdiscovery/katana/cmd/katana@latest"
        install_go_tool "naabu"             "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        install_go_tool "dnsx"              "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        install_go_tool "interactsh-client" "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        install_go_tool "ffuf"              "github.com/ffuf/ffuf/v2@latest"
        install_go_tool "gau"               "github.com/lc/gau/v2/cmd/gau@latest"
        install_go_tool "gospider"          "github.com/jaeles-project/gospider@latest"
    else
        for tool in nuclei subfinder httpx katana naabu dnsx interactsh-client ffuf gau gospider; do
            record "$tool" "skipped"
        done
        warn "Skipping all Go tools — Go is not installed."
    fi

    # ---- Python Tools ----
    header "Python Security Tools"

    install_pip_tool "sqlmap"  "sqlmap"
    install_pip_tool "arjun"   "arjun"

    # ---- Apt / System Tools ----
    header "System Package Tools"

    install_apt_tool "nmap"    "nmap"
    install_apt_tool "wafw00f" "wafw00f"
    install_apt_tool "whatweb" "whatweb"

    # ---- Other Tools ----
    header "Additional Tools"

    install_other_tool "dalfox"
    install_other_tool "feroxbuster"
    install_other_tool "waybackurls"

    # ---- Summary ----
    print_summary
}

main "$@"
