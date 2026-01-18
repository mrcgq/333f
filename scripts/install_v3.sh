
#!/bin/bash

set -e

BASE_URL="https://github.com/mrcgq/3v/releases/download/v3"
INSTALL_PATH="/usr/local/bin/v3_server"
XDP_PATH="/usr/local/etc/v3_xdp.o"
SERVICE_NAME="v3-server"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

declare -A VERSION_FILES=(
    ["v5"]="v3_server_max"
    ["v6"]="v3_server_lite"
    ["v7"]="v3_server_wss"
    ["v8"]="v3_server_turbo"
    ["v9"]="v3_server_turbo_portable"
)

declare -A VERSION_NAMES=(
    ["v5"]="Enterprise (T0 Max - AVX2/io_uring)"
    ["v6"]="Portable (Tactical - Static Musl)"
    ["v7"]="Rescue (Survival - WSS/TLS)"
    ["v8"]="Turbo (Brutal - Performance)"
    ["v9"]="Turbo-Portable (Brutal - Static)"
)

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

print_banner() {
    echo -e "${BLUE}╔═════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          v3 Server Universal Installer          ║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════════╝${NC}"
}

print_success() {
    echo -e "${GREEN}✅ Success! v3 Server is running.${NC}"
    echo "---------------------------------------------------"
    echo "Status: systemctl status $SERVICE_NAME"
    echo "Logs:   journalctl -u $SERVICE_NAME -f"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use sudo."
        exit 1
    fi
}

cleanup_old() {
    if systemctl is-active --quiet $SERVICE_NAME; then
        log_info "Stopping existing v3 service..."
        systemctl stop $SERVICE_NAME
    fi
    
    local IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
    if [[ -n "$IFACE" ]]; then
        ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
        ip link set dev "$IFACE" xdp off 2>/dev/null || true
    fi
    
    rm -f $INSTALL_PATH $XDP_PATH
}

attach_xdp() {
    local IFACE="$1"
    local XDP_OBJ="$2"
    
    log_info "Attempting to attach XDP program to $IFACE..."

    if ip link set dev "$IFACE" xdp obj "$XDP_OBJ" sec xdp 2>/dev/null; then
        log_info "✅ Native XDP attached successfully (Hardware/Driver Offload)."
        return 0
    fi
    
    log_warn "Native XDP failed (Driver not supported?). Falling back to Generic Mode..."
    if ip link set dev "$IFACE" xdpgeneric obj "$XDP_OBJ" sec xdp 2>/dev/null; then
        log_info "✅ Generic XDP attached successfully (Software Mode)."
        return 0
    fi
    
    log_warn "❌ Failed to attach XDP. Server will run without kernel acceleration."
    return 1
}

run_probe() {
    log_info "Running capability probe..."
    
    if command -v curl &>/dev/null; then
        local probe_result
        probe_result=$(curl -sSL --connect-timeout 3 "$BASE_URL/v3_detect.sh" | bash -s -- --json 2>/dev/null || true)
        
        if [[ -n "$probe_result" ]]; then
            PROBED_VERSION=$(echo "$probe_result" | grep -o '"recommended": "[^"]*"' | cut -d'"' -f4)
            local PROBE_IO_URING=$(echo "$probe_result" | grep -o '"io_uring": "[^"]*"' | cut -d'"' -f4)
            local PROBE_AVX2=$(echo "$probe_result" | grep -o '"avx2": "[^"]*"' | cut -d'"' -f4)
            
            if [[ -n "$PROBED_VERSION" ]]; then
                log_info "Probe results:"
                log_info "  io_uring: ${PROBE_IO_URING:-Unknown}"
                log_info "  AVX2:     ${PROBE_AVX2:-Unknown}"
                log_info "  Recommended: $PROBED_VERSION"
                return 0
            fi
        fi
    fi
    
    log_warn "Probe failed or network unreachable, falling back to local inference"
    return 1
}

get_local_inference() {
    local ARCH=$(uname -m)
    local KERNEL=$(uname -r | cut -d. -f1)
    local HAS_AVX2=$(grep -q avx2 /proc/cpuinfo && echo "yes" || echo "no")
    
    if [[ "$ARCH" == "x86_64" ]] && [[ "$KERNEL" -ge 5 ]] && [[ "$HAS_AVX2" == "yes" ]]; then
        echo "v5"
    else
        echo "v6"
    fi
}

interactive_select() {
    echo ""
    echo "Please select v3 version to install:"
    echo ""
    echo "  1) v5 - Enterprise     [Dynamic] Ultimate Performance (io_uring + AVX2 + XDP)"
    echo "  2) v6 - Portable       [Static]  Extreme Compatibility (Musl libc)"
    echo "  3) v7 - Rescue         [Dynamic] Survival Mode (WebSocket + TLS)"
    echo "  4) v8 - Turbo          [Dynamic] Brutal Speed (Minimal XDP)"
    echo "  5) v9 - Turbo-Portable [Static]  Brutal Speed Static"
    echo "  0) Auto-detect recommended version"
    echo ""
    read -p "Enter option [0-5]: " choice
    
    case "$choice" in
        1) TARGET_VERSION="v5" ;;
        2) TARGET_VERSION="v6" ;;
        3) TARGET_VERSION="v7" ;;
        4) TARGET_VERSION="v8" ;;
        5) TARGET_VERSION="v9" ;;
        0|"") TARGET_VERSION=$(run_probe && echo "$PROBED_VERSION" || get_local_inference) ;;
        *) log_error "Invalid option"; exit 1 ;;
    esac
}

configure_service() {
    local version="$1"
    
    if [[ "$version" == "v5" ]] || [[ "$version" == "v8" ]]; then
        log_info "Downloading v3_xdp.o for kernel acceleration..."
        if curl -L -o "$XDP_PATH" "$BASE_URL/v3_xdp.o"; then
            chmod 644 "$XDP_PATH"
            local DEFAULT_IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
            if [[ -n "$DEFAULT_IFACE" ]]; then
                attach_xdp "$DEFAULT_IFACE" "$XDP_PATH" || true
            fi
        fi
    fi

    log_info "Creating systemd service..."
    local EXTRA_ARGS="--port=51820 --fec --pacing=100"
    if [[ "$version" == "v7" ]]; then
        EXTRA_ARGS="--port=443 --wss --cert=/etc/v3/cert.pem --key=/etc/v3/key.pem"
        mkdir -p /etc/v3
    fi

    cat > /etc/systemd/system/$SERVICE_NAME.service <<EOF
[Unit]
Description=v3 Server ($version - ${VERSION_NAMES[$version]})
After=network.target

[Service]
ExecStart=$INSTALL_PATH $EXTRA_ARGS
Restart=always
LimitNOFILE=1000000
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_RESOURCE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log /run

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    systemctl start $SERVICE_NAME
}

download_and_install() {
    local version="$1"
    local fname="${VERSION_FILES[$version]}"
    
    if [[ -z "$fname" ]]; then
        log_error "Unknown version code: $version"
        return 1
    fi
    
    log_info "Downloading $fname ($version)..."
    cleanup_old
    
    if ! curl -L -o "$INSTALL_PATH" "$BASE_URL/$fname"; then
        log_error "Download failed for $fname"
        return 1
    fi
    chmod +x "$INSTALL_PATH"
    
    configure_service "$version"
}

verify_installation() {
    local version="$1"
    log_info "Verifying installation..."
    
    set +e
    timeout 2 "$INSTALL_PATH" --help >/dev/null 2>&1
    local exit_code=$?
    set -e
    
    if [[ $exit_code -eq 132 ]]; then
        log_error "✗ Illegal Instruction detected! CPU incompatible with $version."
        return 1
    elif [[ $exit_code -eq 127 ]]; then
        log_error "✗ Shared library missing! System incompatible with $version."
        return 1
    fi
    
    sleep 2
    if ! systemctl is-active --quiet $SERVICE_NAME; then
        log_error "✗ Service failed to start (crashed or exited)."
        journalctl -u $SERVICE_NAME -n 10 --no-pager
        return 1
    fi
    
    log_info "✓ Verification passed."
    return 0
}

main() {
    check_root
    print_banner
    
    TARGET_VERSION=""
    INTERACTIVE=false
    AUTO_CONFIRM=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version) TARGET_VERSION="$2"; shift 2 ;;
            --interactive) INTERACTIVE=true; shift ;;
            --auto) AUTO_CONFIRM=true; shift ;;
            *) INTERACTIVE=true; shift ;; 
        esac
    done
    
    if [[ "$INTERACTIVE" == "true" ]] && [[ -z "$TARGET_VERSION" ]]; then
        interactive_select
    elif [[ -z "$TARGET_VERSION" ]]; then
        if run_probe; then
            TARGET_VERSION="$PROBED_VERSION"
        else
            TARGET_VERSION=$(get_local_inference)
        fi
        log_info "Auto-selected: $TARGET_VERSION"
    fi
    
    if [[ "$AUTO_CONFIRM" != "true" ]]; then
        echo "Will install: $TARGET_VERSION - ${VERSION_NAMES[$TARGET_VERSION]}"
        read -p "Continue? [Y/n] " confirm
        if [[ ! "$confirm" =~ ^[Yy]?$ ]]; then echo "Aborted."; exit 0; fi
    fi
    
    download_and_install "$TARGET_VERSION"
    
    if ! verify_installation "$TARGET_VERSION"; then
        log_warn "Primary installation failed verification."
        
        if [[ "$TARGET_VERSION" != "v6" ]]; then
            log_info ">>> Initiating AUTOMATIC FALLBACK to v6 (Portable)..."
            
            download_and_install "v6"
            
            if verify_installation "v6"; then
                log_info "Fallback successful! v6 Portable is running."
                print_success
                exit 0
            else
                log_error "Fallback failed. System may be incompatible."
                exit 1
            fi
        else
            log_error "Portable version failed. Check logs."
            exit 1
        fi
    fi
    
    print_success
}

main "$@"		  
		  
		  
		  
		  
		  
