#!/bin/bash

set -euo pipefail

# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

readonly XUI_CONFIG_FILE="/etc/x-ui/x-ui.json"
readonly XUI_SERVICE="x-ui"
readonly XUI_SSL_DIR="/usr/local/x-ui/ssl"
readonly XUI_ALT_SSL_DIR="/etc/ssl/3x-ui"
readonly XUI_PORT="2053"
readonly XUI_BACKUP_PORT="8443"

readonly INSTALLER_URL="https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh"
readonly INSTALLER_SCRIPT="/tmp/install-3x-ui.sh"

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

is_root() {
    [[ $EUID -eq 0 ]]
}

check_root() {
    if ! is_root; then
        error "This script must be run as root"
        exit 1
    fi
    log "Running as root - OK"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

wait_for() {
    local description="$1"
    local condition_cmd="$2"
    local max_attempts="${3:-30}"
    local wait_seconds="${4:-5}"
    local attempt=1
    
    log "Waiting for $description..."
    
    while [[ $attempt -le $max_attempts ]]; do
        if eval "$condition_cmd"; then
            log "$description - OK (attempt $attempt/$max_attempts)"
            return 0
        fi
        
        log "Attempt $attempt/$max_attempts: Still waiting for $description..."
        sleep "$wait_seconds"
        ((attempt++))
    done
    
    error "Timeout waiting for $description after $max_attempts attempts"
    return 1
}

create_backup() {
    local file="$1"
    local backup_dir="${2:-$(dirname "$file")}"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$backup_dir/$(basename "$file").backup.$timestamp"
    
    if [[ -f "$file" ]]; then
        cp "$file" "$backup_file"
        log "Created backup: $backup_file"
    fi
}

# ============================================================================
# SYSTEM DEPENDENCIES
# ============================================================================

install_dependencies() {
    log "Installing system dependencies..."
    
    apt-get update
    
    local dependencies=(
        curl
        wget
        openssl
        jq
        python3
    )
    
    for dep in "${dependencies[@]}"; do
        if ! command_exists "$dep"; then
            apt-get install -y "$dep"
        fi
    done
    
    log "Dependencies installed"
}

# ============================================================================
# SSL CERTIFICATE MANAGEMENT
# ============================================================================

generate_ssl_certificates() {
    local ssl_dir="$1"
    local common_name="${2:-localhost}"
    
    log "Generating SSL certificates in $ssl_dir..."
    
    mkdir -p "$ssl_dir"
    
    # Generate private key
    if ! openssl genrsa -out "$ssl_dir/private.key" 2048 2>/dev/null; then
        error "Failed to generate private key"
        return 1
    fi
    
    # Generate self-signed certificate
    if ! openssl req -new -x509 -key "$ssl_dir/private.key" \
        -out "$ssl_dir/certificate.crt" \
        -days 3650 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$common_name" 2>/dev/null; then
        error "Failed to generate certificate"
        return 1
    fi
    
    # Create combined certificate
    cat "$ssl_dir/certificate.crt" "$ssl_dir/private.key" > "$ssl_dir/fullchain.pem"
    
    # Set proper permissions
    chmod 600 "$ssl_dir/private.key"
    chmod 644 "$ssl_dir/certificate.crt" "$ssl_dir/fullchain.pem"
    
    log "SSL certificates generated successfully in $ssl_dir"
    display_certificate_info "$ssl_dir/certificate.crt"
}

generate_alternative_ssl() {
    log "Generating alternative SSL certificates..."
    
    mkdir -p "$XUI_ALT_SSL_DIR"
    cd "$XUI_ALT_SSL_DIR" || {
        error "Failed to access $XUI_ALT_SSL_DIR"
        return 1
    }
    
    openssl genrsa -out secret.key 2048
    openssl req -key secret.key -new -out cert.csr
    openssl x509 -signkey secret.key -in cert.csr -req -days 365 -out cert.crt
    
    echo "-----------------------"
    echo "Panel certificate public key path:"
    echo "-----------------------"
    echo "$XUI_ALT_SSL_DIR/cert.crt"
    echo "-----------------------"
    echo "Panel certificate private key path:"
    echo "-----------------------"
    echo "$XUI_ALT_SSL_DIR/secret.key"
}

display_certificate_info() {
    local cert_file="$1"
    
    info "Certificate information:"
    openssl x509 -in "$cert_file" -text -noout | \
        grep -E "Subject:|Issuer:|Not Before|Not After" | \
        sed 's/^/  /'
}

# ============================================================================
# FIREWALL CONFIGURATION
# ============================================================================

setup_firewall() {
    log "Configuring firewall..."
    
    # Install UFW if not present
    if ! command_exists ufw; then
        apt-get install -y ufw
    fi
    
    # Configure firewall rules
    ufw --force disable
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow necessary ports
    ufw allow "$XUI_PORT/tcp" comment "3x-ui Panel"
    ufw allow "$XUI_BACKUP_PORT/tcp" comment "3x-ui Backup Port"
    ufw allow ssh comment "SSH"
    
    ufw --force enable
    
    log "Firewall configured successfully"
    ufw status verbose
}

# ============================================================================
# 3X-UI SERVICE MANAGEMENT
# ============================================================================

install_3x_ui() {
    log "Installing 3x-ui..."
    
    # Download installer
    if ! curl -s -L "$INSTALLER_URL" -o "$INSTALLER_SCRIPT"; then
        error "Failed to download 3x-ui installer"
        return 1
    fi
    
    chmod +x "$INSTALLER_SCRIPT"
    
    # Run installer
    if ! "$INSTALLER_SCRIPT"; then
        error "3x-ui installer failed"
        return 1
    fi
    
    # Wait for service to be registered
    wait_for "3x-ui service registration" \
        "systemctl list-unit-files | grep -q $XUI_SERVICE" \
        10 3
    
    # Start the service
    systemctl start "$XUI_SERVICE"
    
    # Wait for service to be active
    wait_for "3x-ui service to start" \
        "systemctl is-active --quiet $XUI_SERVICE" \
        6 5
    
    log "3x-ui installed and started successfully"
}

manage_service() {
    local action="$1"
    
    case "$action" in
        "start")
            systemctl start "$XUI_SERVICE"
            ;;
        "stop")
            systemctl stop "$XUI_SERVICE"
            ;;
        "restart")
            systemctl restart "$XUI_SERVICE"
            ;;
        "status")
            systemctl status "$XUI_SERVICE"
            return
            ;;
        *)
            error "Unknown service action: $action"
            return 1
            ;;
    esac
    
    sleep 2
}

# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

wait_for_config_file() {
    wait_for "config file creation" \
        "[[ -f $XUI_CONFIG_FILE ]]" \
        30 5
}

update_config_with_python() {
    local config_file="$XUI_CONFIG_FILE"
    local ssl_dir="$XUI_SSL_DIR"
    
    log "Updating configuration using Python..."
    
    python3 - << EOF
import json
import os
import sys

config_file = "$config_file"

try:
    # Read current config
    with open(config_file, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    # Ensure panel_settings exists
    if "panel_settings" not in config:
        config["panel_settings"] = {}
    
    # Update SSL paths
    config["panel_settings"]["cert_file"] = "$ssl_dir/fullchain.pem"
    config["panel_settings"]["key_file"] = "$ssl_dir/private.key"
    
    # Update web settings if they exist
    if "web" in config.get("panel_settings", {}):
        config["panel_settings"]["web"]["cert_file"] = "$ssl_dir/fullchain.pem"
        config["panel_settings"]["web"]["key_file"] = "$ssl_dir/private.key"
    
    # Write updated config
    with open(config_file, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print("Configuration updated successfully")
    
    # Verify update
    with open(config_file, 'r') as f:
        updated = json.load(f)
    
    cert = updated.get("panel_settings", {}).get("cert_file", "")
    key = updated.get("panel_settings", {}).get("key_file", "")
    
    if cert and key:
        print(f"Certificate path: {cert}")
        print(f"Private key path: {key}")
    else:
        print("Error: SSL paths not found in updated config")
        sys.exit(1)
        
except FileNotFoundError:
    print(f"Error: Config file not found at {config_file}")
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"Error: Invalid JSON in config file: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Error updating config: {e}")
    sys.exit(1)
EOF
    
    return $?
}

update_config_with_jq() {
    if ! command_exists jq; then
        warn "jq not available, skipping jq method"
        return 1
    fi
    
    log "Updating configuration using jq..."
    
    if jq '.panel_settings.cert_file = "/usr/local/x-ui/ssl/fullchain.pem" | 
           .panel_settings.key_file = "/usr/local/x-ui/ssl/private.key"' \
           "$XUI_CONFIG_FILE" > "$XUI_CONFIG_FILE.tmp"; then
        
        mv "$XUI_CONFIG_FILE.tmp" "$XUI_CONFIG_FILE"
        log "Configuration updated with jq"
        return 0
    fi
    
    return 1
}

configure_3x_ui_ssl() {
    if [[ ! -f "$XUI_CONFIG_FILE" ]]; then
        error "Config file not found: $XUI_CONFIG_FILE"
        return 1
    fi
    
    log "Configuring SSL in 3x-ui..."
    
    # Stop service before editing config
    manage_service "stop"
    
    # Create backup
    create_backup "$XUI_CONFIG_FILE"
    
    # Try Python method first
    if update_config_with_python; then
        log "SSL configuration applied via Python"
    elif update_config_with_jq; then
        log "SSL configuration applied via jq"
    else
        error "All configuration methods failed"
        return 1
    fi
    
    # Restart service
    manage_service "start"
    
    # Verify service is running
    if systemctl is-active --quiet "$XUI_SERVICE"; then
        log "3x-ui service running with SSL configuration"
        return 0
    else
        error "Failed to start 3x-ui after SSL configuration"
        journalctl -u "$XUI_SERVICE" --no-pager -n 20
        return 1
    fi
}

# ============================================================================
# TESTING AND VALIDATION
# ============================================================================

test_ssl_connection() {
    log "Testing SSL connection..."
    
    wait_for "HTTPS access" \
        "curl -k -s -f https://localhost:$XUI_PORT > /dev/null" \
        10 5
    
    info "SSL Certificate Details:"
    openssl s_client -connect "localhost:$XUI_PORT" -servername localhost 2>/dev/null | \
        openssl x509 -noout -dates -subject -issuer | \
        sed 's/^/  /'
}

check_installation_status() {
    log "Checking installation status..."
    
    echo ""
    echo "Service Status:"
    echo "---------------"
    manage_service "status"
    
    echo ""
    echo "SSL Configuration:"
    echo "------------------"
    
    if [[ -f "$XUI_CONFIG_FILE" ]]; then
        echo "Config file exists: ✓"
        
        # Use jq if available, otherwise grep
        if command_exists jq; then
            cert_path=$(jq -r '.panel_settings.cert_file // empty' "$XUI_CONFIG_FILE")
            key_path=$(jq -r '.panel_settings.key_file // empty' "$XUI_CONFIG_FILE")
        else
            cert_path=$(grep -o '"cert_file": *"[^"]*"' "$XUI_CONFIG_FILE" | head -1 | cut -d'"' -f4)
            key_path=$(grep -o '"key_file": *"[^"]*"' "$XUI_CONFIG_FILE" | head -1 | cut -d'"' -f4)
        fi
        
        if [[ -n "$cert_path" && -n "$key_path" ]]; then
            echo "Certificate path: $cert_path"
            echo "Private key path: $key_path"
            
            [[ -f "$cert_path" ]] && echo "Certificate file exists: ✓" || echo "Certificate file exists: ✗"
            [[ -f "$key_path" ]] && echo "Private key file exists: ✓" || echo "Private key file exists: ✗"
        else
            echo "SSL not configured in config: ✗"
        fi
    else
        echo "Config file exists: ✗"
    fi
    
    echo ""
    echo "Network Access:"
    echo "---------------"
    if curl -k -s -f "https://localhost:$XUI_PORT" > /dev/null; then
        echo "Local HTTPS access: ✓"
    else
        echo "Local HTTPS access: ✗"
    fi
}

# ============================================================================
# INFORMATION DISPLAY
# ============================================================================

get_ip_addresses() {
    local local_ip
    local public_ip
    
    local_ip=$(hostname -I | awk '{print $1}')
    public_ip=$(curl -s ifconfig.me 2>/dev/null || echo "Unable to determine")
    
    echo "$local_ip|$public_ip"
}

show_installation_info() {
    IFS='|' read -r local_ip public_ip <<< "$(get_ip_addresses)"
    
    cat << EOF

═══════════════════════════════════════════════════════════════
                    3X-UI INSTALLATION COMPLETE                
═══════════════════════════════════════════════════════════════

📱 ACCESS INFORMATION:
   • Local:     https://localhost:$XUI_PORT
   • Network:   https://$local_ip:$XUI_PORT

$(if [[ "$local_ip" != "$public_ip" ]]; then
    echo "   • Internet:  https://$public_ip:$XUI_PORT"
fi)

🔐 DEFAULT CREDENTIALS:
   • Username:  admin
   • Password:  admin

⚠️  IMPORTANT:
   • Browser will show security warning (self-signed certificate)
   • Click 'Advanced' → 'Proceed to localhost (unsafe)'
   • CHANGE DEFAULT PASSWORD AFTER FIRST LOGIN!

📁 SSL CERTIFICATES:
   • Location: $XUI_SSL_DIR/
   • Certificate: $XUI_SSL_DIR/certificate.crt
   • Private Key: $XUI_SSL_DIR/private.key
   • Combined: $XUI_SSL_DIR/fullchain.pem

⚙️  MANAGEMENT COMMANDS:
   • Start:    systemctl start $XUI_SERVICE
   • Stop:     systemctl stop $XUI_SERVICE
   • Restart:  systemctl restart $XUI_SERVICE
   • Status:   systemctl status $XUI_SERVICE
   • Logs:     journalctl -u $XUI_SERVICE -f

📝 CONFIGURATION:
   • Config file: $XUI_CONFIG_FILE
   • View logs: journalctl -u $XUI_SERVICE

═══════════════════════════════════════════════════════════════

EOF
}

# ============================================================================
# MAIN OPERATIONS
# ============================================================================

perform_installation() {
    log "Starting 3x-ui installation with SSL..."
    
    check_root
    install_dependencies
    setup_firewall
    generate_ssl_certificates "$XUI_SSL_DIR"
    
    if ! install_3x_ui; then
        error "3x-ui installation failed"
        exit 1
    fi
    
    wait_for_config_file
    
    if ! configure_3x_ui_ssl; then
        error "SSL configuration failed"
        exit 1
    fi
    
    test_ssl_connection
    generate_alternative_ssl
    show_installation_info
    
    log "🎉 Installation completed successfully!"
}

fix_existing_installation() {
    log "Fixing existing 3x-ui installation..."
    
    check_root
    
    if ! systemctl list-unit-files | grep -q "$XUI_SERVICE"; then
        error "3x-ui is not installed"
        exit 1
    fi
    
    if [[ ! -d "$XUI_SSL_DIR" ]]; then
        generate_ssl_certificates "$XUI_SSL_DIR"
    fi
    
    if configure_3x_ui_ssl; then
        test_ssl_connection
        log "✓ SSL configuration fixed successfully"
    else
        error "Failed to fix SSL configuration"
        exit 1
    fi
}

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

show_usage() {
    cat << EOF
Usage: $(basename "$0") [COMMAND]

Commands:
  install     Install 3x-ui with SSL (default)
  fix         Fix SSL configuration on existing installation
  status      Check installation status
  test-ssl    Test SSL connection
  help        Show this help message

Examples:
  $(basename "$0")           # Install 3x-ui with SSL
  $(basename "$0") fix       # Fix existing installation
  $(basename "$0") status    # Check current status

EOF
}

# ============================================================================
# MAIN FUNCTION
# ============================================================================

main() {
    local command="${1:-install}"
    
    case "$command" in
        install)
            perform_installation
            ;;
        fix)
            fix_existing_installation
            ;;
        status)
            check_installation_status
            ;;
        "test-ssl")
            test_ssl_connection
            ;;
        help|-h|--help)
            show_usage
            ;;
        *)
            error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
