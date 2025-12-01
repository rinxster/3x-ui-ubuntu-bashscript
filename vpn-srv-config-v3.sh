#!/bin/bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
    log "Running as root - OK"
}

# Install 3x-ui with proper waiting
install_3x_ui() {
    log "Installing 3x-ui..."
    
    # Download and run installer
    curl -s -L https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh -o /tmp/install-3x-ui.sh
    chmod +x /tmp/install-3x-ui.sh
    /tmp/install-3x-ui.sh
    
    # Wait longer for installation to complete
    log "Waiting for 3x-ui installation to complete..."
    sleep 30
    
    # Check if service exists
    if systemctl list-unit-files | grep -q x-ui; then
        log "3x-ui service registered"
    else
        error "3x-ui service not found"
        return 1
    fi
    
    # Start the service
    systemctl start x-ui
    sleep 10
    
    # Check if service is running
    if systemctl is-active --quiet x-ui; then
        log "3x-ui service started successfully"
    else
        error "Failed to start x-ui service"
        journalctl -u x-ui --no-pager -n 20
        return 1
    fi
}

# Generate SSL certificates
generate_ssl() {
    log "Generating SSL certificates..."
    
    SSL_DIR="/usr/local/x-ui/ssl"
    mkdir -p $SSL_DIR
    
    # Generate private key
    openssl genrsa -out $SSL_DIR/private.key 2048 2>/dev/null
    
    # Generate certificate
    openssl req -new -x509 -key $SSL_DIR/private.key \
        -out $SSL_DIR/certificate.crt \
        -days 3650 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" 2>/dev/null
    
    # Create combined certificate (some panels need this)
    cat $SSL_DIR/certificate.crt $SSL_DIR/private.key > $SSL_DIR/fullchain.pem
    
    chmod 600 $SSL_DIR/private.key
    chmod 644 $SSL_DIR/certificate.crt $SSL_DIR/fullchain.pem
    
    log "SSL certificates generated in $SSL_DIR/"
    
    # Display certificate info
    openssl x509 -in $SSL_DIR/certificate.crt -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After"
}

# Wait for config file to be created
wait_for_config() {
    local config_file="/etc/x-ui/x-ui.json"
    local max_attempts=30
    local attempt=1
    
    log "Waiting for config file to be created..."
    
    while [[ ! -f "$config_file" && $attempt -le $max_attempts ]]; do
        log "Attempt $attempt/$max_attempts: Config file not found, waiting..."
        sleep 5
        ((attempt++))
    done
    
    if [[ -f "$config_file" ]]; then
        log "Config file found: $config_file"
        return 0
    else
        error "Config file not created after $max_attempts attempts"
        return 1
    fi
}

# Configure SSL in 3x-ui
configure_3x_ui_ssl() {
    local config_file="/etc/x-ui/x-ui.json"
    local ssl_dir="/usr/local/x-ui/ssl"
    
    if [[ ! -f "$config_file" ]]; then
        error "Config file does not exist: $config_file"
        error "Please check if 3x-ui installed correctly"
        return 1
    fi
    
    log "Configuring SSL in 3x-ui..."
    
    # Stop service before editing config
    systemctl stop x-ui
    
    # Create backup
    cp "$config_file" "$config_file.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Read and update config using Python
    python3 - << EOF
import json
import os
import sys

config_file = "/etc/x-ui/x-ui.json"

try:
    # Read current config
    with open(config_file, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    print("Current config structure:")
    print(json.dumps(config, indent=2)[:500] + "...")
    
    # Update panel settings with SSL
    if "panel_settings" not in config:
        config["panel_settings"] = {}
    
    config["panel_settings"]["cert_file"] = "/usr/local/x-ui/ssl/fullchain.pem"
    config["panel_settings"]["key_file"] = "/usr/local/x-ui/ssl/private.key"
    
    # Also update web settings if they exist
    if "web" in config.get("panel_settings", {}):
        config["panel_settings"]["web"]["cert_file"] = "/usr/local/x-ui/ssl/fullchain.pem"
        config["panel_settings"]["web"]["key_file"] = "/usr/local/x-ui/ssl/private.key"
    
    # Write updated config
    with open(config_file, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print("✓ SSL configuration applied successfully")
    
    # Verify the update
    with open(config_file, 'r') as f:
        updated_config = json.load(f)
    
    cert_path = updated_config.get("panel_settings", {}).get("cert_file", "")
    key_path = updated_config.get("panel_settings", {}).get("key_file", "")
    
    if cert_path and key_path:
        print(f"✓ Certificate path: {cert_path}")
        print(f"✓ Private key path: {key_path}")
    else:
        print("✗ SSL paths not found in updated config")
        sys.exit(1)
        
except Exception as e:
    print(f"✗ Error updating config: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
EOF
    
    if [[ $? -eq 0 ]]; then
        log "SSL configuration updated successfully"
        
        # Start service with new config
        systemctl start x-ui
        sleep 5
        
        if systemctl is-active --quiet x-ui; then
            log "3x-ui service started with SSL configuration"
        else
            error "Failed to start 3x-ui after SSL configuration"
            journalctl -u x-ui --no-pager -n 20
            return 1
        fi
    else
        error "Failed to update SSL configuration"
        return 1
    fi
}

# Alternative method using jq if available
configure_with_jq() {
    local config_file="/etc/x-ui/x-ui.json"
    
    log "Trying to configure with jq..."
    
    if command -v jq >/dev/null; then
        # Update config with jq
        jq '.panel_settings.cert_file = "/usr/local/x-ui/ssl/fullchain.pem" | 
            .panel_settings.key_file = "/usr/local/x-ui/ssl/private.key"' \
            "$config_file" > "$config_file.tmp" && \
        mv "$config_file.tmp" "$config_file"
        
        if [[ $? -eq 0 ]]; then
            log "✓ SSL configured with jq"
            return 0
        fi
    fi
    return 1
}

# Test SSL configuration
test_ssl() {
    log "Testing SSL configuration..."
    
    # Wait for service to fully start
    sleep 10
    
    # Test HTTPS access
    local max_attempts=10
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log "SSL test attempt $attempt/$max_attempts..."
        
        if curl -k -s -f https://localhost:2053 > /dev/null; then
            log "✓ HTTPS access successful!"
            
            # Get SSL certificate info
            echo "SSL Certificate Information:"
            echo "----------------------------"
            openssl s_client -connect localhost:2053 -servername localhost 2>/dev/null | \
                openssl x509 -noout -dates -subject -issuer | \
                sed 's/^/  /'
            
            return 0
        else
            warn "HTTPS test failed, retrying in 5 seconds..."
            sleep 5
            ((attempt++))
        fi
    done
    
    error "HTTPS test failed after $max_attempts attempts"
    return 1
}

# Setup firewall
setup_firewall() {
    log "Setting up firewall..."
    
    # Install ufw if not present
    if ! command -v ufw >/dev/null; then
        apt install -y ufw
    fi
    
    # Configure firewall
    ufw --force disable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 8443
    ufw allow 2053/tcp comment '3x-ui Panel'
    ufw --force enable
    
    log "Firewall configured:"
    ufw status verbose
}

# Display installation info
show_info() {
    local ip=$(hostname -I | awk '{print $1}')
    local public_ip=$(curl -s ifconfig.me)
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "                   3x-UI INSTALLATION COMPLETE                "
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "📱 ACCESS INFORMATION:"
    echo "   • Local:     https://localhost:2053"
    echo "   • Network:   https://$ip:2053"
    if [[ "$ip" != "$public_ip" ]]; then
        echo "   • Internet:  https://$public_ip:2053"
    fi
    echo ""
    echo "🔐 DEFAULT CREDENTIALS:"
    echo "   • Username:  admin"
    echo "   • Password:  admin"
    echo ""
    echo "⚠️  IMPORTANT:"
    echo "   • Browser will show security warning (self-signed certificate)"
    echo "   • Click 'Advanced' → 'Proceed to localhost (unsafe)'"
    echo "   • CHANGE DEFAULT PASSWORD AFTER FIRST LOGIN!"
    echo ""
    echo "📁 SSL CERTIFICATES:"
    echo "   • Location: /usr/local/x-ui/ssl/"
    echo "   • Certificate: /usr/local/x-ui/ssl/certificate.crt"
    echo "   • Private Key: /usr/local/x-ui/ssl/private.key"
    echo ""
    echo "⚙️  MANAGEMENT COMMANDS:"
    echo "   • Start:    systemctl start x-ui"
    echo "   • Stop:     systemctl stop x-ui"
    echo "   • Restart:  systemctl restart x-ui"
    echo "   • Status:   systemctl status x-ui"
    echo "   • Logs:     journalctl -u x-ui -f"
    echo ""
    echo "📝 CONFIGURATION:"
    echo "   • Config file: /etc/x-ui/x-ui.json"
    echo "   • Backup: /etc/x-ui/x-ui.json.backup.*"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
}

# Main installation function
main_install() {
    log "Starting 3x-ui installation with automatic SSL configuration..."
    
    # Check root
    check_root
    
    # Update system
    log "Updating system packages..."
    apt update && apt upgrade -y
    
    # Install dependencies
    log "Installing dependencies..."
    apt install -y curl wget openssl jq python3
    
    # Setup firewall
    setup_firewall
    
    # Generate SSL first
    generate_ssl
    
    # Install 3x-ui
    if ! install_3x_ui; then
        error "3x-ui installation failed"
        exit 1
    fi
    
    # Wait for config
    if ! wait_for_config; then
        error "Failed to get config file"
        exit 1
    fi
    
    # Configure SSL
    if ! configure_3x_ui_ssl; then
        warn "Trying alternative configuration method..."
        if ! configure_with_jq; then
            error "All SSL configuration methods failed"
            exit 1
        fi
    fi
    
    # Test SSL
    test_ssl
    
    # Show info
    show_info
    
    log "🎉 Installation completed successfully!"
}

# Fix existing installation
fix_installation() {
    log "Fixing existing 3x-ui installation..."
    
    check_root
    
    # Check if 3x-ui is installed
    if ! systemctl list-unit-files | grep -q x-ui; then
        error "3x-ui is not installed"
        exit 1
    fi
    
    # Generate SSL if needed
    if [[ ! -d "/usr/local/x-ui/ssl" ]]; then
        generate_ssl
    fi
    
    # Configure SSL
    if configure_3x_ui_ssl; then
        log "✓ SSL configuration fixed"
        test_ssl
    else
        error "Failed to fix SSL configuration"
        exit 1
    fi
}

# Check installation status
check_status() {
    log "Checking 3x-ui status..."
    
    echo ""
    echo "Service Status:"
    echo "---------------"
    systemctl status x-ui --no-pager | head -20
    
    echo ""
    echo "SSL Configuration:"
    echo "------------------"
    if [[ -f "/etc/x-ui/x-ui.json" ]]; then
        echo "Config file exists: ✓"
        
        # Check SSL paths in config
        if grep -q "cert_file" /etc/x-ui/x-ui.json; then
            cert_path=$(grep -o '"cert_file": *"[^"]*"' /etc/x-ui/x-ui.json | head -1 | cut -d'"' -f4)
            key_path=$(grep -o '"key_file": *"[^"]*"' /etc/x-ui/x-ui.json | head -1 | cut -d'"' -f4)
            echo "Certificate path: $cert_path"
            echo "Private key path: $key_path"
            
            if [[ -f "$cert_path" ]]; then
                echo "Certificate file exists: ✓"
            else
                echo "Certificate file exists: ✗"
            fi
            
            if [[ -f "$key_path" ]]; then
                echo "Private key file exists: ✓"
            else
                echo "Private key file exists: ✗"
            fi
        else
            echo "SSL not configured in config: ✗"
        fi
    else
        echo "Config file exists: ✗"
    fi
    
    echo ""
    echo "HTTPS Test:"
    echo "-----------"
    if curl -k -s -f https://localhost:2053 > /dev/null; then
        echo "HTTPS access: ✓"
    else
        echo "HTTPS access: ✗"
    fi
}

# Show usage
usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install     - Install 3x-ui with SSL (default)"
    echo "  fix         - Fix SSL configuration on existing installation"
    echo "  status      - Check installation status"
    echo "  help        - Show this help"
    echo ""
}

# Main
main() {
    local command=${1:-"install"}
    
    case $command in
        "install")
            main_install
            ;;
        "fix")
            fix_installation
            ;;
        "status")
            check_status
            ;;
        "help"|"-h"|"--help")
            usage
            ;;
        *)
            error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
