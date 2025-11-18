#!/usr/bin/env bash
# setup.sh - Modular NathHomeServer environment setup script
# Version: 2.0
# Usage: ./setup.sh [--skip step1,step2] [--only step1,step2] [--config config.conf]

#===============================================================================
# Global Configuration and Utilities
#===============================================================================

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.conf"
LOG_FILE="${SCRIPT_DIR}/setup.log"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
SSH_USER="${SUDO_USER:-$USER}"
SKIP_STEPS=()
ONLY_STEPS=()
DRY_RUN=false
PLUGINS_DIR="${SCRIPT_DIR}/plugins"
LOADED_PLUGINS=()

#===============================================================================
# Utility Functions
#===============================================================================

print_log() {
    local level="$1"
    local message="$2"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local color=""
    
    case "$level" in
        "ERROR") color="$RED" ;;
        "SUCCESS") color="$GREEN" ;;
        "WARNING") color="$YELLOW" ;;
        "INFO") color="$BLUE" ;;
        *) color="$NC" ;;
    esac
    
    echo -e "${color}[$timestamp] [$level] - $message${NC}"
    echo "[$timestamp] [$level] - $message" >> "$LOG_FILE"
}

error_exit() {
    print_log "ERROR" "$1"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root."
    fi
}

load_config() {
    if [[ -f "$1" ]]; then
        print_log "INFO" "Loading configuration from $1"
        source "$1"
    else
        print_log "WARNING" "Configuration file $1 not found, using defaults"
    fi
}

load_plugins() {
    if [[ ! -d "$PLUGINS_DIR" ]]; then
        print_log "INFO" "No plugins directory found, skipping plugin loading"
        return 0
    fi
    
    print_log "INFO" "Loading plugins from $PLUGINS_DIR"
    
    for plugin_file in "$PLUGINS_DIR"/*.sh; do
        if [[ -f "$plugin_file" ]]; then
            print_log "INFO" "Loading plugin: $(basename "$plugin_file")"
            source "$plugin_file"
            
            # Extract plugin name from the file
            local plugin_name=$(basename "$plugin_file" .sh)
            LOADED_PLUGINS+=("$plugin_name")
            
            # Call register function if it exists
            if declare -f register_plugin > /dev/null; then
                register_plugin
            fi
        fi
    done
    
    print_log "INFO" "Loaded ${#LOADED_PLUGINS[@]} plugins: ${LOADED_PLUGINS[*]}"
}

should_run_step() {
    local step_name="$1"
    
    # If ONLY_STEPS is set, only run those steps
    if [[ ${#ONLY_STEPS[@]} -gt 0 ]]; then
        for only_step in "${ONLY_STEPS[@]}"; do
            [[ "$step_name" == "$only_step" ]] && return 0
        done
        return 1
    fi
    
    # Check if step should be skipped
    for skip_step in "${SKIP_STEPS[@]}"; do
        [[ "$step_name" == "$skip_step" ]] && return 1
    done
    
    return 0
}

run_step() {
    local step_name="$1"
    local step_description="$2"
    local step_function="$3"
    
    if ! should_run_step "$step_name"; then
        print_log "INFO" "Skipping step: $step_name"
        return 0
    fi
    
    print_log "INFO" "Starting step: $step_name - $step_description"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_log "INFO" "DRY RUN: Would execute $step_function"
        return 0
    fi
    
    if $step_function; then
        print_log "SUCCESS" "Completed step: $step_name"
        return 0
    else
        print_log "ERROR" "Failed step: $step_name"
        return 1
    fi
}

#===============================================================================
# Configuration Defaults (can be overridden in config.conf)
#===============================================================================

# SSH Configuration
SSH_PORT="${SSH_PORT:-2222}"
SSH_HARDENED_CONFIG="${SSH_HARDENED_CONFIG:-ssh/hardened.conf}"
SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-ssh/nathHomeServ.pub}"

# Disk Configuration
DISK_DEVICE="${DISK_DEVICE:-/dev/sda1}"
DISK_MOUNT_POINT="${DISK_MOUNT_POINT:-/media/nasssd}"
DISK_FILESYSTEM="${DISK_FILESYSTEM:-ntfs}"

# Samba Configuration
SAMBA_SHARE_NAME="${SAMBA_SHARE_NAME:-NAS}"
SAMBA_SHARE_PATH="${SAMBA_SHARE_PATH:-/media/nasssd}"
SAMBA_USER="${SAMBA_USER:-$USER}"
SAMBA_GROUP="${SAMBA_GROUP:-users}"

# Services to install
INSTALL_CASAOS="${INSTALL_CASAOS:-true}"
INSTALL_NORDVPN="${INSTALL_NORDVPN:-true}"
INSTALL_FAIL2BAN="${INSTALL_FAIL2BAN:-true}"
INSTALL_SAMBA="${INSTALL_SAMBA:-true}"

#===============================================================================
# Step Functions
#===============================================================================

step_system_update() {
    print_log "INFO" "Updating package list and installing essential packages..."
    apt update || return 1
    apt install -y curl wget git htop vim unattended-upgrades apt-listchanges || return 1
    
    # Enable unattended upgrades
    echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
    dpkg-reconfigure -f noninteractive unattended-upgrades || return 1
    
    print_log "SUCCESS" "System updated and unattended upgrades enabled"
    return 0
}

step_ssh_hardening() {
    local ssh_conf_dir="/etc/ssh/sshd_config.d"
    local hardened_file="$ssh_conf_dir/hardened.conf"
    
    # Create SSH config directory if it doesn't exist
    mkdir -p "$ssh_conf_dir"
    
    # Create hardened SSH config if not exists
    if [[ ! -f "$SSH_HARDENED_CONFIG" ]]; then
        print_log "INFO" "Creating default hardened SSH configuration"
        mkdir -p "$(dirname "$SSH_HARDENED_CONFIG")"
        cat > "$SSH_HARDENED_CONFIG" << EOF
# SSH Hardening Configuration
Port $SSH_PORT
Protocol 2
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 2
EOF
    fi
    
    # Apply SSH hardening
    if install -m 644 "$SSH_HARDENED_CONFIG" "$hardened_file"; then
        print_log "INFO" "SSH hardening configuration applied to $hardened_file"
    else
        print_log "ERROR" "Failed to install SSH hardening config to $hardened_file"
        return 1
    fi
    
    # Add public key
    if [[ -f "$SSH_PUBLIC_KEY" ]]; then
        local user_home="/home/$SSH_USER"
        if mkdir -p "$user_home/.ssh" && 
           cat "$SSH_PUBLIC_KEY" >> "$user_home/.ssh/authorized_keys" &&
           chmod 700 "$user_home/.ssh" &&
           chmod 600 "$user_home/.ssh/authorized_keys" &&
           chown -R "$SSH_USER:$SSH_USER" "$user_home/.ssh"; then
            print_log "INFO" "Public key added for $SSH_USER"
        else
            print_log "WARNING" "Failed to add public key for $SSH_USER"
        fi
    else
        print_log "INFO" "Public key file $SSH_PUBLIC_KEY not found, skipping key setup"
    fi
    
    # Test SSH configuration
    if sshd -t; then
        print_log "INFO" "SSH configuration test passed"
    else
        print_log "ERROR" "SSH configuration test failed"
        return 1
    fi
    
    # Restart SSH service
    if systemctl restart ssh; then
        print_log "INFO" "SSH service restarted successfully"
    else
        print_log "ERROR" "Failed to restart SSH service"
        return 1
    fi
    
    return 0
}

step_firewall_setup() {
    apt install -y ufw || return 1
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow "${SSH_PORT}/tcp"
    ufw --force enable
    
    print_log "INFO" "Firewall configured with SSH port $SSH_PORT allowed"
    return 0
}

step_fail2ban_install() {
    [[ "$INSTALL_FAIL2BAN" != "true" ]] && return 0
    
    apt install -y fail2ban || return 1
    systemctl enable --now fail2ban || return 1
    
    # Create custom jail for SSH
    cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF
    
    systemctl restart fail2ban || return 1
    return 0
}

step_disk_setup() {
    local disk="$DISK_DEVICE"
    local mount_point="$DISK_MOUNT_POINT"
    
    # Check if disk exists
    if [[ ! -b "$disk" ]]; then
        print_log "WARNING" "Disk $disk not found, skipping disk setup"
        return 0
    fi
    
    mkdir -p "$mount_point"
    
    # Install filesystem tools
    case "$DISK_FILESYSTEM" in
        "ntfs") apt install -y ntfs-3g ;;
        "ext4") apt install -y e2fsprogs ;;
        *) print_log "WARNING" "Unknown filesystem: $DISK_FILESYSTEM" ;;
    esac
    
    # Mount disk
    if ! mount | grep -q "$disk"; then
        mount -t "$DISK_FILESYSTEM" "$disk" "$mount_point" || return 1
    fi
    
    # Add to fstab
    local uuid=$(blkid -s UUID -o value "$disk")
    if [[ -n "$uuid" ]] && ! grep -q "$uuid" /etc/fstab; then
        echo "UUID=$uuid  $mount_point  $DISK_FILESYSTEM  defaults  0  0" >> /etc/fstab
    fi
    
    print_log "INFO" "Disk mounted at $mount_point"
    return 0
}

step_casaos_install() {
    [[ "$INSTALL_CASAOS" != "true" ]] && return 0
    
    if systemctl is-active --quiet casaos; then
        print_log "INFO" "CasaOS already installed and running"
        return 0
    fi
    
    # Install Docker first if not present
    if ! command -v docker &> /dev/null; then
        print_log "INFO" "Installing Docker..."
        curl -fsSL https://get.docker.com | sh || return 1
    fi
    
    # Install CasaOS
    curl -fsSL https://get.casaos.io | bash || return 1
    
    # Open ports for CasaOS
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw reload
    
    # Add user to docker group
    usermod -aG docker "$SSH_USER"
    
    return 0
}

step_samba_setup() {
    [[ "$INSTALL_SAMBA" != "true" ]] && return 0
    
    apt install -y samba samba-common-bin || return 1
    
    # Create group and user
    if ! getent group "$SAMBA_GROUP" > /dev/null; then
        groupadd "$SAMBA_GROUP"
    fi
    
    if ! id -u "$SAMBA_USER" > /dev/null 2>&1; then
        useradd --no-create-home --shell /usr/sbin/nologin --ingroup "$SAMBA_GROUP" "$SAMBA_USER"
    fi
    
    # Set up shared directory
    if [[ -d "$SAMBA_SHARE_PATH" ]]; then
        chown -R "$SAMBA_USER:$SAMBA_GROUP" "$SAMBA_SHARE_PATH"
        chmod -R 2770 "$SAMBA_SHARE_PATH"
    fi
    
    # Configure Samba
    if ! grep -q "\\[$SAMBA_SHARE_NAME\\]" /etc/samba/smb.conf; then
        cat >> /etc/samba/smb.conf << EOF

[$SAMBA_SHARE_NAME]
path = $SAMBA_SHARE_PATH
browsable = yes
writable = yes
guest ok = no
valid users = @$SAMBA_GROUP
create mask = 0660
directory mask = 2770
EOF
    fi
    
    # Set Samba password (interactive)
    if [[ -t 0 ]]; then  # Only if running interactively
        print_log "INFO" "Setting up Samba user password..."
        smbpasswd -a "$SAMBA_USER"
        smbpasswd -e "$SAMBA_USER"
    fi
    
    # Enable and start services
    systemctl enable --now smbd nmbd
    ufw allow samba
    
    return 0
}

step_nordvpn_install() {
    [[ "$INSTALL_NORDVPN" != "true" ]] && return 0
    
    if command -v nordvpn &> /dev/null; then
        print_log "INFO" "NordVPN already installed"
        return 0
    fi
    
    sh <(curl -sSf https://downloads.nordcdn.com/apps/linux/install.sh) || return 1
    usermod -aG nordvpn "$SSH_USER"
    
    # Configure NordVPN
    nordvpn set lan-discovery enable
    nordvpn set autoconnect enabled
    
    return 0
}

step_final_report() {
    local private_ip=$(hostname -I | awk '{print $1}')
    
    print_log "SUCCESS" "=== SETUP COMPLETE ==="
    print_log "INFO" "SSH: ssh -p $SSH_PORT $SSH_USER@$private_ip"
    
    if systemctl is-active --quiet casaos; then
        print_log "INFO" "CasaOS: http://$private_ip:8080"
    fi
    
    if systemctl is-active --quiet smbd; then
        print_log "INFO" "Samba: \\\\\\$private_ip\\$SAMBA_SHARE_NAME"
    fi
    
    print_log "INFO" "Log file: $LOG_FILE"
    return 0
}

#===============================================================================
# Main Execution
#===============================================================================

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  --config FILE     Use custom configuration file
  --skip STEPS      Comma-separated list of steps to skip
  --only STEPS      Only run these steps (comma-separated)
  --dry-run         Show what would be done without executing
  --list-steps      List all available steps
  --help            Show this help message

Available steps:
  system_update     Update system and enable unattended upgrades
  ssh_hardening     Configure SSH security settings
  firewall_setup    Configure UFW firewall
  fail2ban_install  Install and configure Fail2Ban
  disk_setup        Mount and configure additional disk
  casaos_install    Install CasaOS container platform
  samba_setup       Configure Samba file sharing
  nordvpn_install   Install NordVPN client
  final_report      Display setup summary

Example:
  $0 --skip nordvpn_install,samba_setup
  $0 --only system_update,ssh_hardening
  $0 --config /path/to/custom.conf
EOF
}

list_steps() {
    echo "Available steps:"
    echo "  system_update"
    echo "  ssh_hardening"
    echo "  firewall_setup"
    echo "  fail2ban_install"
    echo "  disk_setup"
    echo "  casaos_install"
    echo "  samba_setup"
    echo "  nordvpn_install"
    echo "  final_report"
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --skip)
                IFS=',' read -ra SKIP_STEPS <<< "$2"
                shift 2
                ;;
            --only)
                IFS=',' read -ra ONLY_STEPS <<< "$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --list-steps)
                list_steps
                exit 0
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

main() {
    parse_arguments "$@"
    
    print_log "INFO" "Starting NathHomeServer setup script v2.0"
    print_log "INFO" "Running as user: $SSH_USER"
    
    check_root
    load_config "$CONFIG_FILE"
    load_plugins  # Load any available plugins
    
    set -euo pipefail
    
    # Execute all steps
    run_step "system_update" "System update and essential packages" step_system_update
    run_step "ssh_hardening" "SSH security hardening" step_ssh_hardening
    run_step "firewall_setup" "UFW firewall configuration" step_firewall_setup
    run_step "fail2ban_install" "Fail2Ban intrusion prevention" step_fail2ban_install
    run_step "disk_setup" "Additional disk mounting" step_disk_setup
    run_step "casaos_install" "CasaOS container platform" step_casaos_install
    run_step "samba_setup" "Samba file sharing service" step_samba_setup
    run_step "nordvpn_install" "NordVPN client installation" step_nordvpn_install
    
    # Execute plugin steps (example: would need to be dynamically added)
    if [[ " ${LOADED_PLUGINS[@]} " =~ " docker-compose " ]]; then
        run_step "docker_compose_install" "Docker Compose and container services" step_docker_compose_install
    fi
    
    run_step "final_report" "Setup completion summary" step_final_report
    
    print_log "SUCCESS" "All selected steps completed successfully!"
}

# Only run main if script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi