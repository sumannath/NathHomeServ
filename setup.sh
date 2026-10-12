#!/usr/bin/env bash
# setup.sh - Modular NathHomeServer environment setup script
# Version: 2.0
# Usage: bash setup.sh [--skip step1,step2] [--only step1,step2] [--config config.conf]

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
SSH_USER="${SUDO_USER:-}"
SKIP_STEPS=()
ONLY_STEPS=()
DRY_RUN=false
NON_INTERACTIVE=false
CURRENT_SSH_PORT=""
CURRENT_SSH_PORTS=""
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

resolve_path() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s/%s\n' "$SCRIPT_DIR" "$1" ;;
    esac
}

prompt_value() {
    local variable="$1"
    local label="$2"
    local default="$3"
    local value

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        printf -v "$variable" '%s' "$default"
        return 0
    fi

    read -r -p "$label [$default]: " value
    printf -v "$variable" '%s' "${value:-$default}"
}

prompt_yes_no() {
    local variable="$1"
    local label="$2"
    local default="$3"
    local answer
    local normalized_default

    normalized_default="${default,,}"

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        case "$normalized_default" in
            y|yes|true) printf -v "$variable" true ;;
            n|no|false) printf -v "$variable" false ;;
            *) error_exit "Invalid default value for $label: $default" ;;
        esac
        return 0
    fi

    read -r -p "$label [$default]: " answer
    answer="${answer:-$default}"
    case "${answer,,}" in
        y|yes|true) printf -v "$variable" true ;;
        n|no|false) printf -v "$variable" false ;;
        *) error_exit "Answer yes or no for: $label" ;;
    esac
}

get_current_ssh_port() {
    get_current_ssh_ports | awk 'NR == 1 { print; exit }'
}

get_current_ssh_ports() {
    if command -v sshd >/dev/null 2>&1; then
        sshd -T 2>/dev/null | awk '$1 == "port" && !seen[$2]++ { print $2 }'
    fi
}

valid_lan_cidr() {
    local network="$1"
    local address="${network%/*}"
    local prefix="${network#*/}"
    local octet
    local -a octets

    [[ "$address" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    [[ "$network" == */* && "$prefix" =~ ^[0-9]{1,2}$ ]] || return 1
    (( 10#$prefix <= 32 )) || return 1
    IFS='.' read -r -a octets <<< "$address"
    for octet in "${octets[@]}"; do
        (( 10#$octet <= 255 )) || return 1
    done
}

default_homelab_user() {
    getent passwd | awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /(nologin|false)$/ { print $1; exit }'
}

collect_setup_options() {
    local detected_ports
    detected_ports="$(get_current_ssh_ports)"
    local detected_port="${detected_ports%%$'\n'*}"
    local default_user="${SSH_USER:-$(default_homelab_user)}"

    detected_port="${detected_port:-22}"
    CURRENT_SSH_PORTS="${detected_ports:-$detected_port}"
    CURRENT_SSH_PORT="$detected_port"
    if [[ -z "$default_user" && "$NON_INTERACTIVE" == "true" ]]; then
        error_exit "Set SSH_USER or run with sudo from a non-root account."
    fi

    prompt_value SSH_USER "Linux account for SSH and administration" "$default_user"
    [[ -n "$SSH_USER" ]] || error_exit "An SSH account is required."
    id "$SSH_USER" >/dev/null 2>&1 || error_exit "Linux account '$SSH_USER' does not exist."
    [[ "$SSH_USER" != root ]] || error_exit "Choose a non-root SSH account; root login is disabled."

    local user_home
    user_home="$(getent passwd "$SSH_USER" | cut -d: -f6)"
    [[ -n "$user_home" && -d "$user_home" ]] || error_exit "Could not find a valid home directory for '$SSH_USER'."

    local selected_port="${SSH_PORT:-$detected_port}"
    prompt_value SSH_PORT "SSH port (current detected port: $detected_port)" "$selected_port"
    [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && (( SSH_PORT >= 1 && SSH_PORT <= 65535 )) ||
        error_exit "SSH_PORT must be an integer from 1 to 65535."

    prompt_value SSH_PUBLIC_KEY "Public SSH key file" "$SSH_PUBLIC_KEY"
    SSH_HARDENED_CONFIG="$(resolve_path "$SSH_HARDENED_CONFIG")"
    SSH_PUBLIC_KEY="$(resolve_path "$SSH_PUBLIC_KEY")"
    [[ -f "$SSH_PUBLIC_KEY" ]] || error_exit "Public key file not found: $SSH_PUBLIC_KEY. Set SSH_PUBLIC_KEY to a valid public key file."
    grep -Eq '^ssh-(rsa|ed25519)|^ecdsa-sha2-' "$SSH_PUBLIC_KEY" ||
        error_exit "SSH_PUBLIC_KEY does not appear to contain an OpenSSH public key."

    prompt_yes_no INSTALL_CASAOS "Install CasaOS and Docker" "${INSTALL_CASAOS:-true}"
    prompt_yes_no INSTALL_FAIL2BAN "Install Fail2ban" "${INSTALL_FAIL2BAN:-true}"
    prompt_yes_no INSTALL_SAMBA "Configure Samba file sharing" "${INSTALL_SAMBA:-true}"
    prompt_yes_no INSTALL_NORDVPN "Install NordVPN (may affect LAN routing)" "${INSTALL_NORDVPN:-false}"
    prompt_yes_no SETUP_DISK "Mount an additional disk (does not format it)" "${SETUP_DISK:-false}"
    prompt_yes_no DEPLOY_COMPOSE "Deploy the apps/docker-compose.yml service" "${DEPLOY_COMPOSE:-false}"

    if [[ "$SETUP_DISK" == "true" ]]; then
        prompt_value DISK_DEVICE "Disk partition to mount (for example /dev/sda1)" "${DISK_DEVICE:-}"
        [[ -b "$DISK_DEVICE" ]] || error_exit "Disk partition '$DISK_DEVICE' does not exist or is not a block device."
        prompt_value DISK_FILESYSTEM "Filesystem type (ntfs or ext4)" "${DISK_FILESYSTEM:-$(blkid -o value -s TYPE "$DISK_DEVICE" 2>/dev/null || true)}"
        [[ "$DISK_FILESYSTEM" == ntfs || "$DISK_FILESYSTEM" == ext4 ]] ||
            error_exit "Supported filesystem types are ntfs and ext4."
        prompt_value DISK_MOUNT_POINT "Disk mount point" "${DISK_MOUNT_POINT:-/media/nasssd}"
        [[ "$DISK_MOUNT_POINT" == /* && "$DISK_MOUNT_POINT" != *[[:space:]]* ]] ||
            error_exit "DISK_MOUNT_POINT must be an absolute path without whitespace."
    fi

    prompt_value LAN_CIDR "Trusted LAN CIDR for CasaOS/Samba firewall access (blank disables those rules)" "${LAN_CIDR:-}"
    if [[ -n "$LAN_CIDR" ]] && ! valid_lan_cidr "$LAN_CIDR"; then
        error_exit "LAN_CIDR must be an IPv4 CIDR network such as 192.168.1.0/24."
    fi

    if [[ "$INSTALL_SAMBA" == "true" ]]; then
        SAMBA_USER="${SAMBA_USER:-$SSH_USER}"
        prompt_value SAMBA_USER "Linux account for Samba access" "$SAMBA_USER"
        id "$SAMBA_USER" >/dev/null 2>&1 || error_exit "Samba account '$SAMBA_USER' does not exist."
        [[ "$SAMBA_USER" != root ]] || error_exit "Root cannot be used as the Samba account."
        prompt_value SAMBA_SHARE_NAME "Samba share name" "${SAMBA_SHARE_NAME:-NAS}"
        [[ "$SAMBA_SHARE_NAME" =~ ^[A-Za-z0-9_.-]+$ ]] ||
            error_exit "Samba share name may contain only letters, numbers, dot, underscore, and hyphen."
        if [[ "$SETUP_DISK" == "true" ]]; then
            SAMBA_SHARE_PATH="${SAMBA_SHARE_PATH:-$DISK_MOUNT_POINT}"
        else
            SAMBA_SHARE_PATH="${SAMBA_SHARE_PATH:-/srv/samba/NAS}"
        fi
        prompt_value SAMBA_SHARE_PATH "Samba shared directory" "$SAMBA_SHARE_PATH"
        [[ "$SAMBA_SHARE_PATH" == /* ]] || error_exit "SAMBA_SHARE_PATH must be an absolute path."
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
SSH_PORT="${SSH_PORT:-$(get_current_ssh_port)}"
SSH_PORT="${SSH_PORT:-22}"
SSH_HARDENED_CONFIG="${SSH_HARDENED_CONFIG:-ssh/hardened.conf}"
SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-ssh/nathHomeServ.pub}"

# Disk Configuration
DISK_DEVICE="${DISK_DEVICE:-}"
DISK_MOUNT_POINT="${DISK_MOUNT_POINT:-/media/nasssd}"
DISK_FILESYSTEM="${DISK_FILESYSTEM:-}"
SETUP_DISK="${SETUP_DISK:-false}"

# Samba Configuration
SAMBA_SHARE_NAME="${SAMBA_SHARE_NAME:-NAS}"
SAMBA_SHARE_PATH="${SAMBA_SHARE_PATH:-}"
SAMBA_USER="${SAMBA_USER:-${SUDO_USER:-}}"
SAMBA_GROUP="${SAMBA_GROUP:-users}"

# Services to install
INSTALL_CASAOS="${INSTALL_CASAOS:-true}"
INSTALL_FAIL2BAN="${INSTALL_FAIL2BAN:-true}"
INSTALL_SAMBA="${INSTALL_SAMBA:-true}"
INSTALL_NORDVPN="${INSTALL_NORDVPN:-false}"
DEPLOY_COMPOSE="${DEPLOY_COMPOSE:-false}"
LAN_CIDR="${LAN_CIDR:-}"

#===============================================================================
# Step Functions
#===============================================================================

step_system_update() {
    print_log "INFO" "Updating package list and installing essential packages..."
    apt update || return 1
    apt install -y curl wget git htop vim unattended-upgrades apt-listchanges || return 1
    
    # Enable unattended upgrades
    echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections || return 1
    dpkg-reconfigure -f noninteractive unattended-upgrades || return 1
    
    print_log "SUCCESS" "System updated and unattended upgrades enabled"
    return 0
}

step_ssh_hardening() {
    local ssh_conf_dir="/etc/ssh/sshd_config.d"
    local hardened_file="$ssh_conf_dir/00-nath-hardened.conf"
    local user_home
    user_home="$(getent passwd "$SSH_USER" | cut -d: -f6)"

    mkdir -p "$ssh_conf_dir" "$user_home/.ssh" || return 1
    touch "$user_home/.ssh/authorized_keys" || return 1
    if ! grep -Fqx -f "$SSH_PUBLIC_KEY" "$user_home/.ssh/authorized_keys"; then
        cat "$SSH_PUBLIC_KEY" >> "$user_home/.ssh/authorized_keys" || return 1
    fi
    chmod 700 "$user_home/.ssh" || return 1
    chmod 600 "$user_home/.ssh/authorized_keys" || return 1
    chown "$SSH_USER:$(id -gn "$SSH_USER")" "$user_home/.ssh" "$user_home/.ssh/authorized_keys" || return 1

    local config_tmp backup_tmp
    local had_previous_config=false
    config_tmp="$(mktemp)" || return 1
    backup_tmp="$(mktemp)" || { rm -f "$config_tmp"; return 1; }
    if grep -Eq '^[[:space:]]*Port[[:space:]]+' "$SSH_HARDENED_CONFIG"; then
        sed -E "s/^[[:space:]]*Port[[:space:]]+.*/Port $SSH_PORT/" "$SSH_HARDENED_CONFIG" > "$config_tmp" || {
            rm -f "$config_tmp" "$backup_tmp"
            return 1
        }
    else
        printf 'Port %s\n' "$SSH_PORT" > "$config_tmp" || { rm -f "$config_tmp" "$backup_tmp"; return 1; }
        cat "$SSH_HARDENED_CONFIG" >> "$config_tmp" || { rm -f "$config_tmp" "$backup_tmp"; return 1; }
    fi
    if [[ -f "$hardened_file" ]]; then
        cp -p "$hardened_file" "$backup_tmp" || { rm -f "$config_tmp" "$backup_tmp"; return 1; }
        had_previous_config=true
    fi
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
        ufw allow "${SSH_PORT}/tcp" || { rm -f "$config_tmp" "$backup_tmp"; return 1; }
        local current_port
        while IFS= read -r current_port; do
            [[ -n "$current_port" && "$current_port" != "$SSH_PORT" ]] || continue
            ufw allow "${current_port}/tcp" || { rm -f "$config_tmp" "$backup_tmp"; return 1; }
        done <<< "$CURRENT_SSH_PORTS"
    fi
    install -m 644 "$config_tmp" "$hardened_file" || { rm -f "$config_tmp" "$backup_tmp"; return 1; }
    rm -f "$config_tmp"

    if ! sshd -t; then
        print_log "ERROR" "SSH configuration test failed; restoring the previous configuration."
        if [[ "$had_previous_config" == "true" ]]; then
            install -m 644 "$backup_tmp" "$hardened_file" || { rm -f "$backup_tmp"; return 1; }
        else
            rm -f "$hardened_file" || { rm -f "$backup_tmp"; return 1; }
        fi
        rm -f "$backup_tmp"
        return 1
    fi
    local effective_ports
    effective_ports="$(get_current_ssh_ports)"
    if ! grep -Fxq "$SSH_PORT" <<< "$effective_ports"; then
        print_log "ERROR" "The effective SSH configuration does not listen on port $SSH_PORT; restoring the previous configuration."
        if [[ "$had_previous_config" == "true" ]]; then
            install -m 644 "$backup_tmp" "$hardened_file" || { rm -f "$backup_tmp"; return 1; }
        else
            rm -f "$hardened_file" || { rm -f "$backup_tmp"; return 1; }
        fi
        rm -f "$backup_tmp"
        return 1
    fi
    if [[ "$(wc -w <<< "$effective_ports")" -gt 1 ]]; then
        print_log "WARNING" "OpenSSH is configured to listen on multiple ports: ${effective_ports//$'\n'/, }."
    fi
    if ! systemctl restart ssh && ! systemctl restart sshd; then
        print_log "ERROR" "Could not restart SSH; restoring the previous configuration."
        if [[ "$had_previous_config" == "true" ]]; then
            install -m 644 "$backup_tmp" "$hardened_file" || { rm -f "$backup_tmp"; return 1; }
        else
            rm -f "$hardened_file" || { rm -f "$backup_tmp"; return 1; }
        fi
        rm -f "$backup_tmp"
        systemctl restart ssh || systemctl restart sshd || return 1
        return 1
    fi
    rm -f "$backup_tmp"
    print_log "INFO" "SSH is configured on port $SSH_PORT. Keep the current session open and verify a new login before closing it."
}

step_firewall_setup() {
    apt install -y ufw || return 1
    local current_ports="${CURRENT_SSH_PORTS:-22}"
    ufw default deny incoming || return 1
    ufw default allow outgoing || return 1
    ufw allow "${SSH_PORT}/tcp" || return 1
    local current_port
    while IFS= read -r current_port; do
        [[ -n "$current_port" ]] || continue
        ufw allow "${current_port}/tcp" || return 1
        if [[ "$current_port" != "$SSH_PORT" ]]; then
            print_log "WARNING" "Keeping the currently detected SSH port $current_port open until you verify access on $SSH_PORT."
        fi
    done <<< "$current_ports"
    ufw --force enable || return 1

    print_log "INFO" "Firewall configured with SSH port $SSH_PORT allowed"
    return 0
}

step_fail2ban_install() {
    [[ "$INSTALL_FAIL2BAN" != "true" ]] && return 0
    
    apt install -y fail2ban || return 1
    systemctl enable --now fail2ban || return 1
    
    # Create custom jail for SSH
    cat > /etc/fail2ban/jail.local << EOF || return 1
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
backend = systemd
maxretry = 3
bantime = 3600
findtime = 600
EOF
    
    systemctl restart fail2ban || return 1
    return 0
}

step_disk_setup() {
    [[ "$SETUP_DISK" != "true" ]] && return 0
    local disk="$DISK_DEVICE"
    local mount_point="$DISK_MOUNT_POINT"
    
    # Check if disk exists
    if [[ ! -b "$disk" ]]; then
        print_log "WARNING" "Disk $disk not found, skipping disk setup"
        return 0
    fi
    
    mkdir -p "$mount_point" || return 1
    
    local uuid
    uuid="$(blkid -s UUID -o value "$disk")"
    [[ -n "$uuid" ]] || { print_log "ERROR" "Could not determine UUID for $disk."; return 1; }

    local mounted_source
    mounted_source="$(findmnt -n -o SOURCE --mountpoint "$mount_point" 2>/dev/null || true)"
    if [[ -n "$mounted_source" ]]; then
        [[ "$(readlink -f "$mounted_source")" == "$(readlink -f "$disk")" ]] || {
            print_log "ERROR" "$mount_point is already mounted from $mounted_source, not $disk."
            return 1
        }
    fi
    local existing_mount
    existing_mount="$(findmnt -n -o TARGET --source "$disk" 2>/dev/null || true)"
    if [[ -n "$existing_mount" && "$existing_mount" != "$mount_point" ]]; then
        print_log "ERROR" "$disk is already mounted at $existing_mount, not $mount_point."
        return 1
    fi

    local mount_options="defaults"
    if [[ "$DISK_FILESYSTEM" == "ntfs" && "$INSTALL_SAMBA" == "true" ]]; then
        if ! getent group "$SAMBA_GROUP" >/dev/null; then
            groupadd "$SAMBA_GROUP" || return 1
        fi
        local share_gid
        share_gid="$(getent group "$SAMBA_GROUP" | cut -d: -f3)"
        mount_options="uid=$(id -u "$SAMBA_USER"),gid=$share_gid,umask=0007"
    fi

    case "$DISK_FILESYSTEM" in
        "ntfs") apt install -y ntfs-3g || return 1 ;;
        "ext4") apt install -y e2fsprogs || return 1 ;;
        *) print_log "ERROR" "Unsupported filesystem: $DISK_FILESYSTEM"; return 1 ;;
    esac
    
    if [[ -z "$mounted_source" ]]; then
        mount -t "$DISK_FILESYSTEM" -o "$mount_options" "$disk" "$mount_point" || return 1
    fi
    
    local fstab_tmp
    fstab_tmp="$(mktemp /etc/fstab.XXXXXX)" || return 1
    local fstab_options="$mount_options,nofail,x-systemd.device-timeout=10s"
    if ! awk -v uuid="$uuid" -v mount_point="$mount_point" \
        -v filesystem="$DISK_FILESYSTEM" -v options="$fstab_options" '
        $1 == "UUID=" uuid {
            if ($2 != mount_point || found++) {
                conflict = 1
                print
                next
            }
            printf "UUID=%s  %s  %s  %s  0  0\n", uuid, mount_point, filesystem, options
            next
        }
        $1 !~ /^#/ && $2 == mount_point { conflict = 1 }
        { print }
        END {
            if (conflict) exit 1
            if (!found) printf "UUID=%s  %s  %s  %s  0  0\n", uuid, mount_point, filesystem, options
        }
    ' /etc/fstab > "$fstab_tmp"; then
        rm -f "$fstab_tmp"
        print_log "ERROR" "Conflicting or duplicate /etc/fstab entry for $disk or $mount_point."
        return 1
    fi
    install -m 644 "$fstab_tmp" /etc/fstab || { rm -f "$fstab_tmp"; return 1; }
    rm -f "$fstab_tmp"
    
    print_log "INFO" "Disk mounted at $mount_point"
    return 0
}

step_casaos_install() {
    [[ "$INSTALL_CASAOS" != "true" ]] && return 0
    
    if systemctl is-active --quiet casaos; then
        print_log "INFO" "CasaOS already installed and running"
    else
        if ! command -v docker &> /dev/null; then
            print_log "INFO" "Installing Docker..."
            curl -fsSL https://get.docker.com | sh || return 1
        fi

        curl -fsSL https://get.casaos.io | bash || return 1
    fi
    
    if [[ -n "$LAN_CIDR" ]]; then
        ufw allow from "$LAN_CIDR" to any port 80 proto tcp || return 1
        ufw allow from "$LAN_CIDR" to any port 443 proto tcp || return 1
        ufw reload || return 1
    else
        print_log "WARNING" "No LAN CIDR configured; no CasaOS web ports were opened in UFW."
    fi
    
    # Add user to docker group
    getent group docker >/dev/null || { print_log "ERROR" "Docker group was not created by the installer."; return 1; }
    usermod -aG docker "$SSH_USER" || return 1
    
    return 0
}

step_samba_setup() {
    [[ "$INSTALL_SAMBA" != "true" ]] && return 0
    
    apt install -y samba samba-common-bin || return 1
    
    # Create group and user
    if ! getent group "$SAMBA_GROUP" > /dev/null; then
        groupadd "$SAMBA_GROUP" || return 1
    fi

    if ! id -u "$SAMBA_USER" > /dev/null 2>&1; then
        useradd --no-create-home --shell /usr/sbin/nologin --ingroup "$SAMBA_GROUP" "$SAMBA_USER" || return 1
    fi

    # Set up shared directory
    mkdir -p "$SAMBA_SHARE_PATH" || return 1
    usermod -aG "$SAMBA_GROUP" "$SAMBA_USER" || return 1
    local share_fstype
    share_fstype="$(findmnt -n -o FSTYPE --target "$SAMBA_SHARE_PATH" 2>/dev/null || true)"
    if [[ "$share_fstype" == ntfs || "$share_fstype" == ntfs3 ]]; then
        print_log "INFO" "Leaving NTFS ownership to its mount options; existing contents were not recursively changed."
    else
        chown "$SAMBA_USER:$SAMBA_GROUP" "$SAMBA_SHARE_PATH" || return 1
        chmod 2770 "$SAMBA_SHARE_PATH" || return 1
    fi
    
    # Configure Samba
    if ! grep -q "\\[$SAMBA_SHARE_NAME\\]" /etc/samba/smb.conf; then
        cat >> /etc/samba/smb.conf << EOF || return 1

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
    if [[ -t 0 && "$NON_INTERACTIVE" != "true" ]]; then
        print_log "INFO" "Setting up Samba user password..."
        smbpasswd -a "$SAMBA_USER" || return 1
        smbpasswd -e "$SAMBA_USER" || return 1
    elif ! pdbedit -L -u "$SAMBA_USER" 2>/dev/null | grep -Fq "$SAMBA_USER:"; then
        print_log "ERROR" "No Samba password exists for $SAMBA_USER; rerun interactively and set one with smbpasswd."
        return 1
    fi
    
    # Enable and start services
    testparm -s >/dev/null || return 1
    systemctl enable --now smbd nmbd || return 1
    if [[ -n "$LAN_CIDR" ]]; then
        ufw allow from "$LAN_CIDR" to any port 137 proto udp || return 1
        ufw allow from "$LAN_CIDR" to any port 138 proto udp || return 1
        ufw allow from "$LAN_CIDR" to any port 139 proto tcp || return 1
        ufw allow from "$LAN_CIDR" to any port 445 proto tcp || return 1
    else
        print_log "WARNING" "No LAN CIDR configured; Samba firewall access was not opened."
    fi
    
    return 0
}

step_nordvpn_install() {
    [[ "$INSTALL_NORDVPN" != "true" ]] && return 0
    
    if ! command -v nordvpn &> /dev/null; then
        sh <(curl -sSf https://downloads.nordcdn.com/apps/linux/install.sh) || return 1
    fi
    
    usermod -aG nordvpn "$SSH_USER" || return 1
    
    # Configure NordVPN
    nordvpn set lan-discovery enable || return 1
    nordvpn set autoconnect enabled || return 1
    
    return 0
}

step_docker_compose_install() {
    [[ "$DEPLOY_COMPOSE" != "true" ]] && return 0
    local app_dir="$SCRIPT_DIR/apps"
    [[ -f "$app_dir/docker-compose.yml" ]] || { print_log "ERROR" "Compose file not found: $app_dir/docker-compose.yml"; return 1; }
    [[ -f "$app_dir/.env" ]] || {
        print_log "ERROR" "Missing $app_dir/.env. Copy .env.example there, set the image's documented variable names, then rerun this step."
        return 1
    }
    chmod 600 "$app_dir/.env" || return 1
    command -v docker >/dev/null 2>&1 || { print_log "ERROR" "Docker is required to deploy the Compose app."; return 1; }
    docker compose -f "$app_dir/docker-compose.yml" --env-file "$app_dir/.env" config -q || return 1
    docker compose -f "$app_dir/docker-compose.yml" --env-file "$app_dir/.env" up -d || return 1
}

step_final_report() {
    local private_ip=$(hostname -I | awk '{print $1}')
    
    print_log "SUCCESS" "=== SETUP COMPLETE ==="
    print_log "INFO" "SSH: ssh -p $SSH_PORT $SSH_USER@$private_ip"
    
    if systemctl is-active --quiet casaos; then
        print_log "INFO" "CasaOS: http://$private_ip (HTTPS: https://$private_ip)"
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
  --non-interactive Use config/default values without prompts
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
  docker_compose_install Deploy apps/docker-compose.yml
  final_report      Display setup summary

Example:
  bash $0 --skip nordvpn_install,samba_setup
  bash $0 --only system_update,ssh_hardening
  bash $0 --config /path/to/custom.conf
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
    echo "  docker_compose_install"
    echo "  final_report"
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --config)
                [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "ERROR: --config requires a file path."; return 1; }
                CONFIG_FILE="$2"
                shift 2
                ;;
            --skip)
                [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "ERROR: --skip requires a comma-separated step list."; return 1; }
                IFS=',' read -ra SKIP_STEPS <<< "$2"
                shift 2
                ;;
            --only)
                [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "ERROR: --only requires a comma-separated step list."; return 1; }
                IFS=',' read -ra ONLY_STEPS <<< "$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --non-interactive)
                NON_INTERACTIVE=true
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

    local requested_step
    for requested_step in "${SKIP_STEPS[@]}" "${ONLY_STEPS[@]}"; do
        case "$requested_step" in
                system_update|ssh_hardening|firewall_setup|fail2ban_install|disk_setup|casaos_install|samba_setup|nordvpn_install|docker_compose_install|final_report) ;;
                *) echo "ERROR: Unknown setup step: $requested_step"; return 1 ;;
        esac
    done
    if [[ ${#ONLY_STEPS[@]} -gt 0 && ${#SKIP_STEPS[@]} -gt 0 ]]; then
        echo "ERROR: Use either --only or --skip, not both."
        return 1
    fi
}

main() {
    parse_arguments "$@" || exit 1
    check_root
    print_log "INFO" "Starting NathHomeServer setup script v2.0"
    print_log "INFO" "Running as user: ${SSH_USER:-unknown}"
    load_config "$CONFIG_FILE"
    [[ "$CONFIG_FILE" = /* ]] || CONFIG_FILE="$(resolve_path "$CONFIG_FILE")"
    collect_setup_options
    load_plugins

    set -uo pipefail
    
    # Execute all steps
    run_step "system_update" "System update and essential packages" step_system_update || error_exit "System update failed."
    run_step "ssh_hardening" "SSH security hardening" step_ssh_hardening || error_exit "SSH hardening failed."
    run_step "firewall_setup" "UFW firewall configuration" step_firewall_setup || error_exit "Firewall setup failed."
    run_step "fail2ban_install" "Fail2Ban intrusion prevention" step_fail2ban_install || error_exit "Fail2Ban setup failed."
    run_step "disk_setup" "Additional disk mounting" step_disk_setup || error_exit "Disk setup failed."
    run_step "casaos_install" "CasaOS container platform" step_casaos_install || error_exit "CasaOS installation failed."
    run_step "samba_setup" "Samba file sharing service" step_samba_setup || error_exit "Samba setup failed."
    run_step "nordvpn_install" "NordVPN client installation" step_nordvpn_install || error_exit "NordVPN installation failed."
    run_step "docker_compose_install" "Docker Compose app deployment" step_docker_compose_install || error_exit "Compose deployment failed."
    run_step "final_report" "Setup completion summary" step_final_report || error_exit "Final report failed."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_log "INFO" "Dry run finished; no setup steps were executed."
    else
        print_log "SUCCESS" "All selected steps completed successfully!"
    fi
}

# Only run main if script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi