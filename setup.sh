#!/usr/bin/env bash
# setup.sh - Script to setu NathHomeServer environment

#===============================================================================
#  Script generic setup
#===============================================================================
print_log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] - $1"
}

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

SSH_USER=${SUDO_USER:-$USER}
print_log "Running user: $SSH_USER"

set -euo pipefail

#===============================================================================
# 1. Enable unattended upgrades
#===============================================================================
# Update package list
print_log "Updating package list..."
# Install unattended-upgrades if not present
apt update
apt install -y unattended-upgrades apt-listchanges

# Preseed the answer to "Yes"
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | sudo debconf-set-selections

# Apply configuration non-interactively
dpkg-reconfigure -f noninteractive unattended-upgrades

print_log "Unattended upgrades enabled."

#===============================================================================
## 2. Apply SSH hardening
#===============================================================================
print_log "Starting SSH hardening..."

SSH_CONF_DIR="/etc/ssh/sshd_config.d"
HARDENED_FILE="$SSH_CONF_DIR/hardened.conf"

print_log "Applying SSH hardening..."
install -m 644 ssh/hardened.conf "$HARDENED_FILE"

print_log "Testing SSH configuration..."
sshd -t

print_log "Restarting SSH..."
systemctl restart ssh

## 2a. Add your public key
PUB_KEY_PATH="ssh/nathHomeServ.pub"
USER_HOME="/home/$SSH_USER"

if [[ -f "$PUB_KEY_PATH" ]]; then
    print_log "Adding public key for $SSH_USER..."
    mkdir -p "$USER_HOME/.ssh"
    cat "$PUB_KEY_PATH" >> "$USER_HOME/.ssh/authorized_keys"
    chmod 700 "$USER_HOME/.ssh"
    chmod 600 "$USER_HOME/.ssh/authorized_keys"
    chown -R "$SSH_USER:$SSH_USER" "$USER_HOME/.ssh"
    print_log "Public key added."
else
    print_log "Public key not found at $PUB_KEY_PATH. Skipping."
fi

#===============================================================================
## 3. Enable firewall
#===============================================================================
print_log "Configuring UFW firewall..."
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
# Allow hardened SSH port
SSH_PORT=$(grep -E '^Port ' "$HARDENED_FILE" | awk '{print $2}')
ufw allow "${SSH_PORT}/tcp"
ufw --force enable
print_log "Firewall configured. SSH port $SSH_PORT is allowed."

#===============================================================================
## 4. Install fail2ban
#===============================================================================
print_log "Installing Fail2Ban..."
apt install -y fail2ban
systemctl enable --now fail2ban

print_log "SSH hardening complete!"

#===============================================================================
## 5. Mount 1.8 TB disk as /media/nasssd
#===============================================================================
print_log "Mounting 1.8 TB disk as /media/nasssd..."
DISK="/dev/sda1"
MOUNT_POINT="/media/nasssd"

print_log "Setting up $DISK to mount at $MOUNT_POINT..."

# Create mount point
mkdir -p "$MOUNT_POINT"

# Check if disk has a filesystem
FS_TYPE=$(blkid -o value -s TYPE "$DISK" || true)
if [[ "$FS_TYPE" != "ntfs" ]]; then
    echo "Disk not NTFS. Please reformat if needed or adjust FS_TYPE."
    FS_TYPE="ntfs"
fi

# Ensure ntfs-3g is installed
apt install -y ntfs-3g

# Mount using ntfs-3g
if ! mount | grep -q "$DISK"; then
    mount -t ntfs-3g "$DISK" "$MOUNT_POINT"
else
    echo "$DISK is already mounted."
fi

# Add to fstab
UUID=$(blkid -s UUID -o value "$DISK")
if ! grep -q "$UUID" /etc/fstab; then
    echo "UUID=$UUID  $MOUNT_POINT  ntfs-3g  defaults  0  0" >> /etc/fstab
fi

# Verify mount
df -h | grep "$MOUNT_POINT"

print_log "Disk mounted successfully at $MOUNT_POINT."

#===============================================================================
## 6. Install CasaOS
#===============================================================================
print_log "Installing CasaOS..."
# Check if CasaOS is already installed and running
if systemctl is-active --quiet casaos; then
    print_log "CasaOS is already installed and running. No action taken."
else
    print_log "CasaOS is not detected as running. Proceeding with installation."
    apt install -y curl wget
    curl -fsSL https://get.casaos.io | bash

    ## 6.1. Open HTTP/HTTPS ports in UFW for CasaOS
    print_log "Allowing HTTP (80) and HTTPS (443) in UFW..."
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw reload

    print_log "Ports 80 and 443 are now open."
fi

print_log "Adding $SSH_USER to the docker group..."
usermod -aG docker "$SSH_USER"

#===============================================================================
## 7. Samba Setup
#===============================================================================
# Configuration variables
SHARE_NAME="NAS"
SHARE_PATH="/media/nasssd"
SAMBA_USER="suman"
SAMBA_GROUP="users"

# 1. Install Samba
print_log "Installing Samba..."
apt update
apt install -y samba samba-common samba-client # For Debian/Ubuntu-based systems

# 2. Create the shared directory
print_log "Creating shared directory: $SHARE_PATH"
if [ ! -d "$SHARE_PATH" ]; then
    print_log "Directory $SHARE_PATH does not exist. Creating it now..."
else
    print_log "Directory $SHARE_PATH already exists."
fi

# 3. Set directory permissions and ownership
print_log "Setting permissions and ownership for $SHARE_PATH"
# Create the Samba group if it doesn't exist
if ! getent group $SAMBA_GROUP > /dev/null; then
    groupadd $SAMBA_GROUP
fi

# Add the samba user to the system if not present
if ! id -u $SAMBA_USER > /dev/null 2>&1; then
    useradd --no-create-home --shell /usr/sbin/nologin --ingroup $SAMBA_GROUP $SAMBA_USER
fi

# Set ownership of the shared directory to the Samba user and group
chown -R $SAMBA_USER:$SAMBA_GROUP $SHARE_PATH
# Set appropriate permissions for the shared directory
chmod -R 2770 $SHARE_PATH

# 4. Configure Samba (edit smb.conf)
print_log "Configuring Samba share in /etc/samba/smb.conf"
bash -c "cat >> /etc/samba/smb.conf <<EOL
[$SHARE_NAME]
path = $SHARE_PATH
browsable = yes
writable = yes
guest ok = no
valid users = @$SAMBA_GROUP
create mask = 0660
directory mask = 2770
EOL"

# 5. Create a Samba user and set password
print_log "Creating Samba user $SAMBA_USER and setting password..."

# Prompt the user for the Samba password securely
read -s -p "Enter password for Samba user '$SAMBA_USER': " SAMBA_PASSWORD
echo # Print a newline after the password input

# Use smbpasswd to add the user and set the password.
# We need to pipe the password to smbpasswd using `echo` and `-a -s`.
# The `-s` option tells smbpasswd to read from standard input.
echo -e "$SAMBA_PASSWORD\n$SAMBA_PASSWORD" | smbpasswd -a -s $SAMBA_USER
smbpasswd -e $SAMBA_USER # Enable the Samba user

# 6. Enable and restart Samba services
print_log "Enabling and restarting Samba services..."
systemctl enable smbd nmbd
systemctl restart smbd nmbd

# 7. Open Samba ports in firewall (if using UFW)
print_log "Allowing Samba through the firewall (if UFW is active)..."
ufw allow samba

#===============================================================================
## 7. Display setup
#===============================================================================
print_log "Setup complete. Displaying configuration details..."

PRIVATE_IP=$(hostname -I | awk '{print $1}')
print_log "Debian 13 hardening and CasaOS installation complete!"
print_log "Test SSH with: ssh -p $SSH_PORT $SSH_USER@$PRIVATE_IP before closing this session."
print_log "Access CasaOS at http://$PRIVATE_IP:8080"

print_log "Samba share '$SHARE_NAME' created successfully at $SHARE_PATH!"
print_log "You can now access it from network clients using \\\\$PRIVATE_IP\\$SHARE_NAME or smb://$PRIVATE_IP/$SHARE_NAME"