#!/bin/sh

# Detect current user
USER_NAME=$(whoami)

echo "==> Running as: $USER_NAME"

# Ensure script is running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Please run this script as root (using su -)."
    exit 1
fi

echo "==> Updating package lists..."
apt update -y

echo "==> Installing sudo..."
apt install -y sudo

echo "==> Installing git..."
apt install -y git

echo "==> Adding user '$USER_NAME' to sudo group..."
usermod -aG sudo "$USER_NAME"

echo "==> Making sure sudo group rule exists..."
if ! grep -q "^%sudo" /etc/sudoers; then
    echo "%sudo ALL=(ALL:ALL) ALL" >> /etc/sudoers
    echo "Added sudo group rule to /etc/sudoers"
else
    echo "sudo group rule already present."
fi

echo ""
echo "======================================"
echo " Done!"
echo " Logout + login again for sudo access."
echo " Test afterwards with: sudo echo OK"
echo "======================================"
