#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run this script as root, for example with: sudo ./01_sudo.sh"
    exit 1
fi

USER_NAME="${1:-${SUDO_USER:-}}"
if [ -z "$USER_NAME" ]; then
    printf "Linux account to grant sudo access to: "
    read -r USER_NAME
fi

if [ -z "$USER_NAME" ] || [ "$USER_NAME" = root ] || ! getent passwd "$USER_NAME" >/dev/null; then
    echo "ERROR: Provide the name of an existing non-root Linux account."
    exit 1
fi

echo "==> Granting sudo access to: $USER_NAME"
apt update
apt install -y sudo
usermod -aG sudo "$USER_NAME"

SUDOERS_FILE="/etc/sudoers.d/90-nath-homeserv"
if [ ! -e "$SUDOERS_FILE" ]; then
    TEMP_FILE="$(mktemp /etc/sudoers.d/.nath-homeserv.XXXXXX)"
    trap 'rm -f "$TEMP_FILE"' EXIT HUP INT TERM
    printf '%%sudo ALL=(ALL:ALL) ALL\n' > "$TEMP_FILE"
    chmod 0440 "$TEMP_FILE"
    visudo -cf "$TEMP_FILE"
    install -o root -g root -m 0440 "$TEMP_FILE" "$SUDOERS_FILE"
    rm -f "$TEMP_FILE"
    trap - EXIT HUP INT TERM
fi

visudo -cf "$SUDOERS_FILE"
echo "==> Done. Log out and back in for group membership to take effect."
echo "==> Test with: sudo -u $USER_NAME sudo -v"
