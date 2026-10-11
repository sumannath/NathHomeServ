# NathHomeServ

Provisioning scripts for a Debian-based home server. `setup.sh` is interactive by default; it requires root privileges and uses `systemd`, `apt`, OpenSSH, and UFW.

## First-time setup

1. Create a non-root Linux account and install sudo:

   ```sh
   su -
   cd /path/to/NathHomeServ
   sh 01_sudo.sh your-linux-user
   ```

   Log in again as that user, then run the main setup with `sudo bash setup.sh`. Running through `sudo` lets the installer identify the intended non-root account.

2. Answer the setup prompts. It detects the current SSH port and asks which port to use, which account and public key to authorize, which services to install, whether to mount an additional disk, and which LAN CIDR (if any) may access the web UI and Samba.

3. Keep the current SSH session open. Test a new key-based login on the selected port before closing it. When satisfied, remove the old SSH port's UFW rule yourself if it is no longer needed.

The installer does **not** format disks. Disk setup is opt-in, verifies the selected block device and mount point, and adds a `nofail` fstab entry. Review the proposed device and any existing data before enabling it. Samba changes only the top-level share directory's ownership and mode; it does not recursively alter existing files.

The default SSH public key is `ssh/nathHomeServ.pub`. Make sure the matching private key is available to the client you will use to log in. Do not disable password access or close an existing session until a new login has been verified.

## Network and service notes

- UFW denies incoming traffic by default. SSH remains allowed on the currently detected port and the selected port during migration. CasaOS web and Samba rules are limited to the configured IPv4 LAN CIDR; leaving that prompt blank does not open those service ports.
- Docker-published ports may bypass UFW filtering. Review Docker port bindings and test exposure from outside the LAN; do not assume UFW alone protects published containers.
- NordVPN is opt-in because its routing can affect LAN access, Samba, and remote administration.
- Samba setup prompts for its Samba password when run interactively. A non-interactive run requires an existing Samba password for the selected account.
- The CasaOS report uses its HTTP/HTTPS web endpoints (ports 80/443); confirm the installed service's actual bindings before relying on those URLs.

## Compose app

The Torleech Compose service is optional and can be deployed from the setup prompts. Before enabling it, create `apps/.env` from `apps/.env.example`, set real credentials, and verify the environment variable names against the `sumannath/torleech_autologin` image documentation. The example file uses `TORLEECH_PASSWORD`; the image's accepted variable names cannot be verified from this repository alone. `.env` is gitignored and should never be committed.

## Non-interactive use

Pass `--non-interactive` to use values from `config.conf` (or built-in defaults) without prompts. Review those values first, especially `SSH_USER`, `SSH_PORT`, `SSH_PUBLIC_KEY`, and disk/service options. `--dry-run` prints the selected steps without applying them. `--only` and `--skip` do not automatically run prerequisite steps; use them only when those prerequisites are already satisfied.
