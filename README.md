# Linux Security Wizard

A cross-distribution, fully interactive hardening utility that automates a comprehensive server lockdown checklist. The script walks operators through every major decision—user creation, SSH lockdown, firewalls, Fail2Ban, multifactor authentication, /tmp hardening—and adapts to the detected package manager (APT, DNF/YUM, Zypper, Pacman).

## Features

- **Cross-distro support:** Detects apt, dnf, yum, zypper, or pacman and uses the best available tooling on each platform.
- **Interactive workflow:** Professional English prompts confirm every critical change and allow opting in/out per control.
- **Privileged user provisioning:** Creates a new sudo/wheel user, installs the provided SSH key, and disables password logins when possible.
- **SSH hardening:** Changes the daemon port, blocks root logins, enforces key + keyboard-interactive auth, and keeps `KbdInteractiveAuthentication yes` to avoid 2FA restart issues.
- **Automated patching:** Configures unattended upgrades (APT), dnf-automatic, yum-cron, or leaves instructions for other distros.
- **Firewall automation:** Chooses UFW or firewalld based on availability, otherwise prompts for manual action.
- **Fail2Ban tuning:** Installs Fail2Ban with sensible bantime/findtime/maxretry defaults and optional trusted IP whitelist.
- **Google Authenticator 2FA:** Installs the proper PAM module, injects it into `/etc/pam.d/sshd`, and guides the user through QR/backup codes.
- **/tmp protection:** Mounts `/tmp` as tmpfs with `noexec,nosuid,nodev` and verifies execution is blocked.
- **Operational checklist:** Outputs enabled services for manual review and recommends advanced hardening (knockd, auditd, AIDE, SELinux/AppArmor).

## Requirements

- Root access (`sudo -i`).
- A modern Linux distribution with one of the supported package managers.
- OpenSSH server installed and running.
- Optional but recommended: an SSH key pair and a TOTP application (Google Authenticator, Authy, etc.).

## Usage

```bash
# Copy the repository to your server
scp -r LinuxSecurityWizard user@server:/opt/

# On the server
cd /opt/LinuxSecurityWizard
chmod +x harden_server.sh
sudo ./harden_server.sh
```

Keep your original SSH session open while testing a second session after each change—especially when altering SSH ports, authentication methods, or enabling 2FA.

