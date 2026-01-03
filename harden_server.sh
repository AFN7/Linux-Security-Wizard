#!/usr/bin/env bash
#
# Cross-distribution Linux hardening script inspired by the Toolsvana checklist.
# The script asks for confirmation before every critical change and attempts to
# support the most common package managers (APT, DNF/YUM, Zypper, Pacman).
#
# IMPORTANT: Always keep one SSH session open while testing the result.

set -euo pipefail

#######################################
# Logging helpers
#######################################
log()   { printf "\n[+] %s\n" "$1"; }
warn()  { printf "\n[!] %s\n" "$1"; }
fatal() { printf "\n[✗] %s\n" "$1"; exit 1; }

#######################################
# Preconditions
#######################################
require_root() {
  if [[ $(id -u) -ne 0 ]]; then
    fatal "Please run this script as root (sudo -i)."
  fi
}

detect_package_manager() {
  for candidate in apt-get dnf yum zypper pacman; do
    if command -v "$candidate" >/dev/null 2>&1; then
      PKG_MANAGER=$candidate
      return
    fi
  done
  fatal "Supported package manager not found (apt, dnf, yum, zypper, pacman)."
}

#######################################
# Package helpers
#######################################
pkg_update_upgrade() {
  log "Updating system packages ($PKG_MANAGER)"
  case "$PKG_MANAGER" in
    apt-get)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get upgrade -y
      ;;
    dnf)
      dnf -y upgrade --refresh
      ;;
    yum)
      yum -y update
      ;;
    zypper)
      zypper --non-interactive refresh
      zypper --non-interactive update
      ;;
    pacman)
      pacman -Syu --noconfirm
      ;;
  esac
}

pkg_install() {
  local packages=("$@")
  case "$PKG_MANAGER" in
    apt-get)
      apt-get install -y "${packages[@]}"
      ;;
    dnf)
      dnf install -y "${packages[@]}"
      ;;
    yum)
      yum install -y "${packages[@]}"
      ;;
    zypper)
      zypper --non-interactive install --force-resolution "${packages[@]}"
      ;;
    pacman)
      pacman -S --noconfirm --needed "${packages[@]}"
      ;;
  esac
}

#######################################
# Prompt utilities
#######################################
prompt_yes_no() {
  local question=$1
  local default=${2:-Y}
  local hint reply

  if [[ ${default^^} == "Y" ]]; then
    hint="Y/n"
  else
    hint="y/N"
  fi

  while true; do
    read -rp "${question} [${hint}]: " reply
    reply=${reply:-$default}
    case "${reply,,}" in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
      *) echo "Please answer yes or no." ;;
    esac
  done
}

prompt_for_user_inputs() {
  read -rp "Enter the name of the new privileged user: " NEW_ADMIN
  [[ -z ${NEW_ADMIN} ]] && fatal "User name cannot be empty."

  while true; do
    read -rsp "Enter a strong password for ${NEW_ADMIN}: " NEW_PASS
    echo
    read -rsp "Re-enter the password: " NEW_PASS_CONFIRM
    echo
    if [[ -n ${NEW_PASS} && ${NEW_PASS} == "${NEW_PASS_CONFIRM}" ]]; then
      break
    fi
    warn "Passwords do not match. Please try again."
  done

  DEFAULT_PORT=5622
  read -rp "Choose a new SSH port [${DEFAULT_PORT}]: " SSH_PORT
  SSH_PORT=${SSH_PORT:-$DEFAULT_PORT}
  if ! [[ ${SSH_PORT} =~ ^[0-9]+$ ]] || (( SSH_PORT < 1024 || SSH_PORT > 65535 )); then
    fatal "SSH port must be a number between 1024 and 65535."
  fi

  read -rp "Trusted IP/CIDR to whitelist in Fail2Ban (optional): " TRUSTED_IP

  read -rp "Paste the SSH public key for ${NEW_ADMIN} (single line, optional): " SSH_PUBKEY
  if [[ -z ${SSH_PUBKEY} ]]; then
    warn "No SSH key provided. Password-based SSH login will remain enabled."
    PASSWORD_LOGIN_DISABLE=false
  else
    PASSWORD_LOGIN_DISABLE=true
  fi

  prompt_yes_no "Enable unattended/automatic security updates" Y && ENABLE_AUTO_UPDATES=true || ENABLE_AUTO_UPDATES=false
  prompt_yes_no "Configure the SSH daemon with hardened settings" Y && ENABLE_SSH_HARDENING=true || ENABLE_SSH_HARDENING=false
  prompt_yes_no "Configure a host firewall" Y && ENABLE_FIREWALL=true || ENABLE_FIREWALL=false
  prompt_yes_no "Install and tune Fail2Ban" Y && ENABLE_FAIL2BAN=true || ENABLE_FAIL2BAN=false
  prompt_yes_no "Install Google Authenticator (SSH 2FA)" Y && ENABLE_GOOGLE_AUTH=true || ENABLE_GOOGLE_AUTH=false
  prompt_yes_no "Mount /tmp with noexec/nosuid/nodev" Y && HARDEN_TMP=true || HARDEN_TMP=false
}

#######################################
# User management
#######################################
detect_admin_group() {
  if getent group sudo >/dev/null; then
    ADMIN_GROUP=sudo
  elif getent group wheel >/dev/null; then
    ADMIN_GROUP=wheel
  else
    fatal "Neither 'sudo' nor 'wheel' group exists. Please create one and re-run."
  fi
}

create_privileged_user() {
  log "Creating or updating privileged user ${NEW_ADMIN}"
  if id -u "${NEW_ADMIN}" >/dev/null 2>&1; then
    warn "User ${NEW_ADMIN} already exists. The password will be updated."
  else
    if command -v adduser >/dev/null 2>&1; then
      adduser --disabled-password --gecos "" "${NEW_ADMIN}"
    else
      useradd -m -s /bin/bash "${NEW_ADMIN}"
    fi
  fi
  echo "${NEW_ADMIN}:${NEW_PASS}" | chpasswd
  usermod -aG "${ADMIN_GROUP}" "${NEW_ADMIN}"

  if [[ ${PASSWORD_LOGIN_DISABLE} == true ]]; then
    log "Installing provided SSH key for ${NEW_ADMIN}"
    install -d -m 700 -o "${NEW_ADMIN}" -g "${NEW_ADMIN}" "/home/${NEW_ADMIN}/.ssh"
    printf '%s\n' "${SSH_PUBKEY}" >"/home/${NEW_ADMIN}/.ssh/authorized_keys"
    chmod 600 "/home/${NEW_ADMIN}/.ssh/authorized_keys"
    chown "${NEW_ADMIN}:${NEW_ADMIN}" "/home/${NEW_ADMIN}/.ssh/authorized_keys"
  fi
}

#######################################
# System update & unattended upgrades
#######################################
configure_auto_updates() {
  pkg_update_upgrade

  if [[ ${ENABLE_AUTO_UPDATES} == false ]]; then
    warn "Automatic updates were skipped per user request."
    return
  fi

  log "Configuring automatic security updates"
  case "$PKG_MANAGER" in
    apt-get)
      pkg_install unattended-upgrades apt-listchanges
      dpkg-reconfigure -plow unattended-upgrades
      cat <<'EOF' >/etc/apt/apt.conf.d/51-toolsvana-auto
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
      unattended-upgrade --dry-run --debug || true
      ;;
    dnf)
      pkg_install dnf-automatic
      sed -i 's/^apply_updates = .*/apply_updates = yes/' /etc/dnf/automatic.conf
      sed -i 's/^download_updates = .*/download_updates = yes/' /etc/dnf/automatic.conf
      systemctl enable --now dnf-automatic.timer
      ;;
    yum)
      pkg_install yum-cron
      sed -i 's/^apply_updates = .*/apply_updates = yes/' /etc/yum/yum-cron.conf
      systemctl enable --now yum-cron
      ;;
    zypper|pacman)
      warn "Automatic patching must be configured manually on this distribution. Please create a cron/systemd timer that runs the relevant update command."
      ;;
  esac
}

#######################################
# SSH hardening
#######################################
configure_sshd() {
  if [[ ${ENABLE_SSH_HARDENING} == false ]]; then
    warn "SSH hardening skipped per user request."
    return
  fi

  log "Applying hardened SSH configuration"
  local sshd_dir="/etc/ssh"
  local dropin_dir="${sshd_dir}/sshd_config.d"
  local target

  if [[ -d ${dropin_dir} ]]; then
    target="${dropin_dir}/99-toolsvana-hardening.conf"
  else
    target="${sshd_dir}/sshd_config"
    cp "${target}" "${target}.bak.$(date +%s)"
    warn "sshd_config.d not available; writing directly to ${target} (backup created)."
  fi

  {
    echo "Port ${SSH_PORT}"
    echo "PermitRootLogin no"
    if [[ ${PASSWORD_LOGIN_DISABLE} == true ]]; then
      echo "PasswordAuthentication no"
    else
      echo "PasswordAuthentication yes"
      warn "Password authentication remains enabled because no public key was provided."
    fi
    echo "PubkeyAuthentication yes"
    echo "ChallengeResponseAuthentication yes"
    echo "KbdInteractiveAuthentication yes"
    echo "AuthenticationMethods publickey,keyboard-interactive"
    echo "UsePAM yes"
  } >"${target}"

  if ! sshd -t; then
    fatal "sshd configuration test failed. Your previous settings remain backuped."
  fi

  systemctl restart sshd 2>/dev/null || systemctl restart ssh
}

#######################################
# Firewall
#######################################
setup_firewall() {
  if [[ ${ENABLE_FIREWALL} == false ]]; then
    warn "Firewall configuration skipped per user request."
    return
  fi

  if command -v ufw >/dev/null 2>&1 || [[ $PKG_MANAGER == apt-get ]]; then
    log "Configuring UFW firewall"
    pkg_install ufw || warn "Failed to install UFW; attempting to use existing installation."
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow "${SSH_PORT}/tcp" comment "Secured SSH"
    ufw --force enable
    ufw status verbose
    return
  fi

  if command -v firewall-cmd >/dev/null 2>&1 || [[ $PKG_MANAGER =~ ^(dnf|yum|zypper)$ ]]; then
    log "Configuring firewalld"
    pkg_install firewalld || warn "Failed to install firewalld; attempting to use existing installation."
    systemctl enable --now firewalld
    firewall-cmd --permanent --set-default-zone=public
    firewall-cmd --permanent --zone=public --add-port="${SSH_PORT}/tcp"
    firewall-cmd --permanent --zone=public --add-service=ssh
    firewall-cmd --reload
    firewall-cmd --list-all
    return
  fi

  warn "No supported firewall backend detected. Please configure iptables/nftables manually."
}

#######################################
# Fail2Ban
#######################################
configure_fail2ban() {
  if [[ ${ENABLE_FAIL2BAN} == false ]]; then
    warn "Fail2Ban skipped per user request."
    return
  fi

  log "Installing and configuring Fail2Ban"
  pkg_install fail2ban
  local jail_file="/etc/fail2ban/jail.local"
  cat <<EOF >"${jail_file}"
[DEFAULT]
ignoreip = 127.0.0.1/8 ${TRUSTED_IP}
bantime = 1h
findtime = 10m
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ${SSH_PORT}
logpath = %(sshd_log)s
EOF
  systemctl enable --now fail2ban
  fail2ban-client status sshd || warn "Fail2Ban sshd jail status could not be queried."
}

#######################################
# Google Authenticator (2FA)
#######################################
setup_google_authenticator() {
  if [[ ${ENABLE_GOOGLE_AUTH} == false ]]; then
    warn "Google Authenticator skipped per user request."
    return
  fi

  local package_name
  case "$PKG_MANAGER" in
    apt-get|pacman) package_name="libpam-google-authenticator" ;;
    dnf|yum)        package_name="google-authenticator" ;;
    zypper)         package_name="google-authenticator-libpam" ;;
    *)              package_name="libpam-google-authenticator" ;;
  esac

  log "Installing Google Authenticator (package: ${package_name})"
  pkg_install "${package_name}"

  local pam_file="/etc/pam.d/sshd"
  cp "${pam_file}" "${pam_file}.bak.$(date +%s)"
  if ! grep -q "pam_google_authenticator.so" "${pam_file}"; then
    sed -i '1iauth       required     pam_google_authenticator.so' "${pam_file}"
  fi

  sudo -u "${NEW_ADMIN}" -H google-authenticator -t -d -f -r 3 -R 30 -W || true
  warn "The QR code and emergency codes were printed above. Store them securely."

  if ! sshd -t; then
    fatal "SSHD configuration test failed after enabling 2FA."
  fi
  systemctl restart sshd 2>/dev/null || systemctl restart ssh
}

#######################################
# /tmp hardening
#######################################
secure_tmp_partition() {
  if [[ ${HARDEN_TMP} == false ]]; then
    warn "/tmp hardening skipped per user request."
    return
  fi

  log "Applying noexec/nosuid/nodev to /tmp"
  local fstab_backup="/etc/fstab.$(date +%s).bak"
  cp /etc/fstab "${fstab_backup}"
  if ! grep -qs '^tmpfs /tmp' /etc/fstab; then
    cat <<'EOF' >>/etc/fstab
tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0
EOF
  else
    sed -i 's#^tmpfs /tmp .*#tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0#' /etc/fstab
  fi
  mount -a

  cat >/tmp/toolsvana_test.sh <<'EOF'
#!/usr/bin/env bash
echo "Hardened /tmp test"
EOF
  chmod +x /tmp/toolsvana_test.sh
  if /tmp/toolsvana_test.sh >/tmp/toolsvana_test.log 2>&1; then
    warn "/tmp still allows execution. Please review your fstab."
  else
    log "Execution in /tmp is blocked as expected."
  fi
  rm -f /tmp/toolsvana_test.sh /tmp/toolsvana_test.log
}

#######################################
# Final recommendations
#######################################
suggest_additional_steps() {
  log "Generating enabled service inventory"
  systemctl list-unit-files --state=enabled > /root/enabled-services.txt || true
  warn "Review /root/enabled-services.txt and disable everything you do not explicitly need."
  warn "Consider adding knockd, auditd, AIDE, and SELinux/AppArmor policies for maximum protection."
}

#######################################
# Main workflow
#######################################
main() {
  require_root
  detect_package_manager
  detect_admin_group

  log "This utility will apply multiple security controls to the current host."
  prompt_yes_no "Do you want to proceed" Y || fatal "User aborted."

  prompt_for_user_inputs
  create_privileged_user

  configure_auto_updates
  configure_sshd
  setup_firewall
  configure_fail2ban
  setup_google_authenticator
  secure_tmp_partition
  suggest_additional_steps

  log "All selected actions have been applied. Test SSH in a new terminal before closing this session."
}

main "$@"
