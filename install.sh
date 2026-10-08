#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
REPOSITORY=mastermadd/mission-control
INSTALL_DIR=/opt/mission-control
if [[ $EUID -ne 0 ]]; then echo 'Run: curl -fsSL https://raw.githubusercontent.com/mastermadd/mission-control/main/install.sh | sudo bash'; exit 1; fi
if [[ -e "$INSTALL_DIR/config/config.json" ]]; then echo 'Already installed. Run: sudo mission-control update'; exit 0; fi
. /etc/os-release
docker_repository(){
 case "$1" in
  debian|ubuntu) [[ -n "$2" ]] || return 1; printf '%s %s\n' "$1" "$2";;
  kali) printf 'debian trixie\n';;
  *) return 1;;
 esac
}
if ! read -r DOCKER_DISTRO DOCKER_CODENAME < <(docker_repository "$ID" "${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"); then echo 'Supported hosts: Debian, Ubuntu or Kali Linux.'; exit 1; fi
apt-get update -qq
apt-get install -y ca-certificates curl git python3 >/dev/null
exec 3<>/dev/tty
printf 'JDLN Mission Control — internal installation\n' >&3
read -r -p 'LAN IP address to bind (example 192.168.5.20): ' BIND_IP <&3
if ! python3 -c 'import ipaddress,sys; a=ipaddress.ip_address(sys.argv[1]); assert a.version==4 and a.is_private and not a.is_loopback and not a.is_link_local' "$BIND_IP" 2>/dev/null; then echo 'Enter a private IPv4 address assigned to this machine.'; exit 1; fi
read -r -p "Dashboard URL [http://$BIND_IP:8080]: " ORIGIN <&3
ORIGIN=${ORIGIN:-http://$BIND_IP:8080}
read -r -p 'Admin username [admin]: ' ADMIN_USER <&3
ADMIN_USER=${ADMIN_USER:-admin}
read -r -s -p 'Admin password (12+ characters): ' ADMIN_PASSWORD <&3; printf '\n' >&3
read -r -s -p 'Repeat password: ' CONFIRM_PASSWORD <&3; printf '\n' >&3
if [[ ${#ADMIN_PASSWORD} -lt 12 || ${#ADMIN_PASSWORD} -gt 1024 || "$ADMIN_PASSWORD" != "$CONFIRM_PASSWORD" ]]; then echo 'Passwords must match and be at least 12 characters.'; exit 1; fi
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
 install -m 0755 -d /etc/apt/keyrings
 curl -fsSL "https://download.docker.com/linux/$DOCKER_DISTRO/gpg" -o /etc/apt/keyrings/docker.asc
 chmod a+r /etc/apt/keyrings/docker.asc
 printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' "$(dpkg --print-architecture)" "$DOCKER_DISTRO" "$DOCKER_CODENAME" > /etc/apt/sources.list.d/mission-control-docker.list
 apt-get update -qq
 if command -v docker >/dev/null; then apt-get install -y docker-compose-plugin; else apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; fi
fi
if ! docker info >/dev/null 2>&1; then systemctl enable --now docker; fi
docker info >/dev/null
install -m 0755 -d "$INSTALL_DIR" "$INSTALL_DIR/releases"
install -m 0700 -d "$INSTALL_DIR/backups"
install -m 0755 -d -o 1000 -g 1000 "$INSTALL_DIR/config" "$INSTALL_DIR/data"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"; unset ADMIN_PASSWORD CONFIRM_PASSWORD' EXIT
git clone --quiet --depth 1 "https://github.com/$REPOSITORY.git" "$WORK/source"
REVISION=$(git -C "$WORK/source" rev-parse HEAD)
RELEASE="$INSTALL_DIR/releases/$REVISION"
if [[ ! -d "$RELEASE" ]]; then cp -a "$WORK/source" "$RELEASE"; fi
IMAGE="jdln-mission-control:$REVISION"
docker build --pull -t "$IMAGE" "$RELEASE"
printf '%s\0' "$ADMIN_USER" "$ADMIN_PASSWORD" "$ORIGIN" | python3 -c 'import sys,json; a=sys.stdin.buffer.read().decode().split("\0"); print(json.dumps(dict(username=a[0],password=a[1],origin=a[2])))' | docker run --rm -i -v "$INSTALL_DIR/config:/config" "$IMAGE" node provision.mjs
unset ADMIN_PASSWORD CONFIRM_PASSWORD
printf 'MISSION_IMAGE=%s\nMISSION_VERSION=%s\nMISSION_BIND_IP=%s\nMISSION_PORT=8080\n' "$IMAGE" "$REVISION" "$BIND_IP" > "$INSTALL_DIR/.env"
cp "$RELEASE/compose.yaml" "$INSTALL_DIR/compose.yaml"
ln -s "$RELEASE" "$INSTALL_DIR/current"
install -m 0755 "$RELEASE/mission-control" /usr/local/bin/mission-control
if ! docker compose --project-directory "$INSTALL_DIR" up -d --wait --wait-timeout 90; then echo 'Startup failed. Configuration was preserved; inspect: sudo mission-control logs'; exit 1; fi
printf '\nInstalled: %s\nUpdates: sudo mission-control update\nBackup: sudo mission-control backup\nStatus: sudo mission-control status\n' "$ORIGIN"
printf 'Sign in and use Import hosted workspace with the JSON from Export report in your hosted dashboard. Re-enter API credentials locally.\n'
