#!/bin/bash

# -----------------------------------------------------------------------------
# Script: wlan_autonomo.sh
# Funcion: Mantener viva la interfaz Wi-Fi (por defecto wlan0) incluso si
#          NetworkManager se detiene durante el bypass. Configura
#          wpa_supplicant y dhcpcd para gestionar la interfaz de forma
#          independiente y permite revertir los cambios facilmente.
# Uso basico:
#   sudo ./wlan_autonomo.sh apply --ssid "MiWiFi" --psk "MiClaveSuperSecreta"
#   sudo ./wlan_autonomo.sh status
#   sudo ./wlan_autonomo.sh restore
# -----------------------------------------------------------------------------

set -euo pipefail

VERSION="0.1.0"
WLAN_IFACE="wlan0"
WPACFG_PREFIX="/etc/wpa_supplicant/wpa_supplicant"
WPACFG_FILE="${WPACFG_PREFIX}-${WLAN_IFACE}.conf"
NM_OVERRIDE="/etc/NetworkManager/conf.d/wlan_autonomo.conf"

COLOR_INFO="\e[1;34m"
COLOR_OK="\e[1;32m"
COLOR_WARN="\e[1;31m"
COLOR_RESET="\e[0m"

info() { echo -e "${COLOR_INFO}[*] $1${COLOR_RESET}"; }
ok()   { echo -e "${COLOR_OK}[+] $1${COLOR_RESET}"; }
warn() { echo -e "${COLOR_WARN}[!] $1${COLOR_RESET}"; }

require_root() {
  if [ "${EUID}" -ne 0 ]; then
    warn "Ejecuta este script como root (usa sudo)."
    exit 1
  fi
}

ensure_tools() {
  local missing=()
  for cmd in wpa_passphrase systemctl ip; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    warn "Faltan herramientas: ${missing[*]}"
    warn "Instala 'wpasupplicant' y 'dhcpcd5' (o equivalentes) antes de continuar."
    exit 1
  fi
}

install_packages_if_needed() {
  local pkgs=(wpasupplicant dhcpcd5)
  local missing=()
  for pkg in "${pkgs[@]}"; do
    dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    if command -v apt-get >/dev/null 2>&1; then
      info "Instalando paquetes faltantes: ${missing[*]}"
      apt-get update
      apt-get install -y "${missing[@]}"
    else
      warn "No puedo instalar automaticamente los paquetes: ${missing[*]}"
      exit 1
    fi
  fi
}

create_wpa_config() {
  local ssid="$1"
  local psk="$2"
  info "Creando configuracion de wpa_supplicant para ${WLAN_IFACE}"
  mkdir -p "$WPACFG_PREFIX"
  wpa_passphrase "$ssid" "$psk" > "$WPACFG_FILE"
  chmod 600 "$WPACFG_FILE"
  ok "Configuracion guardada en $WPACFG_FILE"
}

mark_nm_unmanaged() {
  info "Indicando a NetworkManager que ignore ${WLAN_IFACE}."
  mkdir -p /etc/NetworkManager/conf.d
  cat > "$NM_OVERRIDE" <<CONF
[keyfile]
unmanaged-devices=interface-name:${WLAN_IFACE}
CONF
  ok "NetworkManager ignorara ${WLAN_IFACE}."
}

reload_nm() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files --type=service --no-legend | awk '{print $1}' | grep -Fxq "NetworkManager.service"; then
    info "Reiniciando NetworkManager para aplicar cambios."
    systemctl restart NetworkManager.service || warn "No se pudo reiniciar NetworkManager."
  else
    info "NetworkManager no esta presente; se ignora este paso."
  fi
}

enable_wifi_services() {
  info "Activando wpa_supplicant y dhcpcd para ${WLAN_IFACE}."
  systemctl enable --now "wpa_supplicant@${WLAN_IFACE}.service"
  systemctl enable --now "dhcpcd@${WLAN_IFACE}.service"
  ok "Servicios activados."
}

bring_up_interface() {
  info "Levantando ${WLAN_IFACE}."
  ip link set "$WLAN_IFACE" up || warn "No se pudo levantar ${WLAN_IFACE}."
  ok "${WLAN_IFACE} arriba."
}

apply_guard() {
  require_root
  install_packages_if_needed
  ensure_tools

  local ssid=""
  local psk=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ssid)
        ssid="$2"; shift 2 ;;
      --psk)
        psk="$2"; shift 2 ;;
      --iface)
        WLAN_IFACE="$2"
        WPACFG_FILE="${WPACFG_PREFIX}-${WLAN_IFACE}.conf"
        shift 2 ;;
      *)
        warn "Parametro desconocido: $1"
        exit 1 ;;
    esac
  done

  if [ -z "$ssid" ] || [ -z "$psk" ]; then
    warn "Debes proporcionar SSID y PSK: --ssid "MiWiFi" --psk "MiClave""
    exit 1
  fi

  create_wpa_config "$ssid" "$psk"
  mark_nm_unmanaged
  reload_nm
  enable_wifi_services
  bring_up_interface
  ok "Blindaje autonomo de ${WLAN_IFACE} completado."
  echo ""
  info "A partir de ahora puedes detener NetworkManager sin perder la Wi-Fi."
}

restore_guard() {
  require_root
  info "Revirtiendo configuracion autonoma de Wi-Fi."
  systemctl disable --now "dhcpcd@${WLAN_IFACE}.service" 2>/dev/null || true
  systemctl disable --now "wpa_supplicant@${WLAN_IFACE}.service" 2>/dev/null || true

  if [ -f "$NM_OVERRIDE" ]; then
    rm -f "$NM_OVERRIDE"
    info "Eliminado $NM_OVERRIDE"
  fi
  reload_nm

  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files --type=service --no-legend | awk '{print $1}' | grep -Fxq "NetworkManager.service"; then
    info "Devolviendo ${WLAN_IFACE} a NetworkManager."
    nmcli device set "$WLAN_IFACE" managed yes 2>/dev/null || true
    systemctl restart NetworkManager.service || true
  fi

  if [ -f "$WPACFG_FILE" ]; then
    info "Mantengo $WPACFG_FILE (borralo manualmente si no lo quieres)."
  fi
  ok "Restauracion completada."
}

show_status() {
  require_root
  info "Estado de wlan_autonomo.sh v$VERSION"
  echo "Interfaz objetivo: $WLAN_IFACE"
  if [ -f "$WPACFG_FILE" ]; then
    ok "Existe configuracion WPA en $WPACFG_FILE"
  else
    warn "No hay configuracion WPA creada por este script."
  fi

  if [ -f "$NM_OVERRIDE" ]; then
    ok "NetworkManager ignora ${WLAN_IFACE}."
  else
    info "NetworkManager gestiona ${WLAN_IFACE}."
  fi

  systemctl is-active "wpa_supplicant@${WLAN_IFACE}.service" >/dev/null 2>&1 && ok "wpa_supplicant@${WLAN_IFACE} activo" || warn "wpa_supplicant@${WLAN_IFACE} no esta activo"
  systemctl is-active "dhcpcd@${WLAN_IFACE}.service" >/dev/null 2>&1 && ok "dhcpcd@${WLAN_IFACE} activo" || warn "dhcpcd@${WLAN_IFACE} no esta activo"

  if command -v nmcli >/dev/null 2>&1; then
    nmcli -t -f DEVICE,STATE,CONNECTION dev status | grep "$WLAN_IFACE" || true
  fi
}

usage() {
  cat <<'USO'
Uso: wlan_autonomo.sh <accion> [opciones]

Acciones:
  apply --ssid "SSID" --psk "PASS" [--iface wlanX]   Prepara la interfaz para ser autonoma
  restore                                               Revierte los cambios y devuelve el control a NetworkManager
  status [--iface wlanX]                                Muestra el estado actual
  help                                                  Muestra esta ayuda

Ejemplos:
  sudo ./wlan_autonomo.sh apply --ssid "MiWiFi" --psk "MiClave"
  sudo ./wlan_autonomo.sh status
  sudo ./wlan_autonomo.sh restore
USO
}

main() {
  local action="${1:-}" || true
  case "$action" in
    apply)
      shift || true
      apply_guard "$@"
      ;;
    restore)
      restore_guard
      ;;
    status)
      shift || true
      if [ "${1:-}" = "--iface" ]; then
        WLAN_IFACE="$2"
        WPACFG_FILE="${WPACFG_PREFIX}-${WLAN_IFACE}.conf"
        shift 2
      fi
      show_status
      ;;
    help|""|-h|--help)
      usage
      ;;
    *)
      warn "Accion desconocida: $action"
      usage
      exit 1
      ;;
  esac
}

main "$@"
