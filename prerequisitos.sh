#!/bin/bash

# -----------------------------------------------------------------------------
# Script: prerequisitos.sh
# Función: automatiza la preparación del entorno para usar el bypass NAC.
#   - Comprueba paquetes base y los instala si faltan.
#   - Verifica que el módulo de kernel br_netfilter esté cargado y persistente.
#   - Muestra las interfaces de red disponibles con sugerencias de uso.
#   - Revisa que los scripts principales existan y tengan permisos de ejecución.
#   - Valida que estén disponibles las herramientas esenciales (apt-get, modprobe, ip, etc.).
#   - Comprueba datos básicos del sistema (distribución, número de interfaces útiles, etc.).
#   - DETECTA Y ELIMINA AVAHI (mDNS/ZeroConf) si está instalado/activo.
# -----------------------------------------------------------------------------

set -euo pipefail

PAQUETES=(
  bridge-utils
  ethtool
  macchanger
  arptables
  ebtables
  iptables
  net-tools
  tcpdump
)

ARCHIVOS_SCRIPT=(
  "nac_bypass_setup.sh"
  "awareness.sh"
)

COMANDOS_BASE=(
  "apt-get"
  "modprobe"
  "ip"
  "lsmod"
  "dpkg"
  "chmod"
  "systemctl"
  "timedatectl"
  "ifconfig"
  "brctl"
  "tcpdump"
  "sysctl"
  "ethtool"
)

SERVICIOS_RED=(
  "NetworkManager.service"
  "network-manager.service"
  "systemd-networkd.service"
)

COLOR_INFO="\e[1;34m"
COLOR_OK="\e[1;32m"
COLOR_WARN="\e[1;31m"
COLOR_RESET="\e[0m"

requerir_root() {
  if [ "${EUID}" -ne 0 ]; then
    echo -e "${COLOR_WARN}[!] Ejecuta este script como root (usa sudo).${COLOR_RESET}"
    exit 1
  fi
}

info() {
  echo -e "${COLOR_INFO}[*] $1${COLOR_RESET}"
}

ok() {
  echo -e "${COLOR_OK}[+] $1${COLOR_RESET}"
}

warn() {
  echo -e "${COLOR_WARN}[!] $1${COLOR_RESET}"
}

verificar_os() {
  info "Comprobando información del sistema..."

  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    local nombre="${NAME:-Desconocido}"
    local version="${VERSION_ID:-}"
    info "Sistema detectado: ${nombre} ${version}"

    local base="${ID_LIKE:-$ID}"
    if [[ "${base,,}" != *"debian"* && "${ID,,}" != "debian" && "${ID,,}" != "ubuntu" ]]; then
      warn "Este script se probó en sistemas tipo Debian/Ubuntu; revisa comandos manualmente si usas otra distribución."
    fi
  else
    warn "No se encontró /etc/os-release. No se pudo identificar la distribución."
  fi
}

verificar_comandos_base() {
  info "Comprobando comandos básicos disponibles en el sistema..."
  local faltan=()

  for cmd in "${COMANDOS_BASE[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
      ok "Comando encontrado: $cmd"
    else
      warn "No se encontró el comando: $cmd"
      faltan+=("$cmd")
    fi
  done

  if [ "${#faltan[@]}" -gt 0 ]; then
    warn "Faltan comandos básicos: ${faltan[*]}."
    warn "Instala los paquetes necesarios o ajusta el PATH antes de continuar."
  fi
}

instalar_paquetes() {
  info "Verificando paquetes necesarios..."
  local faltan=()

  for pkg in "${PAQUETES[@]}"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
      ok "Paquete presente: $pkg"
    else
      warn "Falta el paquete: $pkg"
      faltan+=("$pkg")
    fi
  done

  if [ "${#faltan[@]}" -gt 0 ]; then
    if command -v apt-get >/dev/null 2>&1; then
      info "Instalando paquetes faltantes: ${faltan[*]}"
      apt-get update
      apt-get install -y "${faltan[@]}"
    else
      warn "apt-get no está disponible. Instala manualmente: ${faltan[*]}"
    fi
  else
    info "No hay paquetes pendientes."
  fi
}

asegurar_modulo() {
  local modulo="br_netfilter"
  info "Comprobando módulo de kernel $modulo..."

  if lsmod | grep -qw "$modulo"; then
    ok "El módulo $modulo ya está cargado."
  else
    warn "El módulo $modulo no está cargado. Intentando cargarlo."
    modprobe "$modulo"
    ok "Módulo $modulo cargado con éxito."
  fi

  local modules_file="/etc/modules"
  if grep -E "^${modulo}$" "$modules_file" >/dev/null 2>&1; then
    info "El módulo $modulo ya está configurado para cargarse al iniciar."
  else
    info "Añadiendo $modulo a $modules_file para cargarlo en cada arranque."
    echo "$modulo" >> "$modules_file"
    ok "Módulo $modulo persistente configurado."
  fi
}

detectar_interfaces() {
  info "Detectando interfaces de red disponibles..."

  if ! command -v ip >/dev/null 2>&1; then
    warn "El comando 'ip' no está disponible; no se pueden listar interfaces."
    return
  fi

  local interfaces
  interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$')

  if [ -z "$interfaces" ]; then
    warn "No se encontraron interfaces de red distintas de lo."
    return
  fi

  echo ""
  echo "Interfaces detectadas:"
  local contador=1
  local total=0
  local recommended_switch=""
  local recommended_victim=""
  local wifi_present=0
  local -a resumenes=()

  while IFS= read -r iface; do
    local detalle
    detalle=$(ip -o -4 addr show "$iface" | awk '{print $4}' || true)

    local carrier_val=""
    local carrier_text="estado de link desconocido"
    if [ -f "/sys/class/net/$iface/carrier" ]; then
      carrier_val=$(cat "/sys/class/net/$iface/carrier" 2>/dev/null || echo "")
      if [ "$carrier_val" = "1" ]; then
        carrier_text="link activo"
      elif [ "$carrier_val" = "0" ]; then
        carrier_text="sin link"
      fi
    fi

    local tipo="cableada"
    if [[ "$iface" == wl* || "$iface" == wifi* ]]; then
      tipo="inalámbrica"
      wifi_present=1
    fi

    local linea="  $contador) $iface -> ${tipo}, ${carrier_text}"
    if [ -n "$detalle" ]; then
      linea="$linea, IPs: $detalle"
    else
      linea="$linea, sin IP asignada ahora mismo"
    fi

    resumenes+=("$linea")

    if [ "$tipo" = "cableada" ]; then
      if [ "$carrier_val" = "1" ] && [ -z "$recommended_switch" ]; then
        recommended_switch="$iface"
      fi
      if [ -z "$detalle" ] && [ "$carrier_val" != "1" ] && [ -z "$recommended_victim" ]; then
        recommended_victim="$iface"
      fi
    fi

    contador=$((contador + 1))
    total=$((total + 1))
  done <<< "$interfaces"

  for linea in "${resumenes[@]}"; do
    echo "$linea"
  done

  if [ "$total" -lt 2 ]; then
    warn "Se detectaron solo $total interfaz(es) útil(es). El bypass requiere al menos dos (switch y víctima)."
  else
    info "Total de interfaces útiles detectadas: $total"
  fi

  echo ""
  echo "Sugerencias automáticas:"
  if [ -n "$recommended_switch" ]; then
    echo "  - Lado switch sugerido: $recommended_switch (cableada, link activo)."
  else
    echo "  - Lado switch sugerido: conecta un cable y vuelve a ejecutar el script; no se detectó interfaz cableada con link activo."
  fi

  if [ -n "$recommended_victim" ]; then
    echo "  - Lado víctima sugerido: $recommended_victim (cableada sin IP asignada, ideal para la máquina víctima)."
  else
    echo "  - Lado víctima sugerido: usa una interfaz cableada sin IP (por ejemplo, desconecta y reintenta con otra NIC)."
  fi

  if [ "$wifi_present" -eq 1 ]; then
    echo "  - Se detectó al menos una interfaz inalámbrica; evita usarla para el puente, necesita interfaces Ethernet."
  fi

  echo "  - Si tienes dudas, ejecuta 'sudo ethtool <interfaz>' para comprobar el estado del enlace."
}

preparar_scripts() {
  info "Revisando scripts principales en el directorio actual..."
  local faltantes=()

  for script in "${ARCHIVOS_SCRIPT[@]}"; do
    if [ -f "$script" ]; then
      ok "Encontrado: $script"
      if [ ! -x "$script" ]; then
        info "Asignando permisos de ejecución a $script"
        chmod +x "$script"
        ok "Permisos de ejecución aplicados a $script"
      else
        info "$script ya tiene permisos de ejecución."
      fi
    else
      warn "No se encontró el archivo $script en $(pwd)."
      faltantes+=("$script")
    fi
  done

  if [ "${#faltantes[@]}" -gt 0 ]; then
    warn "Copia los archivos faltantes antes de continuar: ${faltantes[*]}"
  fi
}

revisar_servicios_interferentes() {
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl no está disponible; no se puede verificar el estado de servicios de red."
    return
  fi

  info "Revisando servicios de red que podrían interferir con la configuración manual..."
  local detectados=0

  for svc in "${SERVICIOS_RED[@]}"; do
    if systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Fxq "$svc"; then
      local estado=$(systemctl is-active "$svc" 2>/dev/null || true)
      local habilitado=$(systemctl is-enabled "$svc" 2>/dev/null || true)

      if [ "$estado" = "active" ]; then
        warn "Servicio activo detectado: $svc (se detendrá durante el bypass)."
        detectados=1
      fi

      if [ "$habilitado" = "enabled" ]; then
        info "El servicio $svc está habilitado. Considera deshabilitarlo si deseas un entorno más estático."
      fi
    fi
  done

  if [ "$detectados" -eq 0 ]; then
    info "No se detectaron servicios de red activos que interfieran de inmediato."
  fi
}

# ---------------------------
# Nueva función: disable_avahi
# - Para/disable/mask Avahi si está activo
# - Intenta desinstalar paquetes avahi-daemon y avahi-utils vía apt-get si está disponible
# - Comprueba si el puerto mDNS (UDP 5353) queda libre después
# ---------------------------
disable_avahi() {
  info "Comprobando presencia de Avahi (mDNS/ZeroConf)..."

  # Necesitamos systemctl y dpkg para verificar estado/instalación
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl no disponible: solo se hará una comprobación mediante dpkg/ps/ss."
  fi

  local instalado=0
  if dpkg -s avahi-daemon >/dev/null 2>&1 || dpkg -s avahi-utils >/dev/null 2>&1; then
    instalado=1
  fi

  if [ "$instalado" -eq 0 ]; then
    info "Avahi no parece estar instalado (no se encontraron paquetes avahi-daemon/avahi-utils)."
  else
    info "Avahi detectado: procederemos a detener, deshabilitar, enmascarar y (opcionalmente) desinstalar."
    # detener y deshabilitar (si systemctl disponible)
    if command -v systemctl >/dev/null 2>&1; then
      info "Parando avahi (systemctl)..."
      systemctl stop avahi-daemon.service avahi-daemon.socket >/dev/null 2>&1 || true
      info "Deshabilitando avahi para arranque futuro..."
      systemctl disable avahi-daemon.service avahi-daemon.socket >/dev/null 2>&1 || true
      info "Enmascarando avahi para evitar reactivaciones..."
      systemctl mask avahi-daemon.service avahi-daemon.socket >/dev/null 2>&1 || true
    else
      info "systemctl no disponible; intentaremos finalizar procesos manualmente."
      pkill -f avahi-daemon || true
    fi

    # intento de desinstalación vía apt-get si existe
    if command -v apt-get >/dev/null 2>&1; then
      info "Desinstalando paquetes avahi (apt-get)..."
      apt-get update
      apt-get remove --purge -y avahi-daemon avahi-utils || warn "Fallo al eliminar paquetes avahi con apt-get."
      apt-get autoremove --purge -y || true
      ok "Comando de desinstalación ejecutado (si los paquetes estaban presentes)."
    else
      warn "apt-get no está disponible: avahi desactivado pero no desinstalado."
    fi
  fi

  # comprobaciones finales: procesos y puerto UDP 5353
  if pgrep -af avahi-daemon >/dev/null 2>&1; then
    warn "Se detectan procesos avahi-daemon aún activos. Intentando finalizarlos..."
    pkill -f avahi-daemon || true
  fi

  if command -v ss >/dev/null 2>&1; then
    if ss -lunp 2>/dev/null | grep -q ":5353"; then
      warn "Puerto UDP 5353 (mDNS) sigue en uso. Revisa procesos activos manualmente."
    else
      ok "Puerto UDP 5353 no detectado: mDNS parece inactivo."
    fi
  else
    info "No se puede comprobar puerto 5353: 'ss' no disponible."
  fi
}

main() {
  requerir_root
  verificar_os
  verificar_comandos_base
  instalar_paquetes
  asegurar_modulo
  detectar_interfaces
  preparar_scripts
  revisar_servicios_interferentes

  # Llamada añadida: detectar y eliminar Avahi si existe
  disable_avahi

  ok "Listo. Ya tienes el entorno preparado para lanzar los scripts del bypass."
}

main "$@"
