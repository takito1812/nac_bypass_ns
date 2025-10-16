#!/bin/bash

###############################################################################
# Nombre: awareness.sh
# Descripción: Supervisa el estado de una interfaz de red y ajusta la
#              configuración del bypass NAC cuando detecta cambios.
# Uso: ./awareness.sh [-i <interfaz>] [-h]
# Dependencias: bash, herramientas básicas GNU, nac_bypass_setup.sh
###############################################################################

# Versión del script, útil para depuración y soporte.
VERSION="0.1.1-1746786622"

# Configuración básica que controla cómo se vigila la interfaz.
INTERFAZ_RED="eth0"
ESTADO_ANTERIOR_INTERFAZ=0
CONTADOR_CAMBIO_ESTADO=0
UMBRAL_ACTIVACION=3
UMBRAL_DESACTIVACION=5
INTERVALO_ESPERA="5s"

# Ruta absoluta al directorio donde vive este script y los auxiliares.
DIRECTORIO_SCRIPT=$(dirname "$(readlink -f "$0")")

# Muestra la ayuda con una descripción rápida de los parámetros disponibles.
mostrar_ayuda() {
  echo -e "$0 v$VERSION uso:"
  echo "    -h          muestra esta ayuda"
  echo "    -i <eth>    interfaz de red conectada al switch"
  exit 0
}

# Informa únicamente la versión del script.
mostrar_version() {
  echo -e "$0 v$VERSION"
  exit 0
}

# Lee las opciones pasadas por línea de comandos y ajusta la configuración.
analizar_argumentos() {
  while getopts ":hi:" option; do
    case "$option" in
      h)
        mostrar_ayuda
        ;;
      i)
        INTERFAZ_RED=$OPTARG
        ;;
      *)
        INTERFAZ_RED="eth0"
        ;;
    esac
  done
}

# Ejecuta la primera fase del bypass NAC para dejar todo listo.
ejecutar_configuracion_inicial() {
  bash "${DIRECTORIO_SCRIPT}/nac_bypass_setup.sh" -a -i
}

# Devuelve el estado físico de la interfaz (1 = activa, 0 = inactiva).
leer_estado_interfaz() {
  local archivo_enlace="/sys/class/net/${INTERFAZ_RED}/carrier"
  cat "$archivo_enlace"
}

# Decide qué hacer ante el estado actual: informar o relanzar fases del bypass.
aplicar_acciones_estado() {
  local estado_actual=$1

  if [[ $estado_actual -ne $ESTADO_ANTERIOR_INTERFAZ ]]; then
    CONTADOR_CAMBIO_ESTADO=0

    if [[ $estado_actual -eq 1 ]]; then
      echo "[!] ¡${INTERFAZ_RED} está activo!"
    else
      echo "[!] ¡${INTERFAZ_RED} está inactivo!"
    fi
    return
  fi

  if [[ $CONTADOR_CAMBIO_ESTADO -eq $UMBRAL_ACTIVACION && $estado_actual -eq 1 ]]; then
    echo "[!!] Establecer nueva configuración"
    bash "${DIRECTORIO_SCRIPT}/nac_bypass_setup.sh" -a -c
  elif [[ $CONTADOR_CAMBIO_ESTADO -eq $UMBRAL_DESACTIVACION && $estado_actual -eq 0 ]]; then
    echo "[!!] Restablecer configuración"
    bash "${DIRECTORIO_SCRIPT}/nac_bypass_setup.sh" -a -r
    bash "${DIRECTORIO_SCRIPT}/nac_bypass_setup.sh" -a -i
  fi

  echo "[*] Esperando"
  ((CONTADOR_CAMBIO_ESTADO++))
}

# Flujo principal: interpretar parámetros, configurar y mantener la vigilancia.
analizar_argumentos "$@"
ejecutar_configuracion_inicial

while true; do
  ESTADO_INTERFAZ_ACTUAL=$(leer_estado_interfaz)
  aplicar_acciones_estado "$ESTADO_INTERFAZ_ACTUAL"
  ESTADO_ANTERIOR_INTERFAZ=$ESTADO_INTERFAZ_ACTUAL
  sleep "$INTERVALO_ESPERA"
done
