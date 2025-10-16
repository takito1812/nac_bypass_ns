Este repositorio extiende el **NAC Bypass** de [scipag](https://github.com/scipag/nac_bypass) sin modificar su funcionamiento original. Mantiene flags, dependencias y flujo intactos, permitiendo una integración directa.

## Mejoras clave

* **Monitoreo EAPOL en tiempo real:** durante la `fase_inicial`, se ejecuta `tcpdump` para capturar tráfico 802.1X y analizar la autenticación antes de proceder.
* **Namespace aislado (`bypass`):** el script `nac_bypass_setup_ns.sh` crea una interfaz `macvlan` dentro de un namespace, bloqueando el acceso desde el host al bridge (`br0`). Todo el tráfico del bypass queda contenido, evitando fugas de la MAC del atacante.
* **Prevención de cierre de puerto en el switch:** encapsular la MAC/IP legítima dentro del namespace y bloquear el acceso al bridge evita que el switch detecte actividad anómala, previniendo errores como `security-violation` o que el puerto entre en estado `err-disable`.
* **Limpieza completa (`-r`):** elimina bridge, reglas, namespace y configuraciones residuales, dejando el sistema limpio para nuevos intentos.

**Resumen:** respeta la lógica original de scipag, pero añade aislamiento de red, prevención de fugas de MAC y una rutina de limpieza. Ideal para evasión de NAC sigilosa y reutilizable en ejercicios de Red Team.
