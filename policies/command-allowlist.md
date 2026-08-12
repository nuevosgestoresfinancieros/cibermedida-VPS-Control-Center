# Command Allowlist

Allowlist documental para Fase 1 de inventario READ ONLY. Esta política no es todavía código ejecutable y no concede permisos por sí misma. La implementación futura deberá convertirla en reglas verificables y contextualizadas.

## Principios

- Fase 1 solo puede observar y normalizar metadatos mínimos.
- Ningún comando permitido puede modificar el sistema.
- Ningún comando puede leer secretos, claves privadas, credenciales, backups, dumps ni logs crudos.
- Los comandos `READ_SENSITIVE` requieren autorización humana específica antes de ejecutarse.
- Los comandos `READ_PRIVILEGED` requieren autorización humana específica y `sudo`.
- Los comandos `FORBIDDEN` no pueden utilizarse durante Fase 1.
- Los resultados deben redactarse antes de exponerse a un modelo IA o almacenarse en `INVENTORY.json`.
- `source_refs` debe guardar identificadores lógicos de comandos, nunca salidas crudas.

## A. READ_SAFE

| ID lógico | Comando / patrón | Requiere sudo | Datos obtenidos | Riesgo | Redacción requerida |
|---|---|---:|---|---|---|
| `git_status_project` | `git status --short --branch` en repos autorizados | No | Rama y estado de cambios | Bajo | Redactar rutas si contienen nombres sensibles |
| `git_log_project` | `git log --oneline -n <limit>` en repos autorizados | No | Commits recientes | Bajo | No incluir mensajes si contienen secretos; limitar líneas |
| `git_diff_project` | `git diff --stat` en repos autorizados | No | Resumen de cambios | Bajo | No guardar diff completo en inventario |
| `disk_usage` | `df -B1 --output=source,fstype,size,used,avail,pcent,target` | No | Uso de filesystems montados | Bajo | Redactar mounts sensibles si aparecen |
| `memory_usage` | `free -b` | No | RAM y swap | Bajo | Ninguna |
| `uptime` | `uptime` | No | Uptime y carga resumida | Bajo | Ninguna |
| `systemd_status_unit` | `systemctl status <unit> --no-pager` | No | Estado acotado de unidad conocida | Bajo/medio | No guardar logs embebidos; extraer solo estado |
| `docker_ps` | `docker ps --format <campos_aprobados>` | No | Contenedores en ejecución, imagen, estado y puertos publicados | Medio | No incluir env, labels, mounts ni inspect crudo |
| `pm2_status` | `pm2 status` | No | Procesos PM2 y estado | Medio | No guardar paths o argumentos sensibles |
| `health_check_safe` | `curl --fail --silent --show-error --max-time <n> <health_url_aprobada>` | No | Estado de health check | Bajo | No guardar body salvo valor no sensible aprobado |

## B. READ_SENSITIVE

| ID lógico | Comando / patrón | Requiere sudo | Datos obtenidos | Riesgo | Redacción requerida |
|---|---|---:|---|---|---|
| `os_release` | Lectura de `/etc/os-release` mediante parser acotado | No | Nombre y versión de SO | Bajo | No aplica |
| `kernel_version` | `uname -r` / `uname -m` | No | Kernel y arquitectura | Bajo | No aplica |
| `cpu_summary` | `lscpu` con campos aprobados | No | CPU, cores, arquitectura | Bajo | No incluir flags si no son necesarias |
| `systemd_list_units` | `systemctl list-units --type=service --all --no-pager` | No | Servicios y estado | Medio | No incluir propiedades ni environment |
| `systemd_list_unit_files` | `systemctl list-unit-files --type=service --no-pager` | No | Enabled/disabled de servicios | Medio | No incluir contenido de unidades |
| `ports_summary` | `ss` con formato limitado, sin usuarios ni args | No | Puertos y procesos resumidos | Medio/alto | Redactar IPs; no usar `-e`; no guardar PIDs si no son necesarios |
| `apache_sites_summary` | `apachectl -S` | No | VHosts y puertos Apache | Medio/alto | Redactar dominios/rutas si política lo exige |
| `journal_unit_limited` | `journalctl -u <unit> --since <bounded> -n <limit> --no-pager` | No | Logs mínimos de unidad autorizada | Alto | Redacción obligatoria; no guardar salida cruda |
| `runtime_version` | `<runtime> --version` para runtimes aprobados | No | Versiones de Node, PHP, Python, Java u otros | Bajo | No aplica |
| `repository_remote` | `git remote -v` en repos autorizados | No | URL remota | Medio | Redactar credenciales y tokens en URL |

## C. READ_PRIVILEGED

| ID lógico | Comando / patrón | Requiere sudo | Datos obtenidos | Riesgo | Redacción requerida |
|---|---|---:|---|---|---|
| `apache_enabled_sites_privileged` | Lectura acotada de metadatos de sitios Apache no accesibles sin privilegios | Sí | Sitios habilitados y rutas | Alto | No leer secretos; redactar rutas/dominios si aplica |
| `certificate_public_metadata` | Lectura de metadatos públicos de certificados TLS | Sí | Subject, issuer, expiración | Alto | Nunca leer `privkey.pem`; dominios pueden redactarse |
| `firewall_summary` | Resumen no destructivo de firewall aprobado | Sí | Política y puertos permitidos resumidos | Alto | Redactar IPs/redes; no volcar ruleset completo |
| `backup_catalog_metadata` | Lectura de catálogo de backups aprobado, sin abrir backups | Sí | Fechas, tamaños, checksums si no son secretos | Alto | No leer contenidos; redactar destinos/rutas |
| `service_metadata_privileged` | Lectura acotada de metadatos de servicios no accesibles sin privilegios | Sí | Estado y configuración mínima | Alto | No leer `Environment`, credenciales ni logs crudos |

## D. FORBIDDEN

Estos comandos y patrones no pueden utilizarse durante Fase 1:

- lectura de `.env`, `.env.*` o equivalentes;
- lectura de variables de entorno de procesos: `env`, `printenv`, `set`, `/proc/*/environ`, `ps eww`;
- claves privadas SSH, TLS, GPG, WireGuard o VPN;
- `/etc/shadow`;
- `/etc/gshadow`;
- historial shell: `.bash_history`, `.zsh_history`, `.mysql_history`;
- logs crudos: `cat /var/log/*`, `journalctl` sin unidad, sin intervalo o sin límite de líneas;
- backups, dumps SQL y archivos comprimidos de datos;
- `docker inspect` sin filtros estrictos que excluyan env, labels sensibles, mounts sensibles y secrets;
- `ps` con argumentos completos;
- lectura recursiva de `/home`;
- `authorized_keys` y claves SSH de usuarios;
- `sudo -l`;
- `mysql -e 'SHOW DATABASES'` o consultas equivalentes sin política específica de minimización;
- firewall completo: `iptables-save`, `nft list ruleset`, volcados completos de UFW/nftables/iptables;
- `cat /etc/machine-id` sin redacción o hash irreversible aprobado;
- cualquier comando que modifique el sistema, reinicie servicios, cambie configuración, instale paquetes, elimine datos, despliegue, haga rollback o escriba fuera del proyecto autorizado.

## Representación En Inventario

Cada dato persistido debe registrar:

- `collection_status`;
- `sensitivity_level`;
- `source_refs` con ID lógico de comando;
- errores no sensibles, cuando existan;
- exclusiones explícitas como `excluded_for_security`.

`INVENTORY.json` nunca debe contener salidas crudas de comandos.
