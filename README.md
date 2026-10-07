# sca-gate

Acción de GitHub que escanea las dependencias de una pull request con Trivy y OSV-Scanner, une sus hallazgos por los alias de OSV y decide si la PR puede entrar según CISA KEV y EPSS. Si una herramienta falla, la puerta da ERROR en vez de dar el repositorio por limpio.

Forma parte del TFG *Análisis automatizado de vulnerabilidades en dependencias de software* (UPV/EHU).

## Versiones

| Herramienta | Versión | Cuándo se usa |
|---|---|---|
| Trivy | 0.72.0 | PR y nocturno |
| OSV-Scanner | 2.4.0 | PR y nocturno |
| OWASP Dependency-Check | 12.2.2 | nocturno |

Cada binario se comprueba contra el SHA256 guardado en `sca_gate.py` antes de ejecutarlo. Necesita `ubuntu-24.04` (Linux x86_64 y Python 3.11 o superior).

## Uso

1. Copiar `ejemplos/sca-gate-pr.yml` y `ejemplos/sca-gate-nocturno.yml` en `.github/workflows/`.
2. Cambiar `SHA_DE_SCA_GATE` por el commit de este repositorio que se quiera usar (no una etiqueta, que se puede mover).
3. Crear el secreto `NVD_API_KEY` para el escaneo nocturno.
4. Marcar `sca-gate / escanear` como comprobación obligatoria en la protección de la rama.

La PR recibe un comentario con el informe. El escaneo nocturno abre una incidencia si la rama principal bloquea y la cierra cuando deja de hacerlo.

### Política

| Nivel | Cuándo |
|---|---|
| BLOQUEO | paquete malicioso (`MAL-`), CVE en CISA KEV, o EPSS ≥ 0,1 en una dependencia de ejecución |
| AVISO | EPSS ≥ 0,01, EPSS ≥ 0,1 en desarrollo, CVE sin EPSS todavía |
| SIN_CVE | no tiene CVE, así que no se puede valorar con EPSS ni KEV |
| INFO | EPSS < 0,01 |

En una PR solo bloquea lo que introduce la propia PR; lo que ya estaba en la rama base baja a aviso. Los umbrales se cambian con `epss-bloqueo` y `epss-aviso`, y `modo: avisar` hace que nunca falle por hallazgos.

### Excepciones

En `.sca-excepciones.toml`, en la raíz del repositorio. En una PR se leen las de la rama base, así que una PR no puede eximirse a sí misma. Los ficheros `osv-scanner.toml`, `.trivyignore` y `trivy.yaml` no se aplican.

```toml
[[excepcion]]
id = "CVE-2020-11023"
paquete = "jquery"
motivo = "solo en la documentación estática, no alcanzable"
caduca = 2027-03-15
```

### Remediación con Dependabot

Activar *Dependabot security updates* en el repositorio y añadir `.github/dependabot.yml` con solo actualizaciones de seguridad.

```yaml
version: 2
updates:
  - package-ecosystem: "npm"   # o pip, maven
    directory: "/"
    schedule: { interval: "daily" }
    open-pull-requests-limit: 0
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule: { interval: "weekly" }
```

## En local

```
python3 sca_gate.py instalar --dir ~/.sca-gate
python3 sca_gate.py escanear --ruta ./repo --salida informe --bin ~/.sca-gate/bin
python3 sca_gate.py decidir --salida informe
```

`decidir` se puede repetir sobre el mismo escaneo con otra instantánea (`--epss-fichero`, `--kev-fichero`). El informe, las salidas de cada herramienta, el SBOM CycloneDX y las instantáneas de EPSS y KEV quedan en la carpeta de salida.

## Validación

`.github/workflows/validacion.yml` pasa las pruebas (`python3 -m unittest test_sca_gate.py`).

`.github/workflows/holdout.yml` escanea los 6 repositorios de reserva del TFG, que no se usaron para diseñar la herramienta, y compara la decisión de cada uno con la de la misma política aplicada a su ground truth (`validacion/holdout.json`) con la misma instantánea de EPSS y KEV.

`validacion/esperado.json` es el ground truth de los 12 repositorios sintéticos con los que se diseñó. Son privados, así que se comprueban en local escaneando cada uno y pasando el informe a `validacion/validar.py comprobar`.
