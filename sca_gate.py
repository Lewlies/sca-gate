#!/usr/bin/env python3
"""sca-gate. Puerta de seguridad de dependencias para pull requests.

    python3 sca_gate.py instalar --dir DIR [--herramientas trivy,osv-scanner]
    python3 sca_gate.py escanear --ruta REPO --salida DIR --bin DIR [--herramientas ...]
    python3 sca_gate.py decidir --salida DIR [--base DIR] [--excepciones FICHERO] ...
"""

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Mismas versiones que el banco de pruebas del TFG. El SHA256 se compara con este
# valor y no con el fichero de checksums de la release, que se puede cambiar a la vez.
HERRAMIENTAS = {
    "trivy": {
        "version": "0.72.0",
        "url": "https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_Linux-64bit.tar.gz",
        "sha256": "bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea",
    },
    "osv-scanner": {
        "version": "2.4.0",
        "url": "https://github.com/google/osv-scanner/releases/download/v2.4.0/osv-scanner_linux_amd64",
        "sha256": "15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0",
    },
    "dependency-check": {
        "version": "12.2.2",
        "url": "https://github.com/dependency-check/DependencyCheck/releases/download/v12.2.2/dependency-check-12.2.2-release.zip",
        "sha256": "bf07fefd81af3094c5f6850423b014df44db62ce2dbad0f79079a90df675e44a",
    },
}
VETADAS = {"trivy": ["0.69.4"]}  # version publicada por el atacante de trivy-action

KEV_URLS = ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"]
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_API = "https://api.first.org/data/v1/epss?cve="
OSV_API = "https://api.osv.dev/v1/vulns/"

OK, PARCIAL, SIN_FUENTES, FALLO = "OK", "PARCIAL", "SIN_FUENTES", "FALLO"
NIVELES = ["BLOQUEO", "AVISO", "SIN_CVE", "INFO", "EXCEPTUADO", "RETIRADA"]

MANIFIESTOS = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
               "pyproject.toml", "setup.py", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock",
               "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"}
CONFIG_ESCANERES = {"osv-scanner.toml", ".trivyignore", ".trivyignore.yaml", "trivy.yaml"}
IGNORAR_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}

ECO_TRIVY = {"yarn": "npm", "pnpm": "npm", "node-pkg": "npm", "pip": "pypi", "pipenv": "pypi",
             "poetry": "pypi", "uv": "pypi", "python-pkg": "pypi", "pom": "maven", "gradle": "maven",
             "jar": "maven", "gomod": "golang", "bundler": "gem"}
ECO_OSV = {"go": "golang", "crates.io": "cargo", "rubygems": "gem", "packagist": "composer"}


def descargar(url, timeout=120, intentos=3):
    error = None
    for i in range(intentos):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sca-gate"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise
            error = e
        except (urllib.error.URLError, OSError) as e:
            error = e
        time.sleep(2 * (i + 1))
    raise RuntimeError(f"no se pudo descargar {url} ({error})")


def leer_json(ruta):
    """Devuelve (datos, estado). Un fichero vacio no es un resultado limpio."""
    p = Path(ruta)
    if not p.is_file():
        return None, "no existe"
    if p.stat().st_size == 0:
        return None, "vacio"
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace")), "ok"
    except json.JSONDecodeError:
        return None, "invalido"


def norm_id(v):
    # OSV distingue mayusculas y un GHSA en mayusculas da 404
    if not v:
        return None
    s = str(v).strip()
    if s.upper().startswith("GHSA-"):
        return "GHSA-" + s[5:].lower()
    return s.upper()


def norm_paquete(eco, nombre):
    n = urllib.parse.unquote(str(nombre or "")).strip()
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", n).lower()
    if eco == "maven":
        return n.replace("/", ":").lower()
    return n.lower()


def purl(p):
    """pkg:maven/org.yaml/snakeyaml@1.33 -> ('maven', 'org.yaml:snakeyaml', '1.33')"""
    if not p or not str(p).startswith("pkg:"):
        return None, None, None
    cuerpo = str(p)[4:].split("?")[0].split("#")[0]
    tipo, _, resto = cuerpo.partition("/")
    ruta, _, version = resto.rpartition("@")
    if not ruta:
        ruta, version = resto, ""
    partes = [urllib.parse.unquote(x) for x in ruta.split("/") if x]
    if tipo == "maven" and len(partes) >= 2:
        nombre = partes[-2] + ":" + partes[-1]
    else:
        nombre = "/".join(partes)
    return tipo, norm_paquete(tipo, nombre), urllib.parse.unquote(version)


def relativa(ruta, raiz):
    if not ruta:
        return None
    r = str(ruta).replace("\\", "/")
    raiz = str(raiz).rstrip("/")
    for c in (raiz, raiz.lstrip("/")):
        if r.startswith(c + "/"):
            r = r[len(c) + 1:]
    return r.lstrip("/") or "."


def decimal(x, cifras=3):
    if x is None:
        return "-"
    return (f"{x:.{cifras}f}".rstrip("0").rstrip(".") or "0").replace(".", ",")


def instalar(nombres, destino):
    destino = Path(destino).resolve()
    (destino / "bin").mkdir(parents=True, exist_ok=True)
    for nombre in nombres:
        h = HERRAMIENTAS[nombre]
        if h["version"] in VETADAS.get(nombre, []):
            sys.exit(f"{nombre} {h['version']} esta vetada")
        datos = descargar(h["url"], timeout=300)
        obtenido = hashlib.sha256(datos).hexdigest()
        if obtenido != h["sha256"]:
            sys.exit(f"SHA256 de {nombre} no coincide (esperado {h['sha256']}, obtenido {obtenido}). No se ejecuta.")
        carpeta = destino / nombre
        shutil.rmtree(carpeta, ignore_errors=True)
        carpeta.mkdir()
        fichero = carpeta / Path(h["url"]).name
        fichero.write_bytes(datos)
        if nombre == "trivy":
            with tarfile.open(fichero) as t:
                (carpeta / "trivy").write_bytes(t.extractfile("trivy").read())
            exe = carpeta / "trivy"
        elif nombre == "osv-scanner":
            exe = fichero
        else:
            with zipfile.ZipFile(fichero) as z:
                if any(n.startswith("/") or ".." in Path(n).parts for n in z.namelist()):
                    sys.exit("zip de dependency-check con rutas sospechosas")
                z.extractall(carpeta)
            exe = carpeta / "dependency-check" / "bin" / "dependency-check.sh"
        exe.chmod(0o755)
        enlace = destino / "bin" / nombre
        enlace.unlink(missing_ok=True)
        enlace.symlink_to(exe)
        print(f"{nombre} {h['version']} instalado y verificado")


def entorno_sin_secretos():
    sensibles = ("TOKEN", "SECRET", "PASSWORD", "KEY", "CREDENTIAL")
    return {k: v for k, v in os.environ.items() if not any(s in k.upper() for s in sensibles)}


def correr(cmd, salida, nombre, cwd, env, timeout):
    t0 = time.time()
    reg = {"comando": [str(c) for c in cmd], "codigo": None, "error": None}
    try:
        with open(salida / f"{nombre}.stdout.txt", "wb") as o, open(salida / f"{nombre}.stderr.txt", "wb") as e:
            reg["codigo"] = subprocess.run([str(c) for c in cmd], stdout=o, stderr=e, cwd=cwd,
                                           env=env, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        reg["error"] = f"timeout tras {timeout} s"
    except OSError as e:
        reg["error"] = f"no se pudo ejecutar ({e})"
    reg["segundos"] = round(time.time() - t0, 1)
    return reg


def escanear(ruta, salida, bindir, herramientas, nvd_api_key=None, dc_datos=None):
    ruta, salida, bindir = Path(ruta).resolve(), Path(salida).resolve(), Path(bindir).resolve()
    crudo = salida / "crudo"
    crudo.mkdir(parents=True, exist_ok=True)
    # Las herramientas leen trivy.yaml, .trivyignore y osv-scanner.toml del repositorio,
    # y una PR podria usarlos para ocultar una vulnerabilidad. Se lanzan desde un
    # directorio vacio y OSV-Scanner recibe una configuracion vacia.
    cache = Path(os.environ.get("RUNNER_TEMP", Path.home() / ".cache")) / "sca-gate-cache"
    vacio = cache / "vacio"
    vacio.mkdir(parents=True, exist_ok=True)
    (cache / "osv-vacio.toml").write_text("")
    env = entorno_sin_secretos()
    registro = {"ruta": str(ruta), "fecha": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                "herramientas": {}}

    for h in herramientas:
        if h == "trivy":
            cmd = [bindir / "trivy", "fs", "--scanners", "vuln", "--format", "json",
                   "--output", crudo / "trivy.json", "--include-dev-deps", "--list-all-pkgs",
                   "--cache-dir", cache / "trivy", "--debug", "--no-progress", ruta]
            reg = correr(cmd, crudo, "trivy", vacio, env, 1500)
            correr([bindir / "trivy", "fs", "--format", "cyclonedx", "--output", salida / "sbom.cdx.json",
                    "--cache-dir", cache / "trivy", "--skip-db-update", ruta],
                   crudo, "trivy-sbom", vacio, env, 600)
            reg["bbdd"] = fecha_bbdd_trivy(bindir, cache / "trivy", vacio, env)
        elif h == "osv-scanner":
            # sin --no-resolve, para que resuelva las transitivas de Maven
            cmd = [bindir / "osv-scanner", "scan", "source", "-r", "--no-ignore", "--all-packages",
                   "--config", cache / "osv-vacio.toml", "--format", "json",
                   "--output-file", crudo / "osv-scanner.json", ruta]
            reg = correr(cmd, crudo, "osv-scanner", vacio, env, 1500)
            reg["bbdd"] = "api.osv.dev en vivo, " + registro["fecha"]
        elif h == "dependency-check":
            datos = Path(dc_datos).expanduser().resolve() if dc_datos else cache / "dependency-check"
            cmd = [bindir / "dependency-check", "--scan", ruta, "--format", "JSON", "--out", crudo,
                   "--data", datos, "--project", "sca-gate"]
            if nvd_api_key:
                cmd += ["--nvdApiKey", nvd_api_key]
            reg = correr(cmd, crudo, "dependency-check", vacio, env, 5400)
            reg["comando"] = [c if c != nvd_api_key else "***" for c in reg["comando"]]
        else:
            sys.exit(f"herramienta desconocida {h}")
        reg["version"] = HERRAMIENTAS[h]["version"]
        registro["herramientas"][h] = reg
        print(f"{h} termino con codigo {reg['codigo']} en {reg['segundos']} s")

    (salida / "escaneo.json").write_text(json.dumps(registro, indent=1))


def fecha_bbdd_trivy(bindir, cache, cwd, env):
    try:
        p = subprocess.run([bindir / "trivy", "version", "--format", "json", "--cache-dir", cache],
                           capture_output=True, cwd=cwd, env=env, timeout=60)
        return (json.loads(p.stdout).get("VulnerabilityDB") or {}).get("UpdatedAt")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def hallazgo(herramienta, vid, alias, eco, paquete, version, fichero, dev=None, severidad=None, retirada=False):
    return {"herramienta": herramienta, "id": vid, "alias": {a for a in map(norm_id, alias) if a},
            "eco": eco or "desconocido", "paquete": paquete, "version": version or "", "fichero": fichero,
            "dev": dev, "severidad": severidad, "retirada": retirada}


def leer_trivy(datos, raiz):
    hallazgos, ficheros = [], set()
    for res in datos.get("Results") or []:
        if res.get("Class") != "lang-pkgs":
            continue
        ficheros.add(relativa(res.get("Target"), raiz))
        dev = {p.get("ID"): p.get("Dev", False) for p in res.get("Packages") or []}
        for v in res.get("Vulnerabilities") or []:
            eco, nombre, _ = purl((v.get("PkgIdentifier") or {}).get("PURL"))
            if not nombre:
                eco = ECO_TRIVY.get(res.get("Type"), res.get("Type"))
                nombre = norm_paquete(eco, v.get("PkgName"))
            hallazgos.append(hallazgo("trivy", norm_id(v.get("VulnerabilityID")), v.get("VendorIDs") or [],
                                      eco, nombre, v.get("InstalledVersion"), relativa(res.get("Target"), raiz),
                                      dev.get(v.get("PkgID"), False), v.get("Severity")))
    return hallazgos, ficheros


def leer_osv(datos, raiz):
    hallazgos, ficheros = [], set()
    for res in datos.get("results") or []:
        fichero = relativa((res.get("source") or {}).get("path"), raiz)
        ficheros.add(fichero)
        for pk in res.get("packages") or []:
            info = pk.get("package") or {}
            eco = ECO_OSV.get(str(info.get("ecosystem")).lower(), str(info.get("ecosystem")).lower())
            grupos = {str(g).lower() for g in pk.get("dependency_groups") or []}
            for v in pk.get("vulnerabilities") or []:
                hallazgos.append(hallazgo("osv-scanner", norm_id(v.get("id")), v.get("aliases") or [], eco,
                                          norm_paquete(eco, info.get("name")), info.get("version"), fichero,
                                          bool(grupos & {"dev", "test"}),
                                          (v.get("database_specific") or {}).get("severity"),
                                          bool(v.get("withdrawn"))))
    return hallazgos, ficheros


def leer_dc(datos, raiz):
    hallazgos, ficheros = [], set()
    for d in datos.get("dependencies") or []:
        fichero = relativa(d.get("filePath"), raiz)
        ficheros.add(fichero)
        eco = nombre = version = None
        for p in d.get("packages") or []:
            eco, nombre, version = purl(p.get("id"))
            if nombre:
                break
        for v in d.get("vulnerabilities") or []:
            vid = norm_id(v.get("name"))
            if vid and " " not in vid:  # RetireJS a veces pone texto libre como id
                hallazgos.append(hallazgo("dependency-check", vid, [], eco, nombre or d.get("fileName"),
                                          version, fichero, None, v.get("severity")))
    return hallazgos, ficheros


def salud(herramienta, reg, salida):
    """Estado a partir del codigo de salida, el JSON y el log; ninguno basta por separado."""
    crudo = Path(salida) / "crudo"
    stderr = (crudo / f"{herramienta}.stderr.txt").read_text(errors="replace") if (crudo / f"{herramienta}.stderr.txt").is_file() else ""
    nombre_json = {"trivy": "trivy.json", "osv-scanner": "osv-scanner.json",
                   "dependency-check": "dependency-check-report.json"}[herramienta]
    datos, estado_json = leer_json(crudo / nombre_json)
    codigo = reg.get("codigo")

    if reg.get("error"):
        return FALLO, reg["error"], None

    if herramienta == "trivy":
        if codigo != 0 or estado_json != "ok":
            return FALLO, f"codigo {codigo}, salida {estado_json}. {ultima_linea(stderr)}", None
        # Trivy 0.72.0 pierde las transitivas de un POM que no puede descargar, con codigo 0.
        # Solo queda rastro en el log de depuracion.
        perdidos = sorted(set(re.findall(r"\[pom\].*Repository error.*?err=\"([^\"]+?) was not found", stderr)))
        if perdidos or re.search(r"\[pom\].*(429|Too Many Requests)", stderr):
            return PARCIAL, (f"no pudo descargar {len(perdidos)} POM de Maven ({', '.join(perdidos[:3])}) "
                             "y faltan sus dependencias transitivas"), datos
        if not any(r.get("Class") == "lang-pkgs" for r in datos.get("Results") or []):
            return SIN_FUENTES, "no encontro ningun manifiesto que sepa leer", datos
        return OK, "", datos

    if herramienta == "osv-scanner":
        if codigo == 128:
            return SIN_FUENTES, "no encontro ningun manifiesto que sepa leer", None
        # con 127 escribe un JSON valido sin vulnerabilidades aunque no haya podido consultar la API
        if codigo not in (0, 1) or estado_json != "ok":
            return FALLO, f"codigo {codigo}, salida {estado_json}. {ultima_linea(stderr)}", None
        n_vulns = sum(len(p.get("vulnerabilities") or []) for r in datos.get("results") or []
                      for p in r.get("packages") or [])
        if codigo == 1 and n_vulns == 0:
            return FALLO, "codigo 1 (hay vulnerabilidades) pero el JSON no trae ninguna", None
        errores = re.findall(r"Error during extraction:.*?failed resolution for (\S+?):", stderr)
        if "Error during extraction" in stderr:
            return PARCIAL, "el resolvedor no pudo procesar " + (", ".join(relativa(e, reg.get("ruta", "")) for e in errores) or "algun fichero"), datos
        return OK, "", datos

    # dependency-check devuelve 14 si falla un analizador aunque el informe este completo
    if estado_json != "ok":
        return FALLO, f"informe {estado_json}, codigo {codigo}. {ultima_linea(stderr)}", None
    excepciones = (datos.get("scanInfo") or {}).get("analysisExceptions") or []
    if excepciones or codigo != 0:
        return PARCIAL, f"codigo {codigo}, {len(excepciones)} excepciones de analizador", datos
    if not datos.get("dependencies"):
        return SIN_FUENTES, "no analizo ninguna dependencia", datos
    return OK, "", datos


def ultima_linea(texto):
    lineas = [re.sub(r"\x1b\[[0-9;]*m", "", l).strip() for l in texto.splitlines() if l.strip()]
    causas = [l[2:] for l in lineas if l.startswith("* ")]
    if causas:
        return causas[-1][:250]
    fatal = [i for i, l in enumerate(lineas) if "FATAL" in l]
    if fatal and fatal[0] + 1 < len(lineas):
        return lineas[fatal[0] + 1].lstrip("- ")[:250]
    for l in reversed(lineas):
        if re.search(r"FATAL|ERROR|[Ee]rror", l):
            return l[:250]
    return lineas[-1][:250] if lineas else ""


def cargar_escaneo(salida):
    registro, estado = leer_json(Path(salida) / "escaneo.json")
    if estado != "ok":
        sys.exit(f"no hay escaneo.json en {salida}")
    lectores = {"trivy": leer_trivy, "osv-scanner": leer_osv, "dependency-check": leer_dc}
    hallazgos, saludes, ficheros = [], {}, {}
    for h, reg in registro["herramientas"].items():
        reg["ruta"] = registro["ruta"]
        estado, motivo, datos = salud(h, reg, salida)
        saludes[h] = {"estado": estado, "motivo": motivo, "version": reg["version"], "bbdd": reg.get("bbdd"),
                      "codigo": reg.get("codigo"), "segundos": reg.get("segundos")}
        if datos is not None:
            hs, fs = lectores[h](datos, registro["ruta"])
            hallazgos += [x for x in hs if x["id"]]
            ficheros[h] = fs
    return registro, hallazgos, saludes, ficheros


def inventario(raiz, ficheros_analizados):
    """Manifiestos que ninguna herramienta ha leido y ficheros de configuracion de escaneres."""
    sin_cobertura, configs = [], []
    dirs_cubiertos = {os.path.dirname(f) for fs in ficheros_analizados.values() for f in fs if f}
    for d, subdirs, nombres in os.walk(raiz):
        subdirs[:] = [s for s in subdirs if s not in IGNORAR_DIRS]
        rel = os.path.relpath(d, raiz).replace(os.sep, "/")
        rel = "" if rel == "." else rel
        for n in nombres:
            ruta = f"{rel}/{n}" if rel else n
            if (n in MANIFIESTOS or (n.startswith("requirements") and n.endswith(".txt"))) and rel not in dirs_cubiertos:
                sin_cobertura.append(ruta)
            if n in CONFIG_ESCANERES:
                configs.append(ruta)
    return sorted(sin_cobertura), sorted(configs)


def consultar_osv(vid):
    try:
        datos = json.loads(descargar(OSV_API + urllib.parse.quote(vid), timeout=20))
        return vid, {"alias": [norm_id(a) for a in datos.get("aliases") or []],
                     "retirada": bool(datos.get("withdrawn"))}
    except urllib.error.HTTPError:
        return vid, {"alias": [], "retirada": False}
    except RuntimeError:
        return vid, None


def agrupar(hallazgos, osv=None):
    """Agrupa por (ecosistema, paquete, version, id canonico) uniendo alias de forma transitiva."""
    osv = osv or {}
    padre = {}

    def raiz(x):
        padre.setdefault(x, x)
        while padre[x] != x:
            padre[x] = padre[padre[x]]
            x = padre[x]
        return x

    def unir(a, b):
        ra, rb = sorted((raiz(a), raiz(b)))
        padre[rb] = ra

    for h in hallazgos:
        for a in h["alias"] | set((osv.get(h["id"]) or {}).get("alias", [])):
            unir(h["id"], a)

    grupos = {}
    for h in hallazgos:
        clave = (raiz(h["id"]), h["eco"], h["paquete"], h["version"])
        g = grupos.setdefault(clave, {"eco": h["eco"], "paquete": h["paquete"], "version": h["version"],
                                      "ids": set(), "herramientas": set(), "ficheros": set(), "dev": [],
                                      "retirada": [], "severidad": None})
        g["ids"] |= {h["id"]} | h["alias"] | set((osv.get(h["id"]) or {}).get("alias", []))
        g["herramientas"].add(h["herramienta"])
        g["ficheros"].add(h["fichero"])
        g["dev"].append(h["dev"])
        g["retirada"].append(h["retirada"] or (osv.get(h["id"]) or {}).get("retirada", False))
        g["severidad"] = g["severidad"] or h["severidad"]
    for g in grupos.values():
        # solo es de desarrollo si todas las herramientas que lo vieron lo dicen
        g["dev"] = all(d is True for d in g["dev"])
        g["retirada"] = all(g["retirada"])
        g["cves"] = sorted(i for i in g["ids"] if re.match(r"^CVE-\d{4}-\d+$", i))
        g["id"] = g["cves"][0] if g["cves"] else min(g["ids"])
    return list(grupos.values())


def cargar_kev(fichero, guardar):
    crudo, fuente = None, fichero
    if fichero:
        crudo = Path(fichero).read_bytes()
    else:
        for url in KEV_URLS:
            try:
                crudo, fuente = descargar(url), url
                break
            except Exception:
                continue
    if crudo is None:
        raise RuntimeError("no se pudo descargar CISA KEV")
    datos = json.loads(crudo)
    (Path(guardar) / "kev.json").write_bytes(crudo)
    return ({v["cveID"].upper(): v.get("dateAdded") for v in datos["vulnerabilities"]},
            {"fuente": fuente, "version": datos.get("catalogVersion")})


def cargar_epss(cves, fichero, guardar):
    try:
        crudo, fuente = (Path(fichero).read_bytes(), fichero) if fichero else (descargar(EPSS_URL, 180), EPSS_URL)
    except RuntimeError:
        # plan B, la API de FIRST solo para los CVE que hacen falta
        puntos, lista = {}, sorted(cves)
        for i in range(0, len(lista), 80):
            datos = json.loads(descargar(EPSS_API + ",".join(lista[i:i + 80])))
            puntos.update({d["cve"].upper(): float(d["epss"]) for d in datos.get("data") or []})
        (Path(guardar) / "epss_api.json").write_text(json.dumps(puntos))
        return puntos, {"fuente": "api.first.org", "fecha": dt.date.today().isoformat()}
    texto = gzip.decompress(crudo).decode() if crudo[:2] == b"\x1f\x8b" else crudo.decode()
    cabecera = texto.splitlines()[0]
    meta = dict(p.split(":", 1) for p in cabecera.lstrip("#").split(",") if ":" in p)
    puntos = {f["cve"].upper(): float(f["epss"]) for f in csv.DictReader(l for l in texto.splitlines() if not l.startswith("#"))
              if f["cve"].upper() in cves}
    (Path(guardar) / "epss_scores.csv.gz").write_bytes(crudo if crudo[:2] == b"\x1f\x8b" else gzip.compress(crudo))
    return puntos, {"fuente": fuente, "modelo": meta.get("model_version"), "fecha": meta.get("score_date")}


def clasificar(g, pol, excepciones=(), hoy=None):
    hoy = hoy or dt.date.today()
    exc = next((e for e in excepciones if e["id"] in g["ids"] and e["caduca"] >= hoy
                and (not e.get("paquete") or g["paquete"].split(":")[-1] == e["paquete"].lower())), None)
    epss = g.get("epss")
    if g["retirada"]:
        nivel, motivo = "RETIRADA", "aviso retirado en OSV"
    elif exc:
        nivel, motivo = "EXCEPTUADO", f"excepcion hasta {exc['caduca']}, {exc['motivo']}"
    elif any(i.startswith("MAL-") for i in g["ids"]):
        nivel, motivo = "BLOQUEO", "paquete malicioso conocido"
    elif g.get("kev"):
        # tambien en desarrollo, porque se ejecuta en la propia integracion continua
        nivel, motivo = "BLOQUEO", f"{', '.join(g['kev'])} en CISA KEV"
    elif not g["cves"]:
        nivel, motivo = "SIN_CVE", "sin CVE, EPSS y KEV no aplican"
    elif epss is None:
        nivel, motivo = "AVISO", "CVE sin puntuacion EPSS todavia"
    elif epss >= pol["epss_bloqueo"]:
        nivel = "AVISO" if g["dev"] else "BLOQUEO"
        motivo = f"EPSS {decimal(epss)}" + (" en dependencia de desarrollo" if g["dev"] else "")
    elif epss >= pol["epss_aviso"]:
        nivel, motivo = "AVISO", f"EPSS {decimal(epss)}"
    else:
        nivel, motivo = "INFO", f"EPSS {decimal(epss)}"
    # en modo diferencial solo bloquea lo que introduce la PR
    if nivel == "BLOQUEO" and g.get("preexistente"):
        nivel, motivo = "AVISO", motivo + ", ya estaba en la rama base"
    g["nivel"], g["motivo"] = nivel, motivo


def decision_global(saludes, grupos, sin_cobertura, avisos, errores_fuentes, pol):
    fallos = [f"{h} {s['motivo']}" for h, s in saludes.items() if s["estado"] == FALLO] + errores_fuentes
    niveles = [g["nivel"] for g in grupos]
    if fallos and pol["fallo_herramienta"] == "error":
        return "ERROR", "Sin datos fiables, la puerta falla cerrada. " + "; ".join(fallos)
    if "BLOQUEO" in niveles:
        return "BLOQUEA", f"{niveles.count('BLOQUEO')} vulnerabilidad(es) superan la politica"
    parciales = [h for h, s in saludes.items() if s["estado"] == PARCIAL]
    if "AVISO" in niveles or "SIN_CVE" in niveles or parciales or sin_cobertura or avisos or fallos:
        return "AVISO", "Nada bloquea, pero hay que revisar el informe"
    return "PASA", "Ninguna vulnerabilidad supera la politica y todas las herramientas dieron datos completos"


def cargar_excepciones(ruta):
    if not ruta or not Path(ruta).is_file():
        return [], []
    try:
        datos = tomllib.loads(Path(ruta).read_text())
    except tomllib.TOMLDecodeError as e:
        return [], [f"{ruta} no se puede leer, no se aplica ninguna excepcion ({e})"]
    lista, errores = [], []
    for e in datos.get("excepcion", []):
        caduca = e.get("caduca")
        if not (e.get("id") and e.get("motivo") and isinstance(caduca, dt.date)):
            errores.append(f"excepcion {e.get('id', '?')} sin id, motivo o caducidad, se ignora")
            continue
        lista.append({"id": norm_id(e["id"]), "paquete": e.get("paquete"), "motivo": e["motivo"],
                      "caduca": caduca, "referencia": e.get("referencia")})
    return lista, errores


def decidir(a):
    salida = Path(a.salida)
    fuentes = salida / "fuentes"
    fuentes.mkdir(exist_ok=True)
    pol = {"epss_bloqueo": a.epss_bloqueo, "epss_aviso": a.epss_aviso,
           "fallo_herramienta": a.fallo_herramienta, "modo": a.modo}

    registro, hallazgos, saludes, ficheros = cargar_escaneo(salida)
    base = cargar_escaneo(a.base) if a.base else None
    todos = hallazgos + (base[1] if base else [])

    ids = sorted({h["id"] for h in todos if " " not in h["id"]})
    with ThreadPoolExecutor(8) as pool:
        osv = dict(pool.map(consultar_osv, ids))
    errores_fuentes, avisos = [], []
    if any(v is None for v in osv.values()):
        avisos.append("la API de OSV no respondio para algunos identificadores, se usan solo los alias de las herramientas")

    grupos = agrupar(hallazgos, osv)
    corregidas = []
    if base:
        def mismo(a, b):
            return a["eco"] == b["eco"] and a["paquete"] == b["paquete"] and bool(a["ids"] & b["ids"])
        grupos_base = agrupar(base[1], osv)
        for g in grupos:
            g["preexistente"] = any(mismo(g, b) for b in grupos_base)
        # lo que estaba en la base y ya no esta, por ejemplo tras una PR de Dependabot
        corregidas = [b for b in grupos_base if not b["retirada"] and not any(mismo(b, g) for g in grupos)]
        for h, s in base[2].items():
            if s["estado"] == FALLO:
                errores_fuentes.append(f"{h} fallo en la rama base ({s['motivo']})")

    cves = {c for g in grupos for c in g["cves"]}
    meta = {}
    if cves:
        try:
            kev, meta["kev"] = cargar_kev(a.kev_fichero, fuentes)
            for g in grupos:
                g["kev"] = [c for c in g["cves"] if c in kev]
        except Exception as e:
            errores_fuentes.append(f"CISA KEV no disponible ({e})")
        try:
            epss, meta["epss"] = cargar_epss(cves, a.epss_fichero, fuentes)
            for g in grupos:
                puntos = [epss[c] for c in g["cves"] if c in epss]
                g["epss"] = max(puntos) if puntos else None
        except Exception as e:
            errores_fuentes.append(f"EPSS no disponible ({e})")

    excepciones, errores_exc = cargar_excepciones(a.excepciones)
    avisos += errores_exc
    propuestas, _ = cargar_excepciones(a.propuestas)
    propuestas = [p for p in propuestas if p not in excepciones]
    for g in grupos:
        clasificar(g, pol, excepciones)

    sin_cobertura, configs = inventario(registro["ruta"], ficheros)
    avisos += [f"{c} no se aplica; las exclusiones van en .sca-excepciones.toml" for c in configs]
    decision, motivo = decision_global(saludes, grupos, sin_cobertura, avisos, errores_fuentes, pol)

    texto = informe_md(decision, motivo, saludes, grupos, corregidas, sin_cobertura, avisos, errores_fuentes,
                       propuestas, meta, pol, bool(base))
    (salida / "informe.md").write_text(texto)
    resultado = {"decision": decision, "motivo": motivo, "politica": pol, "herramientas": saludes,
                 "fuentes": meta, "sin_cobertura": sin_cobertura, "avisos": avisos + errores_fuentes,
                 "corregidas": sorted({f"{c['id']} {c['paquete']}@{c['version']}" for c in corregidas}),
                 "grupos": [{**g, "ids": sorted(g["ids"]), "herramientas": sorted(g["herramientas"]),
                             "ficheros": sorted(f for f in g["ficheros"] if f)} for g in grupos]}
    (salida / "informe.json").write_text(json.dumps(resultado, indent=1, ensure_ascii=False, default=str))

    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(texto)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"decision={decision}\n")
    print(f"Decision {decision}. {motivo}")
    if decision == "ERROR" or (decision == "BLOQUEA" and pol["modo"] == "bloquear"):
        return 1
    return 0


def informe_md(decision, motivo, saludes, grupos, corregidas, sin_cobertura, avisos, errores, propuestas, meta, pol, diferencial):
    icono = {"PASA": "✅", "AVISO": "⚠️", "BLOQUEA": "⛔", "ERROR": "❌"}[decision]
    l = [f"## {icono} sca-gate {decision}", "", motivo + ".", ""]
    if diferencial:
        l += ["Modo diferencial, solo bloquea lo que introduce la PR.", ""]

    l += ["| Herramienta | Versión | Estado | Detalle |", "|---|---|---|---|"]
    for h, s in saludes.items():
        l.append(f"| {h} | {s['version']} | {s['estado']} | {s['motivo'] or '-'} |")
    l.append("")

    orden = {n: i for i, n in enumerate(NIVELES)}
    visibles = sorted((g for g in grupos if g["nivel"] in ("BLOQUEO", "AVISO", "SIN_CVE", "EXCEPTUADO")),
                      key=lambda g: (orden[g["nivel"]], not g.get("kev"), -(g.get("epss") or 0)))
    if visibles:
        l += ["| Nivel | Vulnerabilidad | Paquete | EPSS | KEV | Detectada por | Motivo |", "|---|---|---|---|---|---|---|"]
        for g in visibles:
            l.append(f"| {g['nivel']} | {g['id']} | {g['paquete']}@{g['version']} | {decimal(g.get('epss'))} | "
                     f"{'sí' if g.get('kev') else ''} | {', '.join(sorted(g['herramientas']))} | {g['motivo']} |")
        l.append("")
    resto = [g for g in grupos if g["nivel"] in ("INFO", "RETIRADA")]
    if resto:
        l += [f"Además hay {len(resto)} vulnerabilidad(es) con EPSS por debajo de {decimal(pol['epss_aviso'])} "
              "o con el aviso retirado. Están en el artefacto.", ""]

    for titulo, lista in (("Manifiestos que ninguna herramienta ha analizado", sin_cobertura),
                          ("Avisos", avisos + errores),
                          ("Vulnerabilidades que corrige la PR",
                           sorted({f"{c['id']} en {c['paquete']}@{c['version']}" for c in corregidas})),
                          ("Excepciones que propone la PR (no se aplican hasta fusionarlas)",
                           [f"{p['id']} hasta {p['caduca']}, {p['motivo']}" for p in propuestas])):
        if lista:
            l += [f"**{titulo}**", ""] + [f"- {x}" for x in lista] + [""]

    if meta:
        epss, kev = meta.get("epss", {}), meta.get("kev", {})
        l.append(f"EPSS {epss.get('fecha', '-')} (modelo {epss.get('modelo', '-')}), KEV versión {kev.get('version', '-')}. "
                 f"Umbrales EPSS bloqueo {decimal(pol['epss_bloqueo'])}, aviso {decimal(pol['epss_aviso'])}.")
    return "\n".join(l) + "\n"


def main():
    ap = argparse.ArgumentParser(prog="sca_gate")
    sub = ap.add_subparsers(dest="orden", required=True)

    p = sub.add_parser("instalar")
    p.add_argument("--dir", required=True)
    p.add_argument("--herramientas", default="trivy,osv-scanner")

    p = sub.add_parser("escanear")
    p.add_argument("--ruta", required=True)
    p.add_argument("--salida", required=True)
    p.add_argument("--bin", required=True)
    p.add_argument("--herramientas", default="trivy,osv-scanner")
    p.add_argument("--dc-datos")

    p = sub.add_parser("decidir")
    p.add_argument("--salida", required=True)
    p.add_argument("--base")
    p.add_argument("--excepciones")
    p.add_argument("--propuestas")
    p.add_argument("--epss-bloqueo", type=float, default=0.1)
    p.add_argument("--epss-aviso", type=float, default=0.01)
    p.add_argument("--fallo-herramienta", choices=["error", "aviso"], default="error")
    p.add_argument("--modo", choices=["bloquear", "avisar"], default="bloquear")
    p.add_argument("--epss-fichero")
    p.add_argument("--kev-fichero")

    a = ap.parse_args()
    lista = [h.strip() for h in getattr(a, "herramientas", "").split(",") if h.strip()]
    if a.orden == "instalar":
        instalar(lista, a.dir)
    elif a.orden == "escanear":
        escanear(a.ruta, a.salida, a.bin, lista, os.environ.get("NVD_API_KEY"), a.dc_datos)
    else:
        return decidir(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
