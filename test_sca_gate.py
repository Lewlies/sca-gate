import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

import sca_gate as sg

POL = {"epss_bloqueo": 0.1, "epss_aviso": 0.01, "fallo_herramienta": "error", "modo": "bloquear"}


def grupo(ids, epss=None, kev=(), dev=False, paquete="lodash", preexistente=False):
    ids = set(ids)
    return {"ids": ids, "cves": sorted(i for i in ids if i.startswith("CVE-")), "epss": epss, "kev": list(kev),
            "dev": dev, "paquete": paquete, "retirada": False, "preexistente": preexistente}


def salida_falsa(herramienta, codigo, json_texto=None, stderr=""):
    d = Path(tempfile.mkdtemp())
    (d / "crudo").mkdir()
    nombre = {"trivy": "trivy.json", "osv-scanner": "osv-scanner.json",
              "dependency-check": "dependency-check-report.json"}[herramienta]
    if json_texto is not None:
        (d / "crudo" / nombre).write_text(json_texto)
    (d / "crudo" / f"{herramienta}.stderr.txt").write_text(stderr)
    return sg.salud(herramienta, {"codigo": codigo, "ruta": "/repo"}, d)[:2]


TRIVY_OK = json.dumps({"Results": [{"Target": "pom.xml", "Class": "lang-pkgs", "Type": "pom"}]})
OSV_LIMPIO = json.dumps({"results": [{"source": {"path": "/repo/package-lock.json"},
                                      "packages": [{"package": {"name": "a"}, "vulnerabilities": []}]}]})


class Utilidades(unittest.TestCase):
    def test_ghsa_en_minusculas(self):
        self.assertEqual(sg.norm_id("GHSA-35JH-R3H4-6JHM"), "GHSA-35jh-r3h4-6jhm")
        self.assertEqual(sg.norm_id("cve-2021-44228"), "CVE-2021-44228")

    def test_purl(self):
        self.assertEqual(sg.purl("pkg:maven/org.yaml/snakeyaml@1.33"), ("maven", "org.yaml:snakeyaml", "1.33"))
        self.assertEqual(sg.purl("pkg:pypi/PyYAML@5.3"), ("pypi", "pyyaml", "5.3"))


class Salud(unittest.TestCase):
    def test_trivy_pierde_transitivas_con_codigo_0(self):
        log = 'DEBUG [pom] Repository error err="org.foo:bar:1.0 was not found in https://repo.maven.apache.org"'
        self.assertEqual(salida_falsa("trivy", 0, TRIVY_OK, log)[0], sg.PARCIAL)

    def test_trivy_ok(self):
        self.assertEqual(salida_falsa("trivy", 0, TRIVY_OK)[0], sg.OK)

    def test_osv_127_con_json_limpio_es_fallo(self):
        self.assertEqual(salida_falsa("osv-scanner", 127, OSV_LIMPIO)[0], sg.FALLO)

    def test_osv_128_sin_fuentes(self):
        self.assertEqual(salida_falsa("osv-scanner", 128)[0], sg.SIN_FUENTES)

    def test_osv_codigo_1_sin_vulnerabilidades_es_incoherente(self):
        self.assertEqual(salida_falsa("osv-scanner", 1, OSV_LIMPIO)[0], sg.FALLO)

    def test_json_vacio_es_fallo(self):
        self.assertEqual(salida_falsa("trivy", 0, "")[0], sg.FALLO)

    def test_dependency_check_14_con_informe_es_parcial(self):
        informe = json.dumps({"dependencies": [{}], "scanInfo": {"analysisExceptions": [{"exception": {}}]}})
        self.assertEqual(salida_falsa("dependency-check", 14, informe)[0], sg.PARCIAL)


class Politica(unittest.TestCase):
    def nivel(self, g, excepciones=()):
        sg.clasificar(g, POL, excepciones, hoy=dt.date(2026, 10, 1))
        return g["nivel"]

    def test_orden(self):
        self.assertEqual(self.nivel(grupo(["MAL-2025-1"])), "BLOQUEO")
        self.assertEqual(self.nivel(grupo(["CVE-1"], epss=0.001, kev=["CVE-1"], dev=True)), "BLOQUEO")
        self.assertEqual(self.nivel(grupo(["GHSA-x"])), "SIN_CVE")
        self.assertEqual(self.nivel(grupo(["CVE-1"])), "AVISO")
        self.assertEqual(self.nivel(grupo(["CVE-1"], epss=0.5)), "BLOQUEO")
        self.assertEqual(self.nivel(grupo(["CVE-1"], epss=0.5, dev=True)), "AVISO")
        self.assertEqual(self.nivel(grupo(["CVE-1"], epss=0.05)), "AVISO")
        self.assertEqual(self.nivel(grupo(["CVE-1"], epss=0.001)), "INFO")

    def test_preexistente_baja_a_aviso(self):
        self.assertEqual(self.nivel(grupo(["CVE-1"], epss=0.5, preexistente=True)), "AVISO")

    def test_excepcion_caduca(self):
        vigente = {"id": "CVE-1", "paquete": "lodash", "motivo": "x", "caduca": dt.date(2027, 1, 1)}
        caducada = dict(vigente, caduca=dt.date(2026, 1, 1))
        self.assertEqual(self.nivel(grupo(["CVE-1"], epss=0.5), [vigente]), "EXCEPTUADO")
        self.assertEqual(self.nivel(grupo(["CVE-1"], epss=0.5), [caducada]), "BLOQUEO")

    def test_fallo_cerrado(self):
        saludes = {"trivy": {"estado": sg.FALLO, "motivo": "codigo 1"}}
        self.assertEqual(sg.decision_global(saludes, [], [], [], [], POL)[0], "ERROR")
        self.assertEqual(sg.decision_global(saludes, [], [], [], [], dict(POL, fallo_herramienta="aviso"))[0], "AVISO")


class Canonicalizacion(unittest.TestCase):
    def test_union_transitiva_de_alias(self):
        hs = [sg.hallazgo("trivy", "CVE-2021-23337", [], "npm", "lodash", "4.17.20", "package-lock.json"),
              sg.hallazgo("osv-scanner", "GHSA-35jh-r3h4-6jhm", ["CVE-2021-23337"], "npm", "lodash", "4.17.20",
                          "package-lock.json")]
        osv = {"GHSA-35jh-r3h4-6jhm": {"alias": ["CVE-2026-4800"], "retirada": False}}
        grupos = sg.agrupar(hs, osv)
        self.assertEqual(len(grupos), 1)
        self.assertEqual(grupos[0]["cves"], ["CVE-2021-23337", "CVE-2026-4800"])
        self.assertEqual(grupos[0]["herramientas"], {"trivy", "osv-scanner"})


class Inventario(unittest.TestCase):
    def test_setup_py_sin_cobertura_y_config_de_escaner(self):
        d = Path(tempfile.mkdtemp())
        (d / "web").mkdir()
        (d / "web" / "package-lock.json").write_text("{}")
        (d / "web" / "package.json").write_text("{}")
        (d / "setup.py").write_text("")
        (d / "osv-scanner.toml").write_text("")
        sin, configs = sg.inventario(str(d), {"trivy": {"web/package-lock.json"}})
        self.assertEqual(sin, ["setup.py"])
        self.assertEqual(configs, ["osv-scanner.toml"])


if __name__ == "__main__":
    unittest.main()
