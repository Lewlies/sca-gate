#!/usr/bin/env python3
"""Compara la decision de sca-gate en un repo sintetico con la del oraculo.

El oraculo aplica la misma politica al ground truth del repo con la misma instantanea
de EPSS y KEV que uso la puerta, asi que una diferencia solo puede venir de lo que
detectaron las herramientas.

    python3 validacion/validar.py comprobar --informe DIR --repo synthetic-npm-mixed --salida res.json
    python3 validacion/validar.py resumen DIR_CON_RESULTADOS
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import sca_gate  # noqa: E402

ESPERADO = Path(__file__).with_name("esperado.json")


def decision(niveles):
    niveles = list(niveles)
    if "BLOQUEO" in niveles:
        return "BLOQUEA"
    if "AVISO" in niveles or "SIN_CVE" in niveles:
        return "AVISO"
    return "PASA"


def coincide(esperado, grupo):
    a, b = esperado["paquete"].lower(), grupo["paquete"].lower()
    mismo_paquete = a == b or a.split(":")[-1] == b.split(":")[-1]
    misma_version = not esperado["version"] or not grupo["version"] or esperado["version"] == grupo["version"]
    return mismo_paquete and misma_version and bool(set(esperado["ids"]) & set(grupo["ids"]))


def comprobar(dir_informe, repo):
    esperado = next(r for r in json.loads(ESPERADO.read_text())["repos"] if r["repo"] == repo)
    informe = json.loads((Path(dir_informe) / "informe.json").read_text())
    res = {"repo": repo, "decision_gate": informe["decision"]}
    fallos = [h for h, s in informe["herramientas"].items() if s["estado"] == "FALLO"]
    if fallos:
        return {**res, "veredicto": "NO_CONCLUYENTE", "motivo": "fallo de " + ", ".join(fallos)}

    grupos = [g for g in informe["grupos"] if g["nivel"] != "RETIRADA"]
    res["decision_gate"] = decision(g["nivel"] for g in grupos)

    fuentes = Path(dir_informe) / "fuentes"
    cves = {i for p in esperado["presentes"] for i in p["ids"] if i.startswith("CVE-")}
    kev, epss = {}, {}
    if cves:
        # si la puerta no encontro ningun CVE no descargo instantanea, y entonces no hace falta
        if not (fuentes / "kev.json").is_file() or not (fuentes / "epss_scores.csv.gz").is_file():
            return {**res, "veredicto": "NO_CONCLUYENTE", "motivo": "no hay instantanea de EPSS o KEV"}
        kev, _ = sca_gate.cargar_kev(fuentes / "kev.json", fuentes)
        epss, _ = sca_gate.cargar_epss(cves, fuentes / "epss_scores.csv.gz", fuentes)

    niveles, no_vistos = [], []
    for p in esperado["presentes"]:
        g = {"ids": set(p["ids"]), "paquete": p["paquete"], "dev": False, "retirada": False,
             "cves": [i for i in p["ids"] if i.startswith("CVE-")]}
        g["kev"] = [c for c in g["cves"] if c in kev]
        puntos = [epss[c] for c in g["cves"] if c in epss]
        g["epss"] = max(puntos) if puntos else None
        sca_gate.clasificar(g, informe["politica"])
        niveles.append(g["nivel"])
        if g["nivel"] in ("BLOQUEO", "AVISO") and not any(coincide(p, x) for x in grupos):
            no_vistos.append(f"{p['ids'][0]} en {p['paquete']}")
    res["decision_oraculo"] = decision(niveles)

    documentados = esperado["presentes"] + esperado["ausentes"]
    extra = [f"{g['id']} en {g['paquete']}" for g in grupos
             if g["nivel"] in ("BLOQUEO", "AVISO") and not any(coincide(p, g) for p in documentados)]

    if res["decision_gate"] == res["decision_oraculo"]:
        return {**res, "veredicto": "COINCIDE", "motivo": ""}
    if no_vistos or extra:
        motivo = "; ".join(filter(None, ["no detectadas " + ", ".join(no_vistos) if no_vistos else "",
                                          "no documentadas en el ground truth " + ", ".join(extra) if extra else ""]))
        return {**res, "veredicto": "DISCREPA_EXPLICADA", "motivo": motivo}
    return {**res, "veredicto": "DISCREPA", "motivo": "la decision difiere sin explicacion"}


def resumen(carpeta):
    filas = [json.loads(f.read_text()) for f in sorted(Path(carpeta).rglob("*.json"))]
    print("| Repositorio | Oráculo | sca-gate | Veredicto | Motivo |\n|---|---|---|---|---|")
    for r in filas:
        print(f"| {r['repo']} | {r.get('decision_oraculo', '-')} | {r['decision_gate']} | {r['veredicto']} | {r['motivo']} |")
    return 1 if any(r["veredicto"] == "DISCREPA" for r in filas) else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="orden", required=True)
    p = sub.add_parser("comprobar")
    p.add_argument("--informe", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--salida", required=True)
    p = sub.add_parser("resumen")
    p.add_argument("carpeta")
    a = ap.parse_args()
    if a.orden == "resumen":
        sys.exit(resumen(a.carpeta))
    r = comprobar(a.informe, a.repo)
    Path(a.salida).write_text(json.dumps(r, ensure_ascii=False))
    print(f"{r['repo']} {r['veredicto']} {r['motivo']}")
