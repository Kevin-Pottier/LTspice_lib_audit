#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LTspice third-party library auditor
-----------------------------------
Objectif :
- scanner récursivement un dossier de librairies LTspice
- faire un pré-scan statique des fichiers SPICE
- extraire les .SUBCKT / .MODEL
- générer des decks de test LTspice
- lancer LTspice en batch si disponible
- produire des rapports CSV

Conçu pour Windows + LTspice.
Compatible Python 3.10+.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shlex
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional, Tuple, Dict

SUPPORTED_EXTS = {".lib", ".sub", ".cir", ".mod", ".txt", ".si"}
TEXT_ENCODINGS = ["utf-8", "utf-8-sig", "cp1252", "latin-1"]

SUBCKT_RE = re.compile(r"^\s*\.subckt\s+([^\s]+)\s*(.*)$", re.IGNORECASE)
ENDS_RE = re.compile(r"^\s*\.ends\b\s*([^\s;*]+)?", re.IGNORECASE)
MODEL_RE = re.compile(r"^\s*\.model\s+([^\s]+)\s+([^\s]+)", re.IGNORECASE)
INCLUDE_RE = re.compile(r'^\s*\.(?:include|inc|lib)\s+("?)([^"\n\r]+)\1', re.IGNORECASE)
TABLE_RE = re.compile(r"\bTABLE\b", re.IGNORECASE)

DEFAULT_LTSPICE_CANDIDATES = [
    r"C:\Program Files\ADI\LTspice\LTspice.exe",
    r"C:\Program Files\ADI\LTspice\XVIIx64.exe",
    r"C:\Program Files\LTC\LTspiceXVII\XVIIx64.exe",
    r"C:\Program Files\LTC\LTspiceIV\scad3.exe",
]

CSV_DIALECT = "excel"


@dataclass
class FileSummary:
    file_path: str
    rel_path: str
    extension: str
    encoding: str
    line_count: int
    char_count: int
    subckt_count: int
    model_count: int
    include_count: int
    syntax_score: int
    status: str
    issues: str


@dataclass
class StaticIssue:
    file_path: str
    rel_path: str
    line_no: int
    severity: str
    category: str
    message: str
    excerpt: str


@dataclass
class SubcktInfo:
    file_path: str
    rel_path: str
    line_no: int
    name: str
    pin_count: int
    pins: str
    params: str


@dataclass
class ModelInfo:
    file_path: str
    rel_path: str
    line_no: int
    name: str
    model_type: str


@dataclass
class BatchResult:
    target_kind: str
    file_path: str
    rel_path: str
    target_name: str
    test_cir: str
    status: str
    exit_code: str
    error_summary: str
    raw_log_path: str


def detect_encoding(raw: bytes) -> Tuple[str, str]:
    for enc in TEXT_ENCODINGS:
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace"), "latin-1-replace"


def list_candidate_files(root: Path, extensions: set[str]) -> List[Path]:
    out = []
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in extensions:
            out.append(p)
    return sorted(out)


def normalize_excerpt(s: str, max_len: int = 180) -> str:
    s = s.rstrip("\n\r")
    s = s.replace("\t", "    ")
    return s[:max_len]


def strip_inline_comment(line: str) -> str:
    # On garde volontairement simple :
    # - '*' colonne 1 = commentaire SPICE
    # - ';' souvent utilisé inline dans des libs tierces
    if re.match(r"^\s*\*", line):
        return ""
    if ";" in line:
        return line.split(";", 1)[0]
    return line


def count_parentheses_balance(text: str) -> Tuple[int, int]:
    opens = text.count("(")
    closes = text.count(")")
    return opens, closes


def is_probably_table_suspicious(line: str) -> bool:
    if not TABLE_RE.search(line):
        return False
    stripped = strip_inline_comment(line)
    opens, closes = count_parentheses_balance(stripped)
    return opens != closes


def parse_subckt_signature(rest: str) -> Tuple[List[str], List[str]]:
    """
    Sépare grossièrement pins et paramètres.
    Hypothèse : tout ce qui commence par PARAMS: ou contient '=' va dans params.
    """
    tokens = rest.split()
    pins: List[str] = []
    params: List[str] = []
    param_mode = False
    for tok in tokens:
        if tok.upper().startswith("PARAMS:"):
            param_mode = True
            params.append(tok)
            continue
        if "=" in tok:
            param_mode = True
            params.append(tok)
            continue
        if param_mode:
            params.append(tok)
        else:
            pins.append(tok)
    return pins, params


def prescan_file(root: Path, path: Path) -> Tuple[FileSummary, List[StaticIssue], List[SubcktInfo], List[ModelInfo]]:
    raw = path.read_bytes()
    text, enc = detect_encoding(raw)
    lines = text.splitlines()

    rel_path = str(path.relative_to(root))
    issues: List[StaticIssue] = []
    subckts: List[SubcktInfo] = []
    models: List[ModelInfo] = []

    include_count = 0
    subckt_open_stack: List[Tuple[str, int]] = []
    syntax_score = 100

    total_open = 0
    total_close = 0

    for idx, line in enumerate(lines, start=1):
        stripped = strip_inline_comment(line)

        opens, closes = count_parentheses_balance(stripped)
        total_open += opens
        total_close += closes

        m = INCLUDE_RE.match(stripped)
        if m:
            include_count += 1

        m = SUBCKT_RE.match(stripped)
        if m:
            name = m.group(1)
            rest = m.group(2) or ""
            pins, params = parse_subckt_signature(rest)
            subckts.append(SubcktInfo(
                file_path=str(path),
                rel_path=rel_path,
                line_no=idx,
                name=name,
                pin_count=len(pins),
                pins=" ".join(pins),
                params=" ".join(params),
            ))
            subckt_open_stack.append((name, idx))

        m = ENDS_RE.match(stripped)
        if m:
            if subckt_open_stack:
                subckt_open_stack.pop()
            else:
                issues.append(StaticIssue(
                    file_path=str(path),
                    rel_path=rel_path,
                    line_no=idx,
                    severity="ERROR",
                    category="ENDS",
                    message="'.ENDS' sans '.SUBCKT' ouvert correspondant",
                    excerpt=normalize_excerpt(line),
                ))
                syntax_score -= 10

        m = MODEL_RE.match(stripped)
        if m:
            models.append(ModelInfo(
                file_path=str(path),
                rel_path=rel_path,
                line_no=idx,
                name=m.group(1),
                model_type=m.group(2),
            ))

        if is_probably_table_suspicious(line):
            issues.append(StaticIssue(
                file_path=str(path),
                rel_path=rel_path,
                line_no=idx,
                severity="ERROR",
                category="TABLE",
                message="Ligne TABLE avec parenthèses déséquilibrées",
                excerpt=normalize_excerpt(line),
            ))
            syntax_score -= 15

        # Parenthèses fortement déséquilibrées sur une seule ligne
        if abs(opens - closes) >= 2:
            issues.append(StaticIssue(
                file_path=str(path),
                rel_path=rel_path,
                line_no=idx,
                severity="WARN",
                category="PARENS_LINE",
                message=f"Parenthèses déséquilibrées sur la ligne: {opens} '(' vs {closes} ')'",
                excerpt=normalize_excerpt(line),
            ))
            syntax_score -= 3

    for name, idx in subckt_open_stack:
        issues.append(StaticIssue(
            file_path=str(path),
            rel_path=rel_path,
            line_no=idx,
            severity="ERROR",
            category="SUBCKT",
            message=f".SUBCKT '{name}' sans .ENDS correspondant",
            excerpt=f".SUBCKT {name}",
        ))
        syntax_score -= 20

    if total_open != total_close:
        issues.append(StaticIssue(
            file_path=str(path),
            rel_path=rel_path,
            line_no=0,
            severity="WARN",
            category="PARENS_FILE",
            message=f"Parenthèses déséquilibrées dans le fichier: {total_open} '(' vs {total_close} ')'",
            excerpt="(fichier complet)",
        ))
        syntax_score -= min(20, abs(total_open - total_close))

    if syntax_score >= 90:
        status = "LIKELY_OK"
    elif syntax_score >= 70:
        status = "SUSPECT"
    else:
        status = "BROKEN_LIKELY"

    summary = FileSummary(
        file_path=str(path),
        rel_path=rel_path,
        extension=path.suffix.lower(),
        encoding=enc,
        line_count=len(lines),
        char_count=len(text),
        subckt_count=len(subckts),
        model_count=len(models),
        include_count=include_count,
        syntax_score=max(0, syntax_score),
        status=status,
        issues=" | ".join(f"L{it.line_no}:{it.category}:{it.message}" for it in issues[:10]),
    )
    return summary, issues, subckts, models


def find_ltspice_exe(user_path: Optional[str]) -> Optional[Path]:
    if user_path:
        p = Path(user_path)
        return p if p.exists() else None
    for cand in DEFAULT_LTSPICE_CANDIDATES:
        p = Path(cand)
        if p.exists():
            return p
    return None


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)


def build_file_parse_test_deck(file_path: Path) -> str:
    # But : forcer LTspice à parser le fichier inclus.
    return textwrap.dedent(f"""
    * file-parse test
    .include "{file_path}"
    V1 in 0 0
    R1 in 0 1k
    .op
    .end
    """).strip() + "\n"


def build_subckt_test_deck(file_path: Path, subckt_name: str, pin_count: int) -> str:
    # On crée N noeuds artificiels n1..nN.
    # But: forcer l'instanciation du subckt. Même si le circuit n'est pas "physiquement utile",
    # ça permet déjà de déclencher le parseur et une partie des vérifications.
    pins = " ".join(f"n{i}" for i in range(1, max(pin_count, 1) + 1))
    bias = "\n".join([f"V{i} n{i} 0 0" for i in range(1, max(pin_count, 1) + 1)])
    return textwrap.dedent(f"""
    * subckt-instantiation test
    .include "{file_path}"
    {bias}
    XU1 {pins} {subckt_name}
    .op
    .end
    """).strip() + "\n"


def run_ltspice_batch(ltspice_exe: Path, cir_path: Path, timeout_s: int = 60) -> Tuple[int, str, str]:
    """
    Tente plusieurs formes de commandes compatibles LTspice.
    Retourne (exit_code, stdout, stderr).
    """
    candidates = [
        [str(ltspice_exe), "-b", str(cir_path)],
        [str(ltspice_exe), "-Run", "-b", str(cir_path)],
        [str(ltspice_exe), "-run", "-b", str(cir_path)],
        [str(ltspice_exe), str(cir_path), "-b"],
    ]

    last_exc = None
    last_result = None
    for cmd in candidates:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                shell=False
            )
            # On considère qu'une exécution qui crée un .log ou ne plante pas le process
            # est déjà utile. On renvoie la première qui répond.
            return proc.returncode, proc.stdout, proc.stderr
        except Exception as exc:
            last_exc = exc
            last_result = None

    if last_exc:
        return 999, "", f"{type(last_exc).__name__}: {last_exc}"
    return 998, "", "Unable to execute LTspice"


def read_possible_log(cir_path: Path) -> Tuple[str, Optional[Path]]:
    candidates = [
        cir_path.with_suffix(".log"),
        cir_path.parent / (cir_path.stem + ".log"),
    ]
    for p in candidates:
        if p.exists():
            try:
                return p.read_text(encoding="utf-8", errors="replace"), p
            except Exception:
                return p.read_text(errors="replace"), p
    return "", None


def classify_log(log_text: str, stderr: str, exit_code: int) -> Tuple[str, str]:
    text = "\n".join([log_text or "", stderr or ""]).strip()

    if not text and exit_code == 0:
        return "OK", ""

    lower = text.lower()
    if "expected \")\"" in lower:
        return "FAIL_SYNTAX", 'Expected ")"'
    if "syntax error" in lower:
        return "FAIL_SYNTAX", "Syntax error"
    if "cannot be instantiated" in lower:
        return "FAIL_SUBCKT", "Subcircuit cannot be instantiated"
    if "unknown subcircuit called" in lower:
        return "FAIL_MISSING_SUBCKT", "Unknown subcircuit called"
    if "file not found" in lower:
        return "FAIL_INCLUDE", "Included file not found"
    if "too few nodes" in lower or "too many nodes" in lower:
        return "FAIL_PINCOUNT", "Subckt pin count mismatch"
    if "fatal error" in lower:
        return "FAIL_FATAL", "Fatal error"
    if exit_code != 0 and text:
        return "FAIL_OTHER", text.splitlines()[:1][0][:240]
    if exit_code == 0 and text:
        return "WARN_LOG", text.splitlines()[:1][0][:240]
    return "UNKNOWN", ""


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def write_csv(path: Path, rows: Iterable[dict], fieldnames: List[str]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, dialect=CSV_DIALECT)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit automatisé de librairies LTspice third-party"
    )
    parser.add_argument("--root", required=True, help="Dossier racine de la librairie à auditer")
    parser.add_argument("--out", required=True, help="Dossier de sortie pour rapports et decks")
    parser.add_argument("--ltspice", default="", help="Chemin vers LTspice.exe / XVIIx64.exe")
    parser.add_argument("--extensions", default=".lib,.sub,.cir,.mod,.txt,.si",
                        help="Extensions à scanner, séparées par des virgules")
    parser.add_argument("--no-batch", action="store_true",
                        help="N'exécute pas LTspice ; génère seulement les decks et les commandes")
    parser.add_argument("--only-suspect", action="store_true",
                        help="Ne lance les tests batch que pour les fichiers SUSPECT/BROKEN_LIKELY")
    parser.add_argument("--max-files", type=int, default=0,
                        help="Limite le nombre de fichiers scannés (0 = illimité)")
    parser.add_argument("--max-subckts", type=int, default=0,
                        help="Limite le nombre de sous-circuits testés (0 = illimité)")
    args = parser.parse_args()

    root = Path(args.root).expanduser().resolve()
    out = Path(args.out).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        print(f"[ERREUR] Dossier racine introuvable: {root}")
        return 2

    ensure_dir(out)
    reports_dir = out / "reports"
    decks_dir = out / "generated_test_decks"
    ensure_dir(reports_dir)
    ensure_dir(decks_dir)

    exts = {e.strip().lower() if e.strip().startswith(".") else "." + e.strip().lower()
            for e in args.extensions.split(",") if e.strip()}

    files = list_candidate_files(root, exts)
    if args.max_files and args.max_files > 0:
        files = files[:args.max_files]

    print(f"[INFO] Racine : {root}")
    print(f"[INFO] Sortie : {out}")
    print(f"[INFO] Fichiers candidats : {len(files)}")

    summaries: List[FileSummary] = []
    static_issues: List[StaticIssue] = []
    subckts: List[SubcktInfo] = []
    models: List[ModelInfo] = []

    for i, fp in enumerate(files, start=1):
        try:
            summary, issues, subs, mods = prescan_file(root, fp)
            summaries.append(summary)
            static_issues.extend(issues)
            subckts.extend(subs)
            models.extend(mods)
        except Exception as exc:
            rel = str(fp.relative_to(root))
            summaries.append(FileSummary(
                file_path=str(fp),
                rel_path=rel,
                extension=fp.suffix.lower(),
                encoding="ERROR",
                line_count=0,
                char_count=0,
                subckt_count=0,
                model_count=0,
                include_count=0,
                syntax_score=0,
                status="READ_ERROR",
                issues=f"{type(exc).__name__}: {exc}",
            ))

        if i % 50 == 0 or i == len(files):
            print(f"[INFO] Prescan: {i}/{len(files)}")

    # Rapports prescan
    write_csv(
        reports_dir / "files_summary.csv",
        [asdict(x) for x in summaries],
        fieldnames=list(asdict(summaries[0]).keys()) if summaries else list(FileSummary.__annotations__.keys()),
    )
    write_csv(
        reports_dir / "static_issues.csv",
        [asdict(x) for x in static_issues],
        fieldnames=list(asdict(static_issues[0]).keys()) if static_issues else list(StaticIssue.__annotations__.keys()),
    )
    write_csv(
        reports_dir / "subckts.csv",
        [asdict(x) for x in subckts],
        fieldnames=list(asdict(subckts[0]).keys()) if subckts else list(SubcktInfo.__annotations__.keys()),
    )
    write_csv(
        reports_dir / "models.csv",
        [asdict(x) for x in models],
        fieldnames=list(asdict(models[0]).keys()) if models else list(ModelInfo.__annotations__.keys()),
    )

    # Génération decks
    command_rows: List[dict] = []
    batch_results: List[BatchResult] = []

    ltspice_exe = find_ltspice_exe(args.ltspice.strip() or None)
    if args.no_batch:
        print("[INFO] Mode no-batch activé : génération des decks uniquement.")
    else:
        if ltspice_exe is None:
            print("[WARN] LTspice introuvable automatiquement.")
            print("[WARN] Utilise --ltspice \"C:\\...\\LTspice.exe\" ou relance en --no-batch.")
        else:
            print(f"[INFO] LTspice détecté : {ltspice_exe}")

    summary_map: Dict[str, FileSummary] = {x.file_path: x for x in summaries}

    # Test 1 : parsing par fichier
    for fs in summaries:
        if args.only_suspect and fs.status not in {"SUSPECT", "BROKEN_LIKELY", "READ_ERROR"}:
            continue

        file_path = Path(fs.file_path)
        deck_name = safe_name(fs.rel_path) + "__file_parse_test.cir"
        cir_path = decks_dir / deck_name
        cir_path.write_text(build_file_parse_test_deck(file_path), encoding="utf-8")
        cmd = f'"{ltspice_exe}" -b "{cir_path}"' if ltspice_exe else f'LTspice.exe -b "{cir_path}"'
        command_rows.append({
            "kind": "FILE_PARSE",
            "file_path": fs.file_path,
            "rel_path": fs.rel_path,
            "target_name": "(file)",
            "cir_path": str(cir_path),
            "suggested_command": cmd,
        })

        if not args.no_batch and ltspice_exe is not None:
            exit_code, stdout, stderr = run_ltspice_batch(ltspice_exe, cir_path)
            log_text, raw_log_path = read_possible_log(cir_path)
            status, err = classify_log(log_text, stderr, exit_code)
            batch_results.append(BatchResult(
                target_kind="FILE_PARSE",
                file_path=fs.file_path,
                rel_path=fs.rel_path,
                target_name="(file)",
                test_cir=str(cir_path),
                status=status,
                exit_code=str(exit_code),
                error_summary=err,
                raw_log_path=str(raw_log_path) if raw_log_path else "",
            ))

    # Test 2 : instanciation par subckt
    subckt_iter = subckts
    if args.max_subckts and args.max_subckts > 0:
        subckt_iter = subckt_iter[:args.max_subckts]

    for i, sub in enumerate(subckt_iter, start=1):
        fs = summary_map.get(sub.file_path)
        if args.only_suspect and fs and fs.status not in {"SUSPECT", "BROKEN_LIKELY", "READ_ERROR"}:
            continue

        file_path = Path(sub.file_path)
        deck_name = safe_name(sub.rel_path + "__" + sub.name) + "__subckt_test.cir"
        cir_path = decks_dir / deck_name
        cir_path.write_text(build_subckt_test_deck(file_path, sub.name, sub.pin_count), encoding="utf-8")
        cmd = f'"{ltspice_exe}" -b "{cir_path}"' if ltspice_exe else f'LTspice.exe -b "{cir_path}"'
        command_rows.append({
            "kind": "SUBCKT_INSTANTIATION",
            "file_path": sub.file_path,
            "rel_path": sub.rel_path,
            "target_name": sub.name,
            "cir_path": str(cir_path),
            "suggested_command": cmd,
        })

        if not args.no_batch and ltspice_exe is not None:
            exit_code, stdout, stderr = run_ltspice_batch(ltspice_exe, cir_path)
            log_text, raw_log_path = read_possible_log(cir_path)
            status, err = classify_log(log_text, stderr, exit_code)
            batch_results.append(BatchResult(
                target_kind="SUBCKT_INSTANTIATION",
                file_path=sub.file_path,
                rel_path=sub.rel_path,
                target_name=sub.name,
                test_cir=str(cir_path),
                status=status,
                exit_code=str(exit_code),
                error_summary=err,
                raw_log_path=str(raw_log_path) if raw_log_path else "",
            ))

        if i % 100 == 0 or i == len(subckt_iter):
            print(f"[INFO] Subckt tests préparés: {i}/{len(subckt_iter)}")

    write_csv(
        reports_dir / "batch_commands.csv",
        command_rows,
        fieldnames=list(command_rows[0].keys()) if command_rows else ["kind", "file_path", "rel_path", "target_name", "cir_path", "suggested_command"],
    )
    write_csv(
        reports_dir / "batch_results.csv",
        [asdict(x) for x in batch_results],
        fieldnames=list(asdict(batch_results[0]).keys()) if batch_results else list(BatchResult.__annotations__.keys()),
    )

    # Rapport synthèse
    broken = [x for x in summaries if x.status == "BROKEN_LIKELY"]
    suspect = [x for x in summaries if x.status == "SUSPECT"]
    likely_ok = [x for x in summaries if x.status == "LIKELY_OK"]
    read_err = [x for x in summaries if x.status == "READ_ERROR"]

    synth = out / "README_AUDIT.txt"
    synth.write_text(textwrap.dedent(f"""
    Audit LTspice third-party terminé.

    Racine auditée : {root}
    Dossier de sortie : {out}

    Résumé prescan :
    - Fichiers scannés       : {len(summaries)}
    - Sous-circuits trouvés  : {len(subckts)}
    - Modèles trouvés        : {len(models)}
    - Issues statiques       : {len(static_issues)}

    Classement prescan :
    - LIKELY_OK      : {len(likely_ok)}
    - SUSPECT        : {len(suspect)}
    - BROKEN_LIKELY  : {len(broken)}
    - READ_ERROR     : {len(read_err)}

    Fichiers de rapport :
    - reports/files_summary.csv
    - reports/static_issues.csv
    - reports/subckts.csv
    - reports/models.csv
    - reports/batch_commands.csv
    - reports/batch_results.csv

    Dossier des decks de test :
    - generated_test_decks/

    Conseils d'usage :
    1) Regarde d'abord static_issues.csv pour les erreurs structurelles évidentes.
    2) Regarde ensuite batch_results.csv pour les vraies erreurs remontées par LTspice.
    3) Priorise les catégories FAIL_SYNTAX, FAIL_INCLUDE et FAIL_SUBCKT.
    """).strip() + "\n", encoding="utf-8")

    print(f"[OK] Audit terminé. Rapports dans : {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
