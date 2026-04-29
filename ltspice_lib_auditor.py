#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LTspice third-party library auditor (parallel + cache + resume)
---------------------------------------------------------------
Objectif :
- scanner recursivement un dossier de librairies LTspice
- faire un pre-scan statique des fichiers SPICE
- extraire les .SUBCKT / .MODEL
- generer des decks de test LTspice
- lancer LTspice en batch en parallele si disponible
- produire des rapports CSV
- mettre en cache les resultats par hash de fichier (reprise/incremental)

Concu pour Windows + LTspice. Compatible Python 3.10+.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import datetime
import hashlib
import html as html_lib
import json
import multiprocessing
import os
import re
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional, Tuple, Dict, Any

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

# Cache : on stocke par hash de fichier ce qui a ete deja calcule.
# Bumper CACHE_VERSION si la logique de prescan / classification change.
CACHE_FILENAME = ".audit_cache.json"
CACHE_VERSION = 1
CACHE_SAVE_EVERY = 500  # sauve le cache toutes les N taches batch terminees

REPORT_FILENAME = "report.html"
REPORT_MAX_TABLE_ROWS = 10000  # tronque les tables au-dela (sinon HTML enorme)


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


# ---------------------------------------------------------------------------
# Helpers purs
# ---------------------------------------------------------------------------

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
    if re.match(r"^\s*\*", line):
        return ""
    if ";" in line:
        return line.split(";", 1)[0]
    return line


def count_parentheses_balance(text: str) -> Tuple[int, int]:
    return text.count("("), text.count(")")


def is_probably_table_suspicious(line: str) -> bool:
    if not TABLE_RE.search(line):
        return False
    stripped = strip_inline_comment(line)
    opens, closes = count_parentheses_balance(stripped)
    return opens != closes


def parse_subckt_signature(rest: str) -> Tuple[List[str], List[str]]:
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


def file_hash(path: Path) -> str:
    """Hash rapide du contenu (BLAKE2b 128 bits, plus rapide que SHA-1)."""
    h = hashlib.blake2b(digest_size=16)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def write_csv(path: Path, rows: Iterable[dict], fieldnames: List[str]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, dialect=CSV_DIALECT)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def load_cache(cache_path: Path) -> dict:
    empty = {"version": CACHE_VERSION, "files": {}, "batch": {}}
    if not cache_path.exists():
        return empty
    try:
        with cache_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("version") != CACHE_VERSION:
            print(f"[INFO] Cache version differente ({data.get('version')} != {CACHE_VERSION}), ignore.")
            return empty
        data.setdefault("files", {})
        data.setdefault("batch", {})
        return data
    except Exception as exc:
        print(f"[WARN] Cache illisible ({exc}), repart a zero.")
        return empty


def save_cache(cache_path: Path, cache: dict) -> None:
    tmp = cache_path.with_suffix(cache_path.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(cache, f)
        os.replace(tmp, cache_path)
    except Exception as exc:
        print(f"[WARN] Sauvegarde cache echouee: {exc}")


# ---------------------------------------------------------------------------
# Prescan (utilisable en main process et en worker)
# ---------------------------------------------------------------------------

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
                message="Ligne TABLE avec parentheses desequilibrees",
                excerpt=normalize_excerpt(line),
            ))
            syntax_score -= 15

        if abs(opens - closes) >= 2:
            issues.append(StaticIssue(
                file_path=str(path),
                rel_path=rel_path,
                line_no=idx,
                severity="WARN",
                category="PARENS_LINE",
                message=f"Parentheses desequilibrees sur la ligne: {opens} '(' vs {closes} ')'",
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
            message=f"Parentheses desequilibrees dans le fichier: {total_open} '(' vs {total_close} ')'",
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


def _prescan_worker(args: Tuple[str, str]) -> dict:
    """Worker top-level pour ProcessPoolExecutor (doit etre picklable)."""
    root_str, path_str = args
    root = Path(root_str)
    path = Path(path_str)
    rel = path_str
    try:
        rel = str(path.relative_to(root))
    except Exception:
        pass
    try:
        h = file_hash(path)
        summary, issues, subs, mods = prescan_file(root, path)
        return {
            "ok": True,
            "file_path": str(path),
            "rel_path": rel,
            "hash": h,
            "summary": asdict(summary),
            "issues": [asdict(x) for x in issues],
            "subckts": [asdict(x) for x in subs],
            "models": [asdict(x) for x in mods],
        }
    except Exception as exc:
        return {
            "ok": False,
            "file_path": str(path),
            "rel_path": rel,
            "extension": path.suffix.lower(),
            "error": f"{type(exc).__name__}: {exc}",
        }


# ---------------------------------------------------------------------------
# LTspice : detection executable + detection forme de commande + worker batch
# ---------------------------------------------------------------------------

def find_ltspice_exe(user_path: Optional[str]) -> Optional[Path]:
    if user_path:
        p = Path(user_path)
        return p if p.exists() else None
    for cand in DEFAULT_LTSPICE_CANDIDATES:
        p = Path(cand)
        if p.exists():
            return p
    return None


def build_file_parse_test_deck(file_path: Path) -> str:
    return textwrap.dedent(f"""
    * file-parse test
    .include "{file_path}"
    V1 in 0 0
    R1 in 0 1k
    .op
    .end
    """).strip() + "\n"


def build_subckt_test_deck(file_path: Path, subckt_name: str, pin_count: int) -> str:
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


def _cleanup_ltspice_artifacts(cir_path: Path, keep_raw: bool) -> None:
    """Supprime les fichiers lourds generes a cote du .cir, garde le .log."""
    if keep_raw:
        return
    base = cir_path.with_suffix("")
    for ext in (".raw", ".op.raw", ".net", ".fft"):
        f = base.with_name(base.name + ext)
        if f.exists():
            try:
                f.unlink()
            except Exception:
                pass


def detect_ltspice_cmd_form(ltspice_exe: Path, work_dir: Path) -> List[str]:
    """
    Sonde au demarrage quelle forme '-b' fonctionne pour cette version de LTspice.
    Retourne la liste d'arguments a inserer entre l'exe et le chemin du .cir.
    """
    probe = work_dir / "_probe_ltspice.cir"
    probe.write_text("* probe\nV1 a 0 1\nR1 a 0 1k\n.op\n.end\n", encoding="utf-8")
    candidates = [["-b"], ["-Run", "-b"], ["-run", "-b"]]
    chosen: List[str] = ["-b"]
    for cmd_args in candidates:
        try:
            proc = subprocess.run(
                [str(ltspice_exe), *cmd_args, str(probe)],
                capture_output=True, text=True, timeout=20, shell=False,
            )
            log_exists = probe.with_suffix(".log").exists()
            if proc.returncode == 0 or log_exists:
                chosen = cmd_args
                break
        except Exception:
            continue
    # nettoyage
    for ext in (".cir", ".log", ".raw", ".op.raw", ".net"):
        f = probe.with_suffix(ext)
        if f.exists():
            try:
                f.unlink()
            except Exception:
                pass
    return chosen


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


def _batch_worker(task: dict) -> dict:
    """Worker top-level pour ProcessPoolExecutor : execute LTspice sur 1 deck."""
    ltspice_exe = task["ltspice_exe"]
    cir_path = Path(task["cir_path"])
    timeout_s = int(task["timeout"])
    cmd_prefix = task["cmd_prefix"]
    keep_raw = bool(task.get("keep_raw", False))

    base = {
        "task_id": task["task_id"],
        "target_kind": task["target_kind"],
        "file_path": task["file_path"],
        "rel_path": task["rel_path"],
        "target_name": task["target_name"],
        "test_cir": str(cir_path),
    }

    cmd = [ltspice_exe, *cmd_prefix, str(cir_path)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s, shell=False
        )
        exit_code = proc.returncode
        stderr = proc.stderr or ""
    except subprocess.TimeoutExpired:
        _cleanup_ltspice_artifacts(cir_path, keep_raw)
        return {**base, "status": "TIMEOUT", "exit_code": "-1",
                "error_summary": f"Timeout apres {timeout_s}s", "raw_log_path": ""}
    except Exception as exc:
        return {**base, "status": "EXEC_ERROR", "exit_code": "-2",
                "error_summary": f"{type(exc).__name__}: {exc}", "raw_log_path": ""}

    log_text, raw_log_path = read_possible_log(cir_path)
    status, err = classify_log(log_text, stderr, exit_code)
    _cleanup_ltspice_artifacts(cir_path, keep_raw)

    return {
        **base,
        "status": status,
        "exit_code": str(exit_code),
        "error_summary": err,
        "raw_log_path": str(raw_log_path) if raw_log_path else "",
    }


# ---------------------------------------------------------------------------
# Helpers UI / progression
# ---------------------------------------------------------------------------

def fmt_eta(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds/60:.1f} min"
    return f"{seconds/3600:.2f} h"


# ---------------------------------------------------------------------------
# Rapport HTML (autonome, zero dependance externe)
# ---------------------------------------------------------------------------

def _h(s: Any) -> str:
    """Echappement HTML."""
    return html_lib.escape("" if s is None else str(s))


def _read_csv_dicts(path: Path) -> List[dict]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _bin_pin_count(n: int) -> str:
    if n <= 0:
        return "0 (autre)"
    if n <= 2:
        return "1-2"
    if n == 3:
        return "3"
    if n == 4:
        return "4"
    if n <= 6:
        return "5-6"
    if n <= 8:
        return "7-8"
    if n <= 16:
        return "9-16"
    return "17+"


def _build_recommendations(prescan_counts: Dict[str, int],
                           batch_counts: Dict[str, int]) -> List[str]:
    recs: List[str] = []
    bk = prescan_counts.get("BROKEN_LIKELY", 0)
    re_ = prescan_counts.get("READ_ERROR", 0)
    sus = prescan_counts.get("SUSPECT", 0)
    if re_:
        recs.append(f"{re_} fichier(s) en READ_ERROR — encodage probablement non géré, regarde la colonne <code>encoding</code>.")
    if bk:
        recs.append(f"{bk} fichier(s) BROKEN_LIKELY — structure SPICE clairement abîmée (.SUBCKT/.ENDS, parenthèses). Corrige avant tout retest.")
    if sus:
        recs.append(f"{sus} fichier(s) SUSPECT — motifs douteux mais peut-être faux positifs ; les FAIL_* du batch tranchent.")

    fs = batch_counts.get("FAIL_SYNTAX", 0)
    fi = batch_counts.get("FAIL_INCLUDE", 0)
    fsub = batch_counts.get("FAIL_SUBCKT", 0)
    fpin = batch_counts.get("FAIL_PINCOUNT", 0)
    fmis = batch_counts.get("FAIL_MISSING_SUBCKT", 0)
    ffat = batch_counts.get("FAIL_FATAL", 0)
    fto = batch_counts.get("TIMEOUT", 0)
    fother = batch_counts.get("FAIL_OTHER", 0)
    fexec = batch_counts.get("EXEC_ERROR", 0)

    if fs:
        recs.append(f"{fs} FAIL_SYNTAX — erreurs de syntaxe SPICE remontées par LTspice (parenthèses, opérateurs, virgules dans des TABLE).")
    if fi:
        recs.append(f"{fi} FAIL_INCLUDE — fichiers <code>.include</code> introuvables. Vérifie les chemins relatifs et les fichiers de dépendance.")
    if fsub:
        recs.append(f"{fsub} FAIL_SUBCKT — sous-circuits non instanciables. Souvent : interface mal détectée ou pin introuvable.")
    if fpin:
        recs.append(f"{fpin} FAIL_PINCOUNT — nombre de pins entre déclaration et instanciation incohérent.")
    if fmis:
        recs.append(f"{fmis} FAIL_MISSING_SUBCKT — un sous-circuit appelle un autre sous-circuit non défini.")
    if ffat:
        recs.append(f"{ffat} FAIL_FATAL — erreur fatale LTspice. À regarder en priorité.")
    if fto:
        recs.append(f"{fto} TIMEOUT — augmente <code>--timeout</code> pour ces fichiers, ou regarde s'ils contiennent des boucles infinies.")
    if fexec:
        recs.append(f"{fexec} EXEC_ERROR — échec du lancement de LTspice (chemin exe ?).")
    if fother:
        recs.append(f"{fother} FAIL_OTHER — erreurs non classifiées, regarde <code>error_summary</code> pour le détail.")

    if not recs:
        recs.append("Aucun problème majeur détecté. 🎉")
    return recs


def _bar_block(counts: Dict[str, int], total_override: Optional[int] = None,
               max_items: int = 50, ok_keys: Optional[set] = None,
               as_badge: bool = True) -> str:
    if not counts:
        return '<p class="no-data">aucune donnée</p>'
    ok_keys = ok_keys if ok_keys is not None else {"OK", "LIKELY_OK"}
    items = sorted(counts.items(), key=lambda x: -x[1])[:max_items]
    total = total_override if total_override is not None else max(1, sum(counts.values()))
    parts = []
    for key, n in items:
        pct = 100 * n / total if total else 0
        cls = "ok" if key in ok_keys else ""
        label_html = _h(key) or "(vide)"
        if as_badge:
            label = f'<span class="status {_h(key)}">{label_html}</span>'
        else:
            label = label_html
        parts.append(
            f'<div class="bar {cls}">'
            f'<span class="lbl">{label}</span>'
            f'<span class="fill" style="width:{min(400, max(2, pct*4)):.0f}px"></span>'
            f'<span class="num">{n} ({pct:.1f}%)</span>'
            f'</div>'
        )
    return "".join(parts)


REPORT_CSS = r"""
:root {
  --bg: #fafafa; --card: #ffffff; --txt: #222; --hdr: #1a3a5e;
  --border: #dcdcdc; --muted: #666;
  --bad: #c62828; --warn: #ef6c00; --ok: #2e7d32; --suspect: #f9a825;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: var(--txt); background: var(--bg); padding: 1.5rem 2rem 4rem; }
h1, h2, h3 { color: var(--hdr); }
h1 { margin: 0 0 .25rem; font-size: 1.7rem; }
h2 { border-bottom: 2px solid var(--hdr); padding-bottom: .3rem; margin-top: 2.2rem; font-size: 1.25rem; }
h3 { margin: 0 0 .5rem; font-size: 1rem; }
.meta { color: var(--muted); font-size: .9rem; margin-bottom: .5rem; }
code { background: #eee; padding: .1rem .35rem; border-radius: 3px; font-size: .9em; font-family: Consolas, Menlo, monospace; }
a { color: var(--hdr); }

.cards { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0 1.5rem; }
.card { background: var(--card); padding: .9rem 1.25rem; border-radius: 6px; border: 1px solid var(--border); min-width: 160px; flex: 1 1 160px; max-width: 240px; }
.card .num { font-size: 1.7rem; font-weight: 700; color: var(--hdr); line-height: 1.1; }
.card .label { color: var(--muted); font-size: .82rem; margin-top: .15rem; }

.recos { background: #fff8e1; border: 1px solid #ffe69c; padding: .8rem 1.2rem; border-radius: 6px; margin: .5rem 0 1rem; }
.recos ul { margin: .3rem 0 0; padding-left: 1.2rem; }
.recos li { margin: .25rem 0; }

.cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; }
.col-card { background: var(--card); padding: 1rem 1.2rem; border: 1px solid var(--border); border-radius: 6px; }

.bar { display: flex; align-items: center; gap: .5rem; margin: .25rem 0; }
.bar .lbl { width: 200px; font-size: .85rem; flex-shrink: 0; }
.bar .fill { background: linear-gradient(90deg, #d32f2f, #ef6c00); height: 16px; border-radius: 3px; flex-shrink: 0; }
.bar.ok .fill { background: linear-gradient(90deg, #2e7d32, #66bb6a); }
.bar .num { font-size: .82rem; color: var(--muted); }

table { width: 100%; border-collapse: collapse; background: var(--card); margin: .5rem 0 1rem; font-size: .87rem; box-shadow: 0 1px 2px rgba(0,0,0,.04); }
th, td { padding: .4rem .6rem; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }
th { background: #eef3f8; cursor: pointer; user-select: none; position: sticky; top: 0; z-index: 1; font-weight: 600; }
th:hover { background: #dde6f0; }
th.sorted-asc::after { content: " ▲"; color: var(--hdr); }
th.sorted-desc::after { content: " ▼"; color: var(--hdr); }
tbody tr:hover td { background: #fafbfd; }

.status { padding: .1rem .5rem; border-radius: 3px; font-size: .76rem; font-weight: 600; white-space: nowrap; display: inline-block; }
.status.OK, .status.LIKELY_OK { background: #e8f5e9; color: var(--ok); }
.status.WARN_LOG, .status.SUSPECT { background: #fff3e0; color: var(--warn); }
.status.UNKNOWN { background: #f5f5f5; color: #555; }
.status.BROKEN_LIKELY, .status.READ_ERROR, .status.TIMEOUT, .status.EXEC_ERROR,
.status.FAIL_SYNTAX, .status.FAIL_INCLUDE, .status.FAIL_SUBCKT, .status.FAIL_PINCOUNT,
.status.FAIL_FATAL, .status.FAIL_OTHER, .status.FAIL_MISSING_SUBCKT { background: #ffebee; color: var(--bad); }
.status.ENDS, .status.SUBCKT, .status.TABLE, .status.PARENS_FILE, .status.PARENS_LINE { background: #fff3e0; color: var(--warn); }

.toolbar { display: flex; gap: .5rem; align-items: center; margin: .4rem 0 .6rem; flex-wrap: wrap; }
.toolbar input[type=search] { padding: .35rem .55rem; border: 1px solid var(--border); border-radius: 4px; min-width: 240px; font-size: .9rem; }
.toolbar .count { color: var(--muted); font-size: .85rem; margin-left: .5rem; }

.notice { background: #fff3cd; border: 1px solid #ffe69c; padding: .5rem .9rem; border-radius: 4px; margin: .5rem 0; font-size: .87rem; }
.no-data { color: var(--muted); font-style: italic; padding: .8rem 0; }
.truncate { max-width: 600px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.excerpt { font-family: Consolas, Menlo, monospace; font-size: .8rem; color: #555; max-width: 520px; word-break: break-all; white-space: pre-wrap; }

footer { margin-top: 2.5rem; color: var(--muted); font-size: .82rem; text-align: center; }
"""

REPORT_JS = r"""
// Tri colonne
document.querySelectorAll('table.sortable').forEach(table => {
  table.querySelectorAll('thead th').forEach((th, idx) => {
    th.addEventListener('click', () => {
      const tbody = table.querySelector('tbody');
      const rows = Array.from(tbody.querySelectorAll('tr'));
      const asc = !th.classList.contains('sorted-asc');
      table.querySelectorAll('thead th').forEach(o => o.classList.remove('sorted-asc', 'sorted-desc'));
      th.classList.add(asc ? 'sorted-asc' : 'sorted-desc');
      rows.sort((a, b) => {
        const ac = a.children[idx], bc = b.children[idx];
        const av = (ac ? ac.textContent : '').trim();
        const bv = (bc ? bc.textContent : '').trim();
        const an = parseFloat(av), bn = parseFloat(bv);
        let cmp;
        if (!isNaN(an) && !isNaN(bn) && /^-?\d/.test(av) && /^-?\d/.test(bv)) cmp = an - bn;
        else cmp = av.localeCompare(bv, 'fr');
        return asc ? cmp : -cmp;
      });
      rows.forEach(r => tbody.appendChild(r));
    });
  });
});

// Recherche live
function applyFilter(input) {
  const q = input.value.toLowerCase().trim();
  const tableId = input.dataset.target;
  const table = document.getElementById(tableId);
  if (!table) return;
  let visible = 0;
  table.querySelectorAll('tbody tr').forEach(tr => {
    const txt = tr.textContent.toLowerCase();
    const show = !q || txt.includes(q);
    tr.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  const cnt = document.querySelector('span.count[data-for="' + tableId + '"]');
  if (cnt) cnt.textContent = visible + ' visible(s)';
}
document.querySelectorAll('input[type=search][data-target]').forEach(inp => {
  inp.addEventListener('input', () => applyFilter(inp));
  applyFilter(inp);
});
"""


def _render_overview_cards(n_files: int, n_subs: int, n_models: int,
                           n_static: int, n_batch: int,
                           n_batch_ok: int, n_batch_fail: int) -> str:
    pct_ok = (100 * n_batch_ok / n_batch) if n_batch else 0
    return (
        '<div class="cards">'
        f'<div class="card"><div class="num">{n_files}</div><div class="label">Fichiers scannés</div></div>'
        f'<div class="card"><div class="num">{n_subs}</div><div class="label">Sous-circuits</div></div>'
        f'<div class="card"><div class="num">{n_models}</div><div class="label">Modèles (.MODEL)</div></div>'
        f'<div class="card"><div class="num">{n_static}</div><div class="label">Issues statiques</div></div>'
        f'<div class="card"><div class="num">{n_batch}</div><div class="label">Tests LTspice</div></div>'
        f'<div class="card"><div class="num" style="color:#2e7d32">{n_batch_ok}</div><div class="label">OK ({pct_ok:.1f}%)</div></div>'
        f'<div class="card"><div class="num" style="color:#c62828">{n_batch_fail}</div><div class="label">Échecs LTspice</div></div>'
        '</div>'
    )


def _render_recommendations(recs: List[str]) -> str:
    if not recs:
        return ""
    lis = "".join(f"<li>{r}</li>" for r in recs)  # recs already pre-formatted with safe HTML <code>
    return f'<div class="recos"><h3>Recommandations</h3><ul>{lis}</ul></div>'


def _render_status_section(prescan_counts: Dict[str, int], batch_counts: Dict[str, int]) -> str:
    return (
        '<section><h2>Répartition par statut</h2><div class="cols">'
        '<div class="col-card"><h3>Statuts prescan</h3>'
        + _bar_block(prescan_counts) +
        '</div><div class="col-card"><h3>Statuts batch LTspice</h3>'
        + _bar_block(batch_counts) +
        '</div></div></section>'
    )


def _render_top_categories(batch_counts: Dict[str, int]) -> str:
    fail = {k: v for k, v in batch_counts.items()
            if k.startswith("FAIL") or k in {"TIMEOUT", "EXEC_ERROR", "WARN_LOG"}}
    if not fail:
        return ""
    return (
        '<section><h2>Top catégories d\'erreurs</h2>'
        + _bar_block(fail, total_override=sum(fail.values()), max_items=10)
        + '</section>'
    )


def _render_inventory(counts_ext: Dict[str, int],
                      counts_model_type: Dict[str, int],
                      counts_pin_bin: Dict[str, int]) -> str:
    return (
        '<section><h2>Inventaire (utile pour la réorganisation)</h2><div class="cols">'
        '<div class="col-card"><h3>Par extension</h3>'
        + _bar_block(counts_ext, ok_keys=set(), as_badge=False) +
        '</div><div class="col-card"><h3>Par type de modèle (.MODEL)</h3>'
        + _bar_block(counts_model_type, ok_keys=set(), as_badge=False) +
        '</div><div class="col-card"><h3>Par nombre de pins (.SUBCKT)</h3>'
        + _bar_block(counts_pin_bin, ok_keys=set(), as_badge=False) +
        '</div></div></section>'
    )


def _render_errored_files_table(err_rows: List[dict]) -> str:
    if not err_rows:
        return ('<section><h2>Fichiers avec erreurs</h2>'
                '<p class="no-data">Aucun fichier en erreur. 🎉</p></section>')
    truncated = len(err_rows) > REPORT_MAX_TABLE_ROWS
    rows = err_rows[:REPORT_MAX_TABLE_ROWS]
    body = []
    for r in rows:
        body.append(
            '<tr>'
            f'<td><code>{_h(r["rel_path"])}</code></td>'
            f'<td>{_h(r["extension"])}</td>'
            f'<td><span class="status {_h(r["status"])}">{_h(r["status"]) or "(vide)"}</span></td>'
            f'<td>{r["n_static"]}</td>'
            f'<td>{r["n_fail"]}</td>'
            f'<td class="truncate">{_h(r["categories"])}</td>'
            '</tr>'
        )
    notice = (f'<div class="notice">Tableau tronqué à {REPORT_MAX_TABLE_ROWS} lignes '
              f'sur {len(err_rows)}. Consulte les CSV pour la liste complète.</div>') if truncated else ""
    return (
        '<section><h2>Fichiers avec erreurs ' + f'({len(err_rows)})</h2>'
        '<div class="toolbar">'
        '<input type="search" data-target="tbl-errored" placeholder="filtrer (chemin, statut, catégorie)...">'
        '<span class="count" data-for="tbl-errored"></span>'
        '</div>'
        + notice +
        '<table id="tbl-errored" class="sortable"><thead><tr>'
        '<th>Fichier</th><th>Ext.</th><th>Statut</th>'
        '<th>Issues stat.</th><th>Échecs LTspice</th><th>Catégories</th>'
        '</tr></thead><tbody>' + "".join(body) + '</tbody></table></section>'
    )


def _render_static_issues_table(issues: List[dict]) -> str:
    if not issues:
        return ('<section><h2>Issues statiques (prescan)</h2>'
                '<p class="no-data">Aucune issue statique.</p></section>')
    truncated = len(issues) > REPORT_MAX_TABLE_ROWS
    rows = issues[:REPORT_MAX_TABLE_ROWS]
    body = []
    for it in rows:
        body.append(
            '<tr>'
            f'<td><code>{_h(it.get("rel_path",""))}</code></td>'
            f'<td>{_h(it.get("line_no",""))}</td>'
            f'<td><span class="status {_h(it.get("severity",""))}">{_h(it.get("severity",""))}</span></td>'
            f'<td><span class="status {_h(it.get("category",""))}">{_h(it.get("category",""))}</span></td>'
            f'<td>{_h(it.get("message",""))}</td>'
            f'<td class="excerpt">{_h(it.get("excerpt",""))}</td>'
            '</tr>'
        )
    notice = (f'<div class="notice">Tableau tronqué à {REPORT_MAX_TABLE_ROWS} lignes '
              f'sur {len(issues)}.</div>') if truncated else ""
    return (
        '<section><h2>Issues statiques (prescan) ' + f'({len(issues)})</h2>'
        '<div class="toolbar">'
        '<input type="search" data-target="tbl-static" placeholder="filtrer (catégorie, message, fichier)...">'
        '<span class="count" data-for="tbl-static"></span>'
        '</div>'
        + notice +
        '<table id="tbl-static" class="sortable"><thead><tr>'
        '<th>Fichier</th><th>L.</th><th>Sév.</th><th>Catégorie</th>'
        '<th>Message</th><th>Extrait</th>'
        '</tr></thead><tbody>' + "".join(body) + '</tbody></table></section>'
    )


def _render_batch_failures_table(batch: List[dict]) -> str:
    fails = [b for b in batch
             if b.get("status", "").startswith("FAIL")
             or b.get("status") in {"TIMEOUT", "EXEC_ERROR", "WARN_LOG", "UNKNOWN"}]
    if not batch:
        return ('<section><h2>Échecs LTspice</h2>'
                '<p class="no-data">Aucun test batch (mode --no-batch ?).</p></section>')
    if not fails:
        return ('<section><h2>Échecs LTspice</h2>'
                '<p class="no-data">Aucun échec côté LTspice. 🎉</p></section>')
    truncated = len(fails) > REPORT_MAX_TABLE_ROWS
    rows = fails[:REPORT_MAX_TABLE_ROWS]
    body = []
    for b in rows:
        body.append(
            '<tr>'
            f'<td><code>{_h(b.get("rel_path",""))}</code></td>'
            f'<td>{_h(b.get("target_kind",""))}</td>'
            f'<td><code>{_h(b.get("target_name",""))}</code></td>'
            f'<td><span class="status {_h(b.get("status",""))}">{_h(b.get("status",""))}</span></td>'
            f'<td>{_h(b.get("exit_code",""))}</td>'
            f'<td class="excerpt">{_h(b.get("error_summary",""))}</td>'
            '</tr>'
        )
    notice = (f'<div class="notice">Tableau tronqué à {REPORT_MAX_TABLE_ROWS} lignes '
              f'sur {len(fails)}.</div>') if truncated else ""
    return (
        '<section><h2>Échecs LTspice ' + f'({len(fails)})</h2>'
        '<div class="toolbar">'
        '<input type="search" data-target="tbl-batch" placeholder="filtrer (statut, fichier, message)...">'
        '<span class="count" data-for="tbl-batch"></span>'
        '</div>'
        + notice +
        '<table id="tbl-batch" class="sortable"><thead><tr>'
        '<th>Fichier</th><th>Type</th><th>Cible</th>'
        '<th>Statut</th><th>Exit</th><th>Résumé erreur</th>'
        '</tr></thead><tbody>' + "".join(body) + '</tbody></table></section>'
    )


def generate_html_report(out_dir: Path) -> Optional[Path]:
    reports_dir = out_dir / "reports"
    if not reports_dir.exists():
        print(f"[WARN] {reports_dir} introuvable, pas de rapport HTML genere.")
        return None

    summaries = _read_csv_dicts(reports_dir / "files_summary.csv")
    static_issues = _read_csv_dicts(reports_dir / "static_issues.csv")
    subckts = _read_csv_dicts(reports_dir / "subckts.csv")
    models = _read_csv_dicts(reports_dir / "models.csv")
    batch_results = _read_csv_dicts(reports_dir / "batch_results.csv")

    n_files = len(summaries)
    n_subs = len(subckts)
    n_models = len(models)
    n_static = len(static_issues)
    n_batch = len(batch_results)

    prescan_counts: Dict[str, int] = {}
    for s in summaries:
        st = s.get("status", "") or "(vide)"
        prescan_counts[st] = prescan_counts.get(st, 0) + 1

    batch_counts: Dict[str, int] = {}
    for b in batch_results:
        st = b.get("status", "") or "(vide)"
        batch_counts[st] = batch_counts.get(st, 0) + 1

    n_batch_ok = batch_counts.get("OK", 0)
    n_batch_fail = sum(c for s, c in batch_counts.items()
                       if s.startswith("FAIL") or s in {"TIMEOUT", "EXEC_ERROR"})

    # Inventaire
    counts_ext: Dict[str, int] = {}
    for s in summaries:
        e = s.get("extension", "") or "(vide)"
        counts_ext[e] = counts_ext.get(e, 0) + 1

    counts_model_type: Dict[str, int] = {}
    for m in models:
        t = (m.get("model_type", "") or "(vide)").upper()
        counts_model_type[t] = counts_model_type.get(t, 0) + 1

    counts_pin_bin: Dict[str, int] = {}
    for s in subckts:
        try:
            n = int(s.get("pin_count", "0") or "0")
        except ValueError:
            n = 0
        b = _bin_pin_count(n)
        counts_pin_bin[b] = counts_pin_bin.get(b, 0) + 1

    # Index pour aggregation par fichier
    issues_by_path: Dict[str, List[dict]] = {}
    for it in static_issues:
        issues_by_path.setdefault(it.get("file_path", ""), []).append(it)

    batch_by_path: Dict[str, List[dict]] = {}
    for b in batch_results:
        batch_by_path.setdefault(b.get("file_path", ""), []).append(b)

    sm_by_path = {s.get("file_path", ""): s for s in summaries}

    # Fichiers avec erreurs
    errored_paths = set()
    for s in summaries:
        if s.get("status") in {"SUSPECT", "BROKEN_LIKELY", "READ_ERROR"}:
            errored_paths.add(s.get("file_path", ""))
    for it in static_issues:
        errored_paths.add(it.get("file_path", ""))
    for b in batch_results:
        st = b.get("status", "")
        if st.startswith("FAIL") or st in {"TIMEOUT", "EXEC_ERROR", "WARN_LOG", "UNKNOWN"}:
            errored_paths.add(b.get("file_path", ""))
    errored_paths.discard("")

    severity_order = {"READ_ERROR": 0, "BROKEN_LIKELY": 1, "SUSPECT": 2, "LIKELY_OK": 3, "": 4}
    err_rows: List[dict] = []
    for fp in errored_paths:
        s = sm_by_path.get(fp, {})
        issues = issues_by_path.get(fp, [])
        batches = batch_by_path.get(fp, [])
        n_st = len(issues)
        n_fl = sum(1 for b in batches
                   if b.get("status", "").startswith("FAIL")
                   or b.get("status") in {"TIMEOUT", "EXEC_ERROR"})
        cats = {b.get("status", "") for b in batches
                if b.get("status", "") not in {"OK", "", "UNKNOWN"}}
        cats |= {it.get("category", "") for it in issues}
        cats.discard("")
        err_rows.append({
            "rel_path": s.get("rel_path", fp),
            "file_path": fp,
            "extension": s.get("extension", ""),
            "status": s.get("status", ""),
            "n_static": n_st,
            "n_fail": n_fl,
            "categories": ", ".join(sorted(cats)),
        })
    err_rows.sort(key=lambda r: (severity_order.get(r["status"], 9), r["rel_path"]))

    # Recos
    recs = _build_recommendations(prescan_counts, batch_counts)

    # Composition HTML
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    parts: List[str] = []
    parts.append(
        '<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>Audit LTspice — Rapport</title><style>{REPORT_CSS}</style></head><body>'
    )
    parts.append(
        f'<header><h1>Audit LTspice — rapport</h1>'
        f'<p class="meta">Généré le {now} — dossier de sortie : <code>{_h(str(out_dir))}</code></p></header>'
    )
    parts.append(_render_overview_cards(n_files, n_subs, n_models, n_static, n_batch, n_batch_ok, n_batch_fail))
    parts.append(_render_recommendations(recs))
    parts.append(_render_status_section(prescan_counts, batch_counts))
    parts.append(_render_top_categories(batch_counts))
    parts.append(_render_inventory(counts_ext, counts_model_type, counts_pin_bin))
    parts.append(_render_errored_files_table(err_rows))
    parts.append(_render_static_issues_table(static_issues))
    parts.append(_render_batch_failures_table(batch_results))
    parts.append('<footer>Rapport autonome — généré par ltspice_lib_auditor.py</footer>')
    parts.append(f'<script>{REPORT_JS}</script></body></html>')

    out_path = out_dir / REPORT_FILENAME
    out_path.write_text("".join(parts), encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit automatise de librairies LTspice third-party (parallele + cache)"
    )
    parser.add_argument("--root", default="", help="Dossier racine de la librairie a auditer (requis sauf --report-only)")
    parser.add_argument("--out", required=True, help="Dossier de sortie pour rapports et decks")
    parser.add_argument("--ltspice", default="", help="Chemin vers LTspice.exe / XVIIx64.exe")
    parser.add_argument("--extensions", default=".lib,.sub,.cir,.mod,.txt,.si",
                        help="Extensions a scanner, separees par des virgules")
    parser.add_argument("--no-batch", action="store_true",
                        help="N'execute pas LTspice ; genere seulement les decks et les commandes")
    parser.add_argument("--only-suspect", action="store_true",
                        help="Ne lance les tests batch que pour les fichiers SUSPECT/BROKEN_LIKELY/READ_ERROR")
    parser.add_argument("--skip-broken-batch", action="store_true",
                        help="Saute les BROKEN_LIKELY/READ_ERROR au batch (deja juges casses)")
    parser.add_argument("--max-files", type=int, default=0,
                        help="Limite le nombre de fichiers scannes (0 = illimite)")
    parser.add_argument("--max-subckts", type=int, default=0,
                        help="Limite le nombre de sous-circuits testes (0 = illimite)")
    parser.add_argument("-j", "--jobs", type=int, default=0,
                        help="Nombre de workers paralleles (0 = auto = max(1, cpu-1))")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Timeout LTspice par test, en secondes (defaut 15)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Ignore le cache et relance tout (n'ecrit pas non plus de cache)")
    parser.add_argument("--keep-raw", action="store_true",
                        help="Conserve les .raw / .net generes par LTspice (consomme du disque)")
    parser.add_argument("--no-report", action="store_true",
                        help="Ne genere pas le rapport HTML en fin d'audit")
    parser.add_argument("--report-only", action="store_true",
                        help="Regenere uniquement le rapport HTML depuis les CSV existants (pas d'audit)")
    args = parser.parse_args()

    out = Path(args.out).expanduser().resolve()

    # Mode --report-only : on saute tout l'audit, on regenere juste le HTML
    if args.report_only:
        if not (out / "reports").exists():
            print(f"[ERREUR] {out / 'reports'} introuvable. Lance d'abord un audit complet.")
            return 2
        p = generate_html_report(out)
        if p:
            print(f"[OK] Rapport regenere : {p}")
            return 0
        return 2

    if not args.root:
        print("[ERREUR] --root est requis (sauf en mode --report-only).")
        return 2

    root = Path(args.root).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"[ERREUR] Dossier racine introuvable: {root}")
        return 2

    ensure_dir(out)
    reports_dir = out / "reports"
    decks_dir = out / "generated_test_decks"
    ensure_dir(reports_dir)
    ensure_dir(decks_dir)

    cpu = os.cpu_count() or 2
    jobs = args.jobs if args.jobs > 0 else max(1, cpu - 1)

    exts = {e.strip().lower() if e.strip().startswith(".") else "." + e.strip().lower()
            for e in args.extensions.split(",") if e.strip()}

    files = list_candidate_files(root, exts)
    if args.max_files and args.max_files > 0:
        files = files[:args.max_files]

    print(f"[INFO] Racine          : {root}")
    print(f"[INFO] Sortie          : {out}")
    print(f"[INFO] Fichiers cands. : {len(files)}")
    print(f"[INFO] Jobs paralleles : {jobs} (CPU detectes: {cpu})")
    print(f"[INFO] Timeout LTspice : {args.timeout}s")

    cache_path = out / CACHE_FILENAME
    cache = {"version": CACHE_VERSION, "files": {}, "batch": {}}
    if not args.no_cache:
        cache = load_cache(cache_path)
        n_cached_f = len(cache.get("files", {}))
        n_cached_b = len(cache.get("batch", {}))
        if n_cached_f or n_cached_b:
            print(f"[INFO] Cache charge    : {n_cached_f} fichier(s), {n_cached_b} test(s) batch.")

    # ============================================================
    # PRESCAN PARALLELE (avec hits cache)
    # ============================================================
    t_pre = time.time()

    summaries: List[FileSummary] = []
    static_issues: List[StaticIssue] = []
    subckts: List[SubcktInfo] = []
    models: List[ModelInfo] = []
    file_hashes: Dict[str, str] = {}

    to_scan: List[Path] = []
    cached_hits = 0
    for fp in files:
        try:
            h = file_hash(fp)
        except Exception:
            to_scan.append(fp)
            continue
        cached = cache["files"].get(str(fp))
        if cached and cached.get("hash") == h:
            try:
                summaries.append(FileSummary(**cached["summary"]))
                static_issues.extend(StaticIssue(**x) for x in cached.get("issues", []))
                subckts.extend(SubcktInfo(**x) for x in cached.get("subckts", []))
                models.extend(ModelInfo(**x) for x in cached.get("models", []))
                file_hashes[str(fp)] = h
                cached_hits += 1
            except Exception:
                # Cache structurellement corrompu pour ce fichier -> rescan
                to_scan.append(fp)
        else:
            to_scan.append(fp)

    print(f"[INFO] Cache prescan   : {cached_hits} hit / {len(to_scan)} a (re)scanner.")

    if to_scan:
        worker_args = [(str(root), str(p)) for p in to_scan]
        done = 0
        with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as exe:
            for res in exe.map(_prescan_worker, worker_args, chunksize=16):
                done += 1
                if res["ok"]:
                    summaries.append(FileSummary(**res["summary"]))
                    static_issues.extend(StaticIssue(**x) for x in res["issues"])
                    subckts.extend(SubcktInfo(**x) for x in res["subckts"])
                    models.extend(ModelInfo(**x) for x in res["models"])
                    file_hashes[res["file_path"]] = res["hash"]
                    if not args.no_cache:
                        cache["files"][res["file_path"]] = {
                            "hash": res["hash"],
                            "summary": res["summary"],
                            "issues": res["issues"],
                            "subckts": res["subckts"],
                            "models": res["models"],
                        }
                else:
                    summaries.append(FileSummary(
                        file_path=res["file_path"],
                        rel_path=res["rel_path"],
                        extension=res["extension"],
                        encoding="ERROR",
                        line_count=0, char_count=0,
                        subckt_count=0, model_count=0, include_count=0,
                        syntax_score=0, status="READ_ERROR",
                        issues=res["error"],
                    ))
                if done % 500 == 0 or done == len(to_scan):
                    print(f"[INFO] Prescan: {done}/{len(to_scan)}")

        if not args.no_cache:
            save_cache(cache_path, cache)

    print(f"[INFO] Prescan termine en {time.time() - t_pre:.1f}s.")

    # Tri stable des sorties
    summaries.sort(key=lambda x: x.rel_path)
    static_issues.sort(key=lambda x: (x.rel_path, x.line_no))
    subckts.sort(key=lambda x: (x.rel_path, x.line_no))
    models.sort(key=lambda x: (x.rel_path, x.line_no))

    # ============================================================
    # CSV PRESCAN
    # ============================================================
    write_csv(
        reports_dir / "files_summary.csv",
        [asdict(x) for x in summaries],
        fieldnames=list(FileSummary.__annotations__.keys()),
    )
    write_csv(
        reports_dir / "static_issues.csv",
        [asdict(x) for x in static_issues],
        fieldnames=list(StaticIssue.__annotations__.keys()),
    )
    write_csv(
        reports_dir / "subckts.csv",
        [asdict(x) for x in subckts],
        fieldnames=list(SubcktInfo.__annotations__.keys()),
    )
    write_csv(
        reports_dir / "models.csv",
        [asdict(x) for x in models],
        fieldnames=list(ModelInfo.__annotations__.keys()),
    )

    # ============================================================
    # PREPARATION BATCH
    # ============================================================
    summary_map: Dict[str, FileSummary] = {x.file_path: x for x in summaries}
    command_rows: List[dict] = []
    tasks: List[dict] = []
    batch_results: List[BatchResult] = []

    ltspice_exe = find_ltspice_exe(args.ltspice.strip() or None)
    if args.no_batch:
        print("[INFO] Mode no-batch active : decks generes sans execution.")
    elif ltspice_exe is None:
        print("[WARN] LTspice introuvable. Utilise --ltspice \"...\" ou --no-batch.")
    else:
        print(f"[INFO] LTspice detecte : {ltspice_exe}")

    cmd_prefix: List[str] = ["-b"]
    if not args.no_batch and ltspice_exe is not None:
        cmd_prefix = detect_ltspice_cmd_form(ltspice_exe, decks_dir)
        print(f"[INFO] Forme de cmd    : {' '.join(cmd_prefix)}")

    def file_skip_for_batch(fs: FileSummary) -> bool:
        if args.only_suspect and fs.status not in {"SUSPECT", "BROKEN_LIKELY", "READ_ERROR"}:
            return True
        if args.skip_broken_batch and fs.status in {"BROKEN_LIKELY", "READ_ERROR"}:
            return True
        return False

    def make_cmd_str(cir_path: Path) -> str:
        if ltspice_exe:
            return f'"{ltspice_exe}" ' + " ".join(cmd_prefix) + f' "{cir_path}"'
        return f'LTspice.exe -b "{cir_path}"'

    # Test 1 : parsing par fichier
    for fs in summaries:
        if file_skip_for_batch(fs):
            continue
        file_path = Path(fs.file_path)
        deck_name = safe_name(fs.rel_path) + "__file_parse_test.cir"
        cir_path = decks_dir / deck_name
        cir_path.write_text(build_file_parse_test_deck(file_path), encoding="utf-8")
        command_rows.append({
            "kind": "FILE_PARSE",
            "file_path": fs.file_path,
            "rel_path": fs.rel_path,
            "target_name": "(file)",
            "cir_path": str(cir_path),
            "suggested_command": make_cmd_str(cir_path),
        })
        if not args.no_batch and ltspice_exe is not None:
            file_h = file_hashes.get(fs.file_path, "no_hash")
            task_id = f"{file_h}|FILE_PARSE|(file)"
            tasks.append({
                "task_id": task_id,
                "target_kind": "FILE_PARSE",
                "file_path": fs.file_path,
                "rel_path": fs.rel_path,
                "target_name": "(file)",
                "cir_path": str(cir_path),
                "ltspice_exe": str(ltspice_exe),
                "cmd_prefix": cmd_prefix,
                "timeout": args.timeout,
                "keep_raw": args.keep_raw,
            })

    # Test 2 : sous-circuits
    subckt_iter = subckts
    if args.max_subckts and args.max_subckts > 0:
        subckt_iter = subckt_iter[:args.max_subckts]

    for sub in subckt_iter:
        fs = summary_map.get(sub.file_path)
        if fs and file_skip_for_batch(fs):
            continue
        file_path = Path(sub.file_path)
        deck_name = safe_name(sub.rel_path + "__" + sub.name) + "__subckt_test.cir"
        cir_path = decks_dir / deck_name
        cir_path.write_text(build_subckt_test_deck(file_path, sub.name, sub.pin_count), encoding="utf-8")
        command_rows.append({
            "kind": "SUBCKT_INSTANTIATION",
            "file_path": sub.file_path,
            "rel_path": sub.rel_path,
            "target_name": sub.name,
            "cir_path": str(cir_path),
            "suggested_command": make_cmd_str(cir_path),
        })
        if not args.no_batch and ltspice_exe is not None:
            file_h = file_hashes.get(sub.file_path, "no_hash")
            task_id = f"{file_h}|SUBCKT_INSTANTIATION|{sub.name}"
            tasks.append({
                "task_id": task_id,
                "target_kind": "SUBCKT_INSTANTIATION",
                "file_path": sub.file_path,
                "rel_path": sub.rel_path,
                "target_name": sub.name,
                "cir_path": str(cir_path),
                "ltspice_exe": str(ltspice_exe),
                "cmd_prefix": cmd_prefix,
                "timeout": args.timeout,
                "keep_raw": args.keep_raw,
            })

    write_csv(
        reports_dir / "batch_commands.csv",
        command_rows,
        fieldnames=["kind", "file_path", "rel_path", "target_name", "cir_path", "suggested_command"],
    )

    # ============================================================
    # CACHE BATCH : recupere ce qui a deja ete teste
    # ============================================================
    if tasks and not args.no_cache:
        kept_tasks: List[dict] = []
        cache_hits = 0
        for t in tasks:
            cached = cache["batch"].get(t["task_id"])
            if cached:
                try:
                    batch_results.append(BatchResult(
                        target_kind=cached["target_kind"],
                        file_path=cached["file_path"],
                        rel_path=cached["rel_path"],
                        target_name=cached["target_name"],
                        test_cir=cached["test_cir"],
                        status=cached["status"],
                        exit_code=cached["exit_code"],
                        error_summary=cached["error_summary"],
                        raw_log_path=cached["raw_log_path"],
                    ))
                    cache_hits += 1
                except Exception:
                    kept_tasks.append(t)
            else:
                kept_tasks.append(t)
        print(f"[INFO] Cache batch     : {cache_hits} hit / {len(kept_tasks)} a executer.")
        tasks = kept_tasks

    # ============================================================
    # EXECUTION BATCH PARALLELE
    # ============================================================
    if tasks:
        print(f"[INFO] Lancement batch : {len(tasks)} tests, {jobs} workers, timeout={args.timeout}s")
        t0 = time.time()
        completed = 0
        last_save = 0

        try:
            with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as exe:
                futures = {exe.submit(_batch_worker, t): t for t in tasks}
                for fut in concurrent.futures.as_completed(futures):
                    try:
                        res = fut.result()
                    except Exception as exc:
                        t = futures[fut]
                        res = {
                            "task_id": t["task_id"],
                            "target_kind": t["target_kind"],
                            "file_path": t["file_path"],
                            "rel_path": t["rel_path"],
                            "target_name": t["target_name"],
                            "test_cir": t["cir_path"],
                            "status": "EXEC_ERROR",
                            "exit_code": "-9",
                            "error_summary": f"{type(exc).__name__}: {exc}",
                            "raw_log_path": "",
                        }

                    batch_results.append(BatchResult(
                        target_kind=res["target_kind"],
                        file_path=res["file_path"],
                        rel_path=res["rel_path"],
                        target_name=res["target_name"],
                        test_cir=res["test_cir"],
                        status=res["status"],
                        exit_code=res["exit_code"],
                        error_summary=res["error_summary"],
                        raw_log_path=res["raw_log_path"],
                    ))
                    if not args.no_cache:
                        cache["batch"][res["task_id"]] = res
                    completed += 1

                    if not args.no_cache and (completed - last_save >= CACHE_SAVE_EVERY):
                        save_cache(cache_path, cache)
                        last_save = completed

                    if completed % 50 == 0 or completed == len(tasks):
                        elapsed = time.time() - t0
                        rate = completed / elapsed if elapsed > 0 else 0
                        eta_s = (len(tasks) - completed) / rate if rate > 0 else 0
                        pct = 100 * completed / len(tasks)
                        print(f"[INFO] Batch: {completed}/{len(tasks)} ({pct:.1f}%) "
                              f"- {rate*60:.0f} tests/min - ETA {fmt_eta(eta_s)}")
        except KeyboardInterrupt:
            print("[WARN] Interruption clavier. Sauvegarde du cache avant sortie...")
            if not args.no_cache:
                save_cache(cache_path, cache)
            raise

        if not args.no_cache:
            save_cache(cache_path, cache)
        print(f"[INFO] Batch termine en {fmt_eta(time.time() - t0)}.")
    elif not args.no_batch and ltspice_exe is not None:
        print("[INFO] Tous les tests batch sont en cache, rien a executer.")

    # Tri stable
    batch_results.sort(key=lambda x: (x.rel_path, x.target_kind, x.target_name))

    write_csv(
        reports_dir / "batch_results.csv",
        [asdict(x) for x in batch_results],
        fieldnames=list(BatchResult.__annotations__.keys()),
    )

    # ============================================================
    # SYNTHESE
    # ============================================================
    broken = [x for x in summaries if x.status == "BROKEN_LIKELY"]
    suspect = [x for x in summaries if x.status == "SUSPECT"]
    likely_ok = [x for x in summaries if x.status == "LIKELY_OK"]
    read_err = [x for x in summaries if x.status == "READ_ERROR"]

    fail_count = sum(1 for x in batch_results
                     if x.status.startswith("FAIL") or x.status in {"TIMEOUT", "EXEC_ERROR"})
    ok_count = sum(1 for x in batch_results if x.status == "OK")
    warn_count = sum(1 for x in batch_results if x.status == "WARN_LOG")

    synth_text = textwrap.dedent(f"""
    Audit LTspice third-party termine.

    Racine auditee   : {root}
    Dossier de sortie: {out}
    Jobs paralleles  : {jobs}
    Timeout LTspice  : {args.timeout}s
    Cache utilise    : {"non" if args.no_cache else f"oui ({cache_path.name})"}

    Resume prescan :
    - Fichiers scannes       : {len(summaries)}
    - Sous-circuits trouves  : {len(subckts)}
    - Modeles trouves        : {len(models)}
    - Issues statiques       : {len(static_issues)}

    Classement prescan :
    - LIKELY_OK      : {len(likely_ok)}
    - SUSPECT        : {len(suspect)}
    - BROKEN_LIKELY  : {len(broken)}
    - READ_ERROR     : {len(read_err)}

    Resume batch LTspice :
    - Tests cumules  : {len(batch_results)}
    - OK             : {ok_count}
    - WARN_LOG       : {warn_count}
    - Echecs         : {fail_count}

    Fichiers de rapport :
    - reports/files_summary.csv
    - reports/static_issues.csv
    - reports/subckts.csv
    - reports/models.csv
    - reports/batch_commands.csv
    - reports/batch_results.csv

    Conseils d'usage :
    1) Regarde d'abord static_issues.csv pour les erreurs structurelles.
    2) Regarde batch_results.csv pour les vraies erreurs LTspice.
    3) Priorise FAIL_SYNTAX, FAIL_INCLUDE, FAIL_SUBCKT.
    4) Une 2eme execution (sans --no-cache) ne re-teste que les fichiers modifies.
    """).strip() + "\n"

    (out / "README_AUDIT.txt").write_text(synth_text, encoding="utf-8")

    if not args.no_report:
        try:
            p = generate_html_report(out)
            if p:
                print(f"[INFO] Rapport HTML : {p}")
        except Exception as exc:
            print(f"[WARN] Generation du rapport HTML echouee: {type(exc).__name__}: {exc}")

    print(f"[OK] Audit termine. Rapports dans : {out}")
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
