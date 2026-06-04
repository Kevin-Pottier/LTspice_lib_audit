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
import shutil
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

# Fix bundle (Vague 4) : paquet portable de sources + logs + JSON pour fix assiste
BUNDLE_DIRNAME = "fix_bundle"
BUNDLE_DEFAULT_MAX_FILES = 100      # cap par defaut du nb de fichiers embarques
BUNDLE_MAX_SOURCE_SIZE = 1024 * 1024  # 1 MB max par fichier source copie
BUNDLE_MAX_LOG_SIZE = 256 * 1024      # 256 KB max par log copie
BUNDLE_LOG_HEAD_LINES = 5
BUNDLE_LOG_TAIL_LINES = 40


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


def build_subckt_group_test_deck(file_path: Path, members: List[Tuple[str, int]]) -> str:
    """
    Construit un deck testant N sous-circuits du meme fichier en une seule
    invocation LTspice. Chaque XU est isole dans son propre namespace de noeuds
    (g{i}_n{j}), donc pas de collisions entre subckts du groupe.
    """
    lines = ['* subckt-group test', f'.include "{file_path}"']
    for i, (name, pin_count) in enumerate(members, start=1):
        n_pins = max(pin_count, 1)
        nodes = [f"g{i}_n{j}" for j in range(1, n_pins + 1)]
        for j, node in enumerate(nodes, start=1):
            lines.append(f"V{i}_{j} {node} 0 0")
        lines.append(f"XU{i} {' '.join(nodes)} {name}")
    lines.append(".op")
    lines.append(".end")
    return "\n".join(lines) + "\n"


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


LTSPICE_BANNER_RE = re.compile(r'^\s*LTspice\s+\S+\s+for\s+', re.IGNORECASE)

# Lignes d'entete/info BENIGNES : presentes dans TOUT log LTspice, meme en cas
# de succes complet. Sert uniquement a reconnaitre un resume "non-erreur" lors
# de la migration du cache. La classification (classify_log) n'en depend pas :
# elle utilise une detection POSITIVE des erreurs (cf. ci-dessous).
LTSPICE_BENIGN_HEADER_RE = re.compile(
    r'^\s*('
    r'LTspice\s+\S+\s+for\b'           # "LTspice 26.0.1 for Windows"
    r'|Circuit\s*:'                     # "Circuit: C:\...cir"
    r'|Start Time\s*:'                  # "Start Time: Wed Jun 3 ..."
    r'|Date\s*:'
    r'|solver\s*='                      # "solver = Normal"
    r'|Maximum thread count'
    r'|Matrix Compiler'
    r'|Reduced\b'                       # "Reduced ... to N nodes"
    r'|Total elapsed time'
    r'|Direct Newton iteration'
    r'|tnom\s*='
    r'|temp\s*='
    r'|method\s*='
    r'|BypassMode'
    r'|Copyright'
    r'|Compilation time'
    r'|Pass\s+\d'
    r'|\*'                              # commentaire SPICE
    r')',
    re.IGNORECASE,
)

# Detection POSITIVE d'une vraie erreur. Deux signaux fiables :
# 1) le format LTspice "fichier(NNN): message"  -> toute erreur de parse/elaboration
# 2) un mot-cle d'erreur runtime sans numero de ligne (fatal, singular, etc.)
LTSPICE_FILE_ERROR_RE = re.compile(r'\(\d+\)\s*:\s*\S')
LTSPICE_RUNTIME_ERROR_RE = re.compile(
    r'\b('
    r'fatal error|singular matrix|no dc (analysis )?path|timestep too small'
    r'|iteration limit|convergence (fail|problem)|analysis failed'
    r'|unknown subcircuit|cannot be instantiated|too few nodes|too many nodes'
    r'|more than one sub-?circuit|undefined model|no such parameter'
    r'|missing\b.*\bparameter|multiple definition|already defined'
    r'|syntax error|unexpected input'
    r')\b',
    re.IGNORECASE,
)

# Notes BENIGNES : LTspice signale qqch mais charge/simule quand meme. Pour un
# audit "le composant fonctionne-t-il ?", ce ne sont PAS des echecs.
LTSPICE_BENIGN_NOTE_RE = re.compile(
    r'((?:^|:\s*)Note\s*:'              # "...(54): Note: The caret character means XOR..."
    r'|may or may not be a problem'     # "Ignoring unknown model parameter. This may..."
    r'|will be ignored'                 # "Ncycles must be positive, will be ignored"
    r'|Missing value, assuming'         # assomption de valeur par defaut
    r'|assuming .*@ DC'
    r'|has zero rise/fall'              # avertissement timing A-device, simule quand meme
    r')',
    re.IGNORECASE,
)


def _first_real_error_line(text: str) -> Optional[str]:
    """Retourne la 1re ligne indiquant une VRAIE erreur LTspice, sinon None.
    Robuste face a l'entete benin (banniere, Circuit:, Start Time:, solver=...)
    ET aux notes informatives (Note:, 'may or may not be a problem', ...) que
    LTspice emet sans empecher le chargement du composant."""
    if not text:
        return None
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln:
            continue
        if LTSPICE_BENIGN_HEADER_RE.match(ln):
            continue
        if LTSPICE_BENIGN_NOTE_RE.search(ln):
            continue
        if LTSPICE_FILE_ERROR_RE.search(ln) or LTSPICE_RUNTIME_ERROR_RE.search(ln):
            return ln
    return None


def classify_log(log_text: str, stderr: str, exit_code: int) -> Tuple[str, str]:
    text = "\n".join([log_text or "", stderr or ""]).strip()

    if not text and exit_code == 0:
        return "OK", ""

    lower = text.lower()
    # Categories specifiques (donnent un libelle d'erreur parlant)
    if "expected \")\"" in lower:
        return "FAIL_SYNTAX", 'Expected ")"'
    if "syntax error" in lower or "unexpected input" in lower:
        return "FAIL_SYNTAX", "Syntax error"
    if "cannot be instantiated" in lower:
        return "FAIL_SUBCKT", "Subcircuit cannot be instantiated"
    if "unknown subcircuit called" in lower:
        return "FAIL_MISSING_SUBCKT", "Unknown subcircuit called"
    if "no such parameter" in lower:
        return "FAIL_PARAM", "No such parameter defined"
    if "file not found" in lower:
        return "FAIL_INCLUDE", "Included file not found"
    if "too few nodes" in lower or "too many nodes" in lower:
        return "FAIL_PINCOUNT", "Subckt pin count mismatch"
    if "fatal error" in lower:
        return "FAIL_FATAL", "Fatal error"

    # Detection POSITIVE : y a-t-il une vraie ligne d'erreur ?
    # Si non -> le log ne contient que l'entete benin -> SUCCES.
    err_line = _first_real_error_line(text)
    if err_line is None:
        return "OK", ""

    if exit_code != 0:
        return "FAIL_OTHER", err_line[:240]
    return "WARN_LOG", err_line[:240]


def _migrate_cache_banner_false_positives(cache: dict) -> int:
    """
    Requalifie en OK les entrees deja en cache classees WARN_LOG/FAIL_OTHER dont
    le error_summary n'est PAS une vraie ligne d'erreur (banniere, Circuit:,
    Start Time:, solver=..., etc.). Idempotent. Spare un re-run complet.
    Retourne le nombre d'entrees corrigees.
    """
    fixed = 0
    for entry in cache.get("batch", {}).values():
        if not isinstance(entry, dict):
            continue
        if entry.get("status", "") not in {"WARN_LOG", "FAIL_OTHER"}:
            continue
        summary = (entry.get("error_summary", "") or "").strip()
        # OK si vide, ou si ce n'est pas une vraie ligne d'erreur reconnue
        if summary == "" or _first_real_error_line(summary) is None:
            entry["status"] = "OK"
            entry["error_summary"] = ""
            fixed += 1
    return fixed


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
    fpar = batch_counts.get("FAIL_PARAM", 0)
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
    if fpar:
        recs.append(f"{fpar} FAIL_PARAM — paramètre <code>{{...}}</code> non défini : le sous-circuit attend un paramètre (souvent à déclarer en défaut dans la ligne <code>.SUBCKT</code>).")
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
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: var(--txt); background: var(--bg); padding: 0 2rem 4rem; }
section[id], div[id] { scroll-margin-top: 70px; }
h1, h2, h3 { color: var(--hdr); }

/* Barre de navigation sticky */
nav.toc { position: sticky; top: 0; z-index: 50; background: var(--card); padding: .5rem 1rem; border-bottom: 1px solid var(--border); display: flex; gap: .35rem; flex-wrap: wrap; margin: 0 -2rem 1rem; box-shadow: 0 2px 4px rgba(0,0,0,.06); }
nav.toc a { color: var(--hdr); text-decoration: none; font-size: .85rem; padding: .3rem .65rem; border-radius: 4px; transition: background .12s; white-space: nowrap; }
nav.toc a:hover { background: #eef3f8; }
nav.toc .toc-title { font-weight: 700; color: var(--hdr); margin-right: .5rem; align-self: center; font-size: .85rem; }

/* Bouton flottant "haut de page" */
.back-to-top { position: fixed; bottom: 1.5rem; right: 1.5rem; background: var(--hdr); color: #fff; border: none; border-radius: 50%; width: 44px; height: 44px; font-size: 1.4rem; font-weight: 700; cursor: pointer; box-shadow: 0 2px 10px rgba(0,0,0,.25); display: none; z-index: 60; line-height: 1; padding: 0; }
.back-to-top.visible { display: flex; align-items: center; justify-content: center; }
.back-to-top:hover { background: #2a4a6e; }
header.audit-header { padding-top: 1.5rem; }
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
.status.FAIL_FATAL, .status.FAIL_OTHER, .status.FAIL_MISSING_SUBCKT, .status.FAIL_PARAM { background: #ffebee; color: var(--bad); }
.status.ENDS, .status.SUBCKT, .status.TABLE, .status.PARENS_FILE, .status.PARENS_LINE { background: #fff3e0; color: var(--warn); }

.toolbar { display: flex; gap: .5rem; align-items: center; margin: .4rem 0 .6rem; flex-wrap: wrap; }
.toolbar input[type=search] { padding: .35rem .55rem; border: 1px solid var(--border); border-radius: 4px; min-width: 240px; font-size: .9rem; }
.toolbar .count { color: var(--muted); font-size: .85rem; margin-left: .5rem; }

.notice { background: #fff3cd; border: 1px solid #ffe69c; padding: .5rem .9rem; border-radius: 4px; margin: .5rem 0; font-size: .87rem; }
.no-data { color: var(--muted); font-style: italic; padding: .8rem 0; }
.truncate { max-width: 600px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.excerpt { font-family: Consolas, Menlo, monospace; font-size: .8rem; color: #555; max-width: 520px; word-break: break-all; white-space: pre-wrap; }

/* Detail par fichier */
.file-card { background: var(--card); border: 1px solid var(--border); border-radius: 6px; margin: .5rem 0; overflow: hidden; box-shadow: 0 1px 2px rgba(0,0,0,.04); }
.file-card-header { background: #eef3f8; padding: .45rem .8rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; cursor: pointer; user-select: none; }
.file-card-header:hover { background: #dde6f0; }
.file-card-header::before { content: "▼"; color: var(--hdr); font-size: .7rem; transition: transform .15s; }
.file-card.collapsed .file-card-header::before { transform: rotate(-90deg); }
.file-card.collapsed .file-card-body { display: none; }
.file-path { font-size: .95rem; font-weight: 600; color: var(--hdr); font-family: Consolas, Menlo, monospace; }
.file-card-meta { color: var(--muted); font-size: .82rem; margin-left: auto; }
.file-card-body { padding: .5rem .8rem .8rem; }
.file-card-body h4 { margin: .6rem 0 .2rem; color: var(--hdr); font-size: .88rem; }
.file-card-body h4:first-child { margin-top: .2rem; }
table.detail { font-size: .83rem; box-shadow: none; margin: .2rem 0; }
table.detail th { background: #f5f7fa; cursor: default; position: static; }
table.detail th:hover { background: #f5f7fa; }
table.detail td { padding: .3rem .5rem; }
.detail-actions { display: flex; gap: .5rem; align-items: center; margin-bottom: .5rem; flex-wrap: wrap; }
.detail-actions button { padding: .25rem .6rem; border: 1px solid var(--border); background: #fff; cursor: pointer; border-radius: 4px; font-size: .82rem; }
.detail-actions button:hover { background: #eef3f8; }
.detail-actions button.active { background: var(--hdr); color: #fff; border-color: var(--hdr); }

/* Checkbox "corrige" sur chaque carte fichier */
.card-fix-label { display: inline-flex; align-items: center; gap: .25rem; font-size: .78rem; color: var(--muted); cursor: pointer; padding: 0 .35rem 0 0; user-select: none; }
.card-fix-label:hover { color: var(--hdr); }
.card-fix { cursor: pointer; margin: 0; transform: scale(1.1); }
.file-card.fixed { opacity: .55; background: #f4f6f8; }
.file-card.fixed .file-card-header { background: #e1e7ee; }
.file-card.fixed .file-path { text-decoration: line-through; }
.file-card.fixed .file-card-meta::after { content: " · corrigé"; color: var(--ok); font-weight: 600; }
#fixed-counter { margin-left: auto; color: var(--ok); font-size: .85rem; font-weight: 600; }

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

// Toggle expansion d'une carte fichier
document.querySelectorAll('.file-card-header').forEach(hdr => {
  hdr.addEventListener('click', () => {
    hdr.parentElement.classList.toggle('collapsed');
  });
});

// Etat "fichiers corriges" persiste dans localStorage, scope par chemin du rapport
const FIXED_STORAGE_KEY = 'ltspice_audit_fixed:' + (window.location.pathname || 'default');
let hideFixed = false;

function loadFixedState() {
  try { return JSON.parse(localStorage.getItem(FIXED_STORAGE_KEY) || '{}'); }
  catch (e) { return {}; }
}
function saveFixedState(state) {
  try { localStorage.setItem(FIXED_STORAGE_KEY, JSON.stringify(state)); }
  catch (e) { /* quota / private mode : on ignore */ }
}
function updateFixedCounter() {
  const total = document.querySelectorAll('.card-fix').length;
  const done = document.querySelectorAll('.file-card.fixed').length;
  const counter = document.getElementById('fixed-counter');
  if (counter && total > 0) {
    counter.textContent = done + ' / ' + total + ' marques corriges';
  }
}

// Unifie : visible <=> matche la recherche ET (pas hideFixed OU pas corrige)
function updateDetailVisibility() {
  const filterInput = document.getElementById('filter-detail');
  const q = (filterInput ? filterInput.value : '').toLowerCase().trim();
  let visible = 0;
  document.querySelectorAll('.file-card').forEach(card => {
    const path = (card.dataset.path || '').toLowerCase();
    const cats = (card.dataset.cats || '').toLowerCase();
    const matchSearch = !q || path.includes(q) || cats.includes(q);
    const isFixed = card.classList.contains('fixed');
    const show = matchSearch && !(hideFixed && isFixed);
    card.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  const cnt = document.getElementById('filter-detail-count');
  if (cnt) cnt.textContent = visible + ' visible(s)';
}

const detailFilter = document.getElementById('filter-detail');
if (detailFilter) {
  detailFilter.addEventListener('input', updateDetailVisibility);
}

// Restaure l'etat coche depuis localStorage + cable les checkboxes
const fixedState = loadFixedState();
document.querySelectorAll('.card-fix').forEach(cb => {
  const key = cb.dataset.key;
  if (fixedState[key]) {
    cb.checked = true;
    cb.closest('.file-card').classList.add('fixed');
  }
  cb.addEventListener('change', () => {
    const card = cb.closest('.file-card');
    card.classList.toggle('fixed', cb.checked);
    const state = loadFixedState();
    if (cb.checked) state[key] = true;
    else delete state[key];
    saveFixedState(state);
    updateFixedCounter();
    if (hideFixed) updateDetailVisibility();
  });
});
updateFixedCounter();
updateDetailVisibility();

// Bouton "Cacher les corriges" / "Afficher les corriges"
const btnHideFixed = document.getElementById('btn-hide-fixed');
if (btnHideFixed) {
  btnHideFixed.addEventListener('click', () => {
    hideFixed = !hideFixed;
    btnHideFixed.classList.toggle('active', hideFixed);
    btnHideFixed.textContent = hideFixed ? 'Afficher les corriges' : 'Cacher les corriges';
    updateDetailVisibility();
  });
}

// Bouton "Tout decocher"
const btnUnfixAll = document.getElementById('btn-unfix-all');
if (btnUnfixAll) {
  btnUnfixAll.addEventListener('click', () => {
    if (!confirm('Decocher TOUTES les cases "corrige" pour ce rapport ?')) return;
    saveFixedState({});
    document.querySelectorAll('.card-fix').forEach(cb => {
      cb.checked = false;
      cb.closest('.file-card').classList.remove('fixed');
    });
    updateFixedCounter();
    updateDetailVisibility();
  });
}

// Boutons "tout ouvrir / tout fermer"
const btnExpandAll = document.getElementById('btn-expand-all');
const btnCollapseAll = document.getElementById('btn-collapse-all');
if (btnExpandAll) btnExpandAll.addEventListener('click', () =>
  document.querySelectorAll('.file-card').forEach(c => c.classList.remove('collapsed')));
if (btnCollapseAll) btnCollapseAll.addEventListener('click', () =>
  document.querySelectorAll('.file-card').forEach(c => c.classList.add('collapsed')));

// Bouton flottant "haut de page"
const backBtn = document.getElementById('back-to-top');
if (backBtn) {
  const toggleBack = () => {
    if (window.scrollY > 400) backBtn.classList.add('visible');
    else backBtn.classList.remove('visible');
  };
  window.addEventListener('scroll', toggleBack, { passive: true });
  backBtn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
  toggleBack();
}
"""


def _render_overview_cards(n_files: int, n_subs: int, n_models: int,
                           n_static: int, n_batch: int,
                           n_batch_ok: int, n_batch_fail: int) -> str:
    pct_ok = (100 * n_batch_ok / n_batch) if n_batch else 0
    return (
        '<section id="overview"><h2 style="border:none;padding:0;margin:.5rem 0">Vue d\'ensemble</h2>'
        '<div class="cards">'
        f'<div class="card"><div class="num">{n_files}</div><div class="label">Fichiers scannés</div></div>'
        f'<div class="card"><div class="num">{n_subs}</div><div class="label">Sous-circuits</div></div>'
        f'<div class="card"><div class="num">{n_models}</div><div class="label">Modèles (.MODEL)</div></div>'
        f'<div class="card"><div class="num">{n_static}</div><div class="label">Issues statiques</div></div>'
        f'<div class="card"><div class="num">{n_batch}</div><div class="label">Tests LTspice</div></div>'
        f'<div class="card"><div class="num" style="color:#2e7d32">{n_batch_ok}</div><div class="label">OK ({pct_ok:.1f}%)</div></div>'
        f'<div class="card"><div class="num" style="color:#c62828">{n_batch_fail}</div><div class="label">Échecs LTspice</div></div>'
        '</div></section>'
    )


def _render_toc() -> str:
    """Barre de navigation sticky en haut du rapport."""
    items = [
        ('overview', 'Vue d\'ensemble'),
        ('recos', 'Recommandations'),
        ('status', 'Statuts'),
        ('top-cats', 'Top erreurs'),
        ('inventory', 'Inventaire'),
        ('errored', 'Fichiers en erreur'),
        ('detail', 'Détail par fichier'),
        ('static-issues', 'Issues statiques'),
        ('batch', 'Échecs LTspice'),
    ]
    links = "".join(f'<a href="#{anchor}">{label}</a>' for anchor, label in items)
    return f'<nav class="toc"><span class="toc-title">Aller à :</span>{links}</nav>'


def _render_recommendations(recs: List[str]) -> str:
    if not recs:
        return ""
    lis = "".join(f"<li>{r}</li>" for r in recs)  # recs already pre-formatted with safe HTML <code>
    return f'<section id="recos"><div class="recos"><h3>Recommandations</h3><ul>{lis}</ul></div></section>'


def _render_status_section(prescan_counts: Dict[str, int], batch_counts: Dict[str, int]) -> str:
    return (
        '<section id="status"><h2>Répartition par statut</h2><div class="cols">'
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
        return ('<section id="top-cats"><h2>Top catégories d\'erreurs</h2>'
                '<p class="no-data">Aucune erreur batch enregistrée (mode --no-batch ?).</p>'
                '</section>')
    return (
        '<section id="top-cats"><h2>Top catégories d\'erreurs</h2>'
        + _bar_block(fail, total_override=sum(fail.values()), max_items=10)
        + '</section>'
    )


def _render_inventory(counts_ext: Dict[str, int],
                      counts_model_type: Dict[str, int],
                      counts_pin_bin: Dict[str, int]) -> str:
    return (
        '<section id="inventory"><h2>Inventaire (utile pour la réorganisation)</h2><div class="cols">'
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
        return ('<section id="errored"><h2>Fichiers avec erreurs</h2>'
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
        '<section id="errored"><h2>Fichiers avec erreurs ' + f'({len(err_rows)})</h2>'
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


def _render_per_file_detail(err_rows: List[dict],
                            issues_by_path: Dict[str, List[dict]],
                            batch_by_path: Dict[str, List[dict]],
                            max_cards: int = 2000) -> str:
    """
    Une carte HTML par fichier en erreur, listant ses issues statiques (avec
    numero de ligne + extrait du code) et ses echecs LTspice (avec message
    exact). But : permettre la correction directe sans cross-reference.
    """
    if not err_rows:
        return ""
    truncated = len(err_rows) > max_cards
    rows = err_rows[:max_cards]

    cards: List[str] = []
    for r in rows:
        fp = r["file_path"]
        rel = r["rel_path"]
        status = r["status"]
        ext = r["extension"]
        cats = r.get("categories", "")
        issues = issues_by_path.get(fp, [])
        fails = [b for b in batch_by_path.get(fp, [])
                 if b.get("status", "").startswith("FAIL")
                 or b.get("status") in {"TIMEOUT", "EXEC_ERROR", "WARN_LOG"}]

        if not issues and not fails:
            # Fichier marque "en erreur" (statut prescan), mais aucun detail
            # ligne par ligne (ex : status = SUSPECT a cause du score uniquement)
            continue

        # Tri des issues par numero de ligne croissant
        def _line_key(it: dict) -> int:
            try:
                return int(it.get("line_no", 0) or 0)
            except (TypeError, ValueError):
                return 0
        issues_sorted = sorted(issues, key=_line_key)

        if issues_sorted:
            iss_body = []
            for it in issues_sorted:
                iss_body.append(
                    '<tr>'
                    f'<td>{_h(it.get("line_no",""))}</td>'
                    f'<td><span class="status {_h(it.get("severity",""))}">{_h(it.get("severity",""))}</span></td>'
                    f'<td><span class="status {_h(it.get("category",""))}">{_h(it.get("category",""))}</span></td>'
                    f'<td>{_h(it.get("message",""))}</td>'
                    f'<td class="excerpt">{_h(it.get("excerpt",""))}</td>'
                    '</tr>'
                )
            iss_html = (
                '<table class="detail"><thead><tr>'
                '<th>Ligne</th><th>Sev.</th><th>Categorie</th><th>Message</th><th>Extrait</th>'
                '</tr></thead><tbody>' + "".join(iss_body) + '</tbody></table>'
            )
        else:
            iss_html = '<p class="no-data" style="margin:.2rem 0">Aucune issue statique sur ce fichier.</p>'

        if fails:
            fail_body = []
            for b in fails:
                fail_body.append(
                    '<tr>'
                    f'<td>{_h(b.get("target_kind",""))}</td>'
                    f'<td><code>{_h(b.get("target_name",""))}</code></td>'
                    f'<td><span class="status {_h(b.get("status",""))}">{_h(b.get("status",""))}</span></td>'
                    f'<td>{_h(b.get("exit_code",""))}</td>'
                    f'<td class="excerpt">{_h(b.get("error_summary",""))}</td>'
                    '</tr>'
                )
            fail_html = (
                '<table class="detail"><thead><tr>'
                '<th>Type</th><th>Cible</th><th>Statut</th><th>Exit</th><th>Message LTspice</th>'
                '</tr></thead><tbody>' + "".join(fail_body) + '</tbody></table>'
            )
        else:
            fail_html = '<p class="no-data" style="margin:.2rem 0">Aucun echec LTspice (que des issues statiques).</p>'

        # Checkbox "corrige" : data-key = rel_path (stable entre regen), stop
        # propagation pour que le clic n'ouvre/ferme pas la carte
        checkbox_html = (
            '<label class="card-fix-label" title="Cocher quand ce fichier a ete corrige" '
            'onclick="event.stopPropagation()">'
            f'<input type="checkbox" class="card-fix" data-key="{_h(rel)}">'
            'corrige'
            '</label>'
        )
        cards.append(
            '<div class="file-card collapsed" '
            f'data-path="{_h(rel.lower())}" data-cats="{_h(cats.lower())}">'
            '<div class="file-card-header">'
            + checkbox_html +
            f'<span class="file-path">{_h(rel)}</span> '
            f'<span class="status {_h(status)}">{_h(status) or "—"}</span>'
            f'<span class="file-card-meta">{_h(ext)} · {len(issues_sorted)} issue(s) · {len(fails)} echec(s) LTspice</span>'
            '</div>'
            '<div class="file-card-body">'
            '<h4>Issues statiques (parser SPICE)</h4>' + iss_html +
            '<h4>Echecs LTspice (batch)</h4>' + fail_html +
            '</div></div>'
        )

    if not cards:
        return ('<section id="detail"><h2>Detail par fichier</h2>'
                '<p class="no-data">Aucun fichier ne porte de detail ligne par ligne.</p></section>')

    notice = (f'<div class="notice">Cartes tronquees a {max_cards} sur {len(err_rows)} fichiers en erreur. '
              'Les details complets restent dans les CSV.</div>') if truncated else ""

    return (
        '<section id="detail">'
        f'<h2>Detail par fichier — a corriger ({len(cards)})</h2>'
        '<p class="meta" style="margin-top:-.5rem">'
        'Clique sur un en-tete pour deplier la carte. Chaque carte liste les erreurs '
        'avec numero de ligne et extrait du code, pour correction directe.'
        '</p>'
        '<div class="detail-actions">'
        '<input type="search" id="filter-detail" placeholder="filtrer par chemin ou categorie..." style="padding:.35rem .55rem;border:1px solid #dcdcdc;border-radius:4px;min-width:280px;font-size:.9rem;">'
        '<span class="count" id="filter-detail-count" style="color:#666;font-size:.85rem"></span>'
        '<button id="btn-expand-all" type="button">Tout ouvrir</button>'
        '<button id="btn-collapse-all" type="button">Tout fermer</button>'
        '<button id="btn-hide-fixed" type="button" title="Masque les fichiers coches">Cacher les corriges</button>'
        '<button id="btn-unfix-all" type="button" title="Decoche toutes les cases (avec confirmation)">Tout decocher</button>'
        '<span id="fixed-counter"></span>'
        '</div>'
        + notice +
        '<div id="file-cards">' + "".join(cards) + '</div>'
        '</section>'
    )


def _render_static_issues_table(issues: List[dict]) -> str:
    if not issues:
        return ('<section id="static-issues"><h2>Issues statiques (prescan)</h2>'
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
        '<section id="static-issues"><h2>Issues statiques (prescan) ' + f'({len(issues)})</h2>'
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
        return ('<section id="batch"><h2>Échecs LTspice</h2>'
                '<p class="no-data">Aucun test batch (mode --no-batch ?).</p></section>')
    if not fails:
        return ('<section id="batch"><h2>Échecs LTspice</h2>'
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
        '<section id="batch"><h2>Échecs LTspice ' + f'({len(fails)})</h2>'
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
    parts.append(_render_toc())
    parts.append(
        '<header class="audit-header"><h1>Audit LTspice — rapport</h1>'
        f'<p class="meta">Généré le {now} — dossier de sortie : <code>{_h(str(out_dir))}</code></p></header>'
    )
    parts.append(_render_overview_cards(n_files, n_subs, n_models, n_static, n_batch, n_batch_ok, n_batch_fail))
    parts.append(_render_recommendations(recs))
    parts.append(_render_status_section(prescan_counts, batch_counts))
    parts.append(_render_top_categories(batch_counts))
    parts.append(_render_inventory(counts_ext, counts_model_type, counts_pin_bin))
    parts.append(_render_errored_files_table(err_rows))
    parts.append(_render_per_file_detail(err_rows, issues_by_path, batch_by_path))
    parts.append(_render_static_issues_table(static_issues))
    parts.append(_render_batch_failures_table(batch_results))
    parts.append('<footer>Rapport autonome — généré par ltspice_lib_auditor.py</footer>')
    parts.append('<button class="back-to-top" id="back-to-top" type="button" title="Retour en haut">↑</button>')
    parts.append(f'<script>{REPORT_JS}</script></body></html>')

    out_path = out_dir / REPORT_FILENAME
    out_path.write_text("".join(parts), encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Fix bundle (Vague 4) : paquet portable pour fix assiste par Claude / humain
# ---------------------------------------------------------------------------

def _is_likely_encrypted(content: bytes) -> bool:
    """
    Heuristique : detecte si un fichier LTspice est probablement chiffre.
    Critere 1 : marqueur explicite "ENCRYPTED" / "*KSh" dans les 5 1res lignes.
    Critere 2 : ratio de bytes imprimables < 65 % dans les 2 premiers Ko.
    Conservateur : prefere un faux positif a partager du contenu chiffre inutile.
    """
    if not content:
        return False
    head = content[:2048]
    try:
        head_text = head.decode("latin-1", errors="replace")
    except Exception:
        return True
    for ln in head_text.splitlines()[:5]:
        ls = ln.strip()
        if "ENCRYPTED" in ls.upper():
            return True
        if ls.upper().startswith("*KSH"):
            return True
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    return (printable / len(head)) < 0.65


def _classify_confidence(prescan_status: str,
                         static_categories: set,
                         batch_statuses: set,
                         is_encrypted: bool) -> str:
    """
    Decide d'un niveau de confiance pour la correction automatique :
    - high       : mecanique, deterministe (ex: .ENDS manquant, INCLUDE resolvable)
    - medium     : probablement corrigeable, a verifier
    - low        : necessite contexte / datasheet (semantique modele, pin count)
    - manual_only: trop ambigu (TIMEOUT, FATAL, chiffre)
    """
    if is_encrypted:
        return "manual_only"
    if batch_statuses & {"TIMEOUT", "FAIL_FATAL", "EXEC_ERROR"}:
        return "manual_only"

    high_static = {"ENDS", "SUBCKT"}
    medium_static = {"TABLE", "PARENS_FILE", "PARENS_LINE"}

    if static_categories and static_categories.issubset(high_static) and not batch_statuses:
        return "high"
    if batch_statuses and batch_statuses.issubset({"FAIL_INCLUDE"}):
        return "high"
    if prescan_status == "READ_ERROR":
        return "medium"
    if static_categories and static_categories.issubset(high_static | medium_static):
        return "medium"
    if batch_statuses & {"FAIL_SYNTAX", "FAIL_MISSING_SUBCKT"}:
        return "medium"
    if batch_statuses & {"FAIL_SUBCKT", "FAIL_PINCOUNT", "FAIL_PARAM", "FAIL_OTHER", "WARN_LOG"}:
        return "low"
    return "low"


def _build_bundle_manifest(data: dict) -> str:
    n = data.get("total_files_in_bundle", 0)
    counts_conf: Dict[str, int] = {}
    counts_status: Dict[str, int] = {}
    for e in data.get("files", []):
        c = e.get("confidence_auto_fix", "")
        counts_conf[c] = counts_conf.get(c, 0) + 1
        s = e.get("prescan_status", "")
        counts_status[s] = counts_status.get(s, 0) + 1
    conf_lines = "\n".join(f"- `{k}` : {v}" for k, v in sorted(counts_conf.items())) or "- (vide)"
    status_lines = "\n".join(f"- `{k}` : {v}" for k, v in sorted(counts_status.items())) or "- (vide)"
    truncated = data.get("truncated_at_max_files", False)
    trunc_note = ""
    if truncated:
        trunc_note = (f"\n> Bundle tronque (cap={data.get('max_files_cap','?')}). "
                      f"Total eligible : {data.get('total_errored_files','?')}. "
                      f"Augmente `--bundle-max-files` pour ratisser plus.\n")
    skipped = data.get("skipped_by_min_confidence", 0)
    skip_note = ""
    if skipped:
        skip_note = (f"\n> {skipped} fichier(s) ignore(s) par "
                     f"`--bundle-min-confidence {data.get('min_confidence_filter','?')}`.\n")

    return textwrap.dedent(f"""\
    # Fix Bundle - LTspice Library Auditor

    Genere le **{data.get('generated_at','?')}**
    Audit racine : `{data.get('audit_root','?')}`

    **{n}** fichier(s) inclus dans ce bundle.{trunc_note}{skip_note}

    ## Repartition par niveau de confiance auto-fix

    {conf_lines}

    ## Repartition par statut prescan

    {status_lines}

    ## Comment utiliser ce bundle avec Claude

    1. Compresse le dossier `fix_bundle/` en zip et partage-le dans une
       conversation Claude (ou colle directement le contenu de `errors.json`
       avec les fichiers de `sources/`).
    2. Demande : *"Voici un bundle d'erreurs LTspice. Corrige d'abord la
       confiance `high`, puis `medium`. Pour chaque fichier, donne-moi la
       version corrigee complete dans un bloc de code."*
    3. Recupere les fichiers corriges, ecrase tes originaux.
    4. Relance : `python ltspice_lib_auditor.py --root ... --out ...`
       Le cache ne retest que les fichiers modifies.

    ## Structure

    | Element                | Contenu                                                              |
    |------------------------|----------------------------------------------------------------------|
    | `errors.json`          | Donnees structurees (a partager en premier)                          |
    | `MANIFEST.md`          | Ce fichier                                                           |
    | `bundle_summary.txt`   | 1 ligne par fichier, lisible humain                                  |
    | `sources/`             | Copies 1:1 des fichiers en erreur (arborescence preservee)           |
    | `logs/`                | Logs LTspice complets (cible des `raw_log_path` des batch_results)   |

    ## Niveaux de confiance

    | Niveau         | Description                                                                            |
    |----------------|----------------------------------------------------------------------------------------|
    | `high`         | Correction mecanique (`.ENDS` manquant, `FAIL_INCLUDE` resolvable dans la lib)         |
    | `medium`       | Probablement corrigeable mais a verifier manuellement                                  |
    | `low`          | Necessite contexte / datasheet (FAIL_SUBCKT semantique, FAIL_PINCOUNT, FAIL_OTHER...)  |
    | `manual_only`  | Trop ambigu (TIMEOUT, FATAL, fichier chiffre)                                          |

    ## Recommandation de batch

    - 50-100 fichiers `high` -> 1 conversation
    - 30-50 `medium` -> 1 conversation
    - `low` / `manual_only` -> cas par cas

    ## Avertissement

    Tu es responsable du contenu que tu partages. Verifie que ta lib n'a pas
    de licence interdisant la redistribution avant de la partager exterieurement.
    Les fichiers chiffres ne sont pas copies dans `sources/`.
    """)


def generate_fix_bundle(out_dir: Path,
                        max_files: int = BUNDLE_DEFAULT_MAX_FILES,
                        min_confidence: str = "low",
                        verbose: bool = False) -> Optional[Path]:
    """
    Genere un dossier portable {out_dir}/fix_bundle/ avec :
    - sources/   : copies des fichiers en erreur (arborescence preservee)
    - logs/      : copies integrales des logs LTspice associes
    - errors.json: structure de donnees pour reprise par un assistant
    - MANIFEST.md: explications pour humain
    - bundle_summary.txt: liste 1-ligne-par-fichier
    """
    reports_dir = out_dir / "reports"
    if not reports_dir.exists():
        print(f"[WARN] {reports_dir} introuvable, bundle non genere.")
        return None

    summaries = _read_csv_dicts(reports_dir / "files_summary.csv")
    static_issues = _read_csv_dicts(reports_dir / "static_issues.csv")
    batch_results = _read_csv_dicts(reports_dir / "batch_results.csv")

    issues_by_path: Dict[str, List[dict]] = {}
    for it in static_issues:
        issues_by_path.setdefault(it.get("file_path", ""), []).append(it)
    batch_by_path: Dict[str, List[dict]] = {}
    for b in batch_results:
        batch_by_path.setdefault(b.get("file_path", ""), []).append(b)
    sm_by_path = {s.get("file_path", ""): s for s in summaries}

    errored: set = set()
    for s in summaries:
        if s.get("status") in {"SUSPECT", "BROKEN_LIKELY", "READ_ERROR"}:
            errored.add(s.get("file_path", ""))
    for it in static_issues:
        errored.add(it.get("file_path", ""))
    for b in batch_results:
        st = b.get("status", "")
        if st.startswith("FAIL") or st in {"TIMEOUT", "EXEC_ERROR", "WARN_LOG"}:
            errored.add(b.get("file_path", ""))
    errored.discard("")

    if not errored:
        print("[INFO] Aucun fichier en erreur, bundle non genere.")
        return None

    bundle_dir = out_dir / BUNDLE_DIRNAME
    if bundle_dir.exists():
        try:
            shutil.rmtree(bundle_dir)
        except Exception as exc:
            print(f"[WARN] Nettoyage bundle precedent echoue: {exc}")
    bundle_dir.mkdir(parents=True, exist_ok=True)
    sources_dir = bundle_dir / "sources"
    logs_dir = bundle_dir / "logs"
    sources_dir.mkdir(exist_ok=True)
    logs_dir.mkdir(exist_ok=True)

    conf_order = {"high": 0, "medium": 1, "low": 2, "manual_only": 3}
    min_idx = conf_order.get(min_confidence, 9)

    entries: List[dict] = []
    skipped_confidence = 0

    errored_list = sorted(errored)
    n_errored = len(errored_list)
    print(f"[PHASE] Construction du bundle : analyse de {n_errored} fichier(s) en erreur...")
    t_bundle = time.time()
    bundle_progress_every = 50 if verbose else 250

    for idx_b, fp in enumerate(errored_list, start=1):
        if idx_b % bundle_progress_every == 0 or idx_b == n_errored:
            elapsed = time.time() - t_bundle
            rate = idx_b / elapsed if elapsed > 0 else 0
            eta = (n_errored - idx_b) / rate if rate > 0 else 0
            print(f"[INFO] Bundle: {idx_b}/{n_errored} analyses "
                  f"({len(entries)} retenus) - ETA {fmt_eta(eta)}")
        s = sm_by_path.get(fp, {})
        issues = issues_by_path.get(fp, [])
        fails = [b for b in batch_by_path.get(fp, [])
                 if b.get("status", "").startswith("FAIL")
                 or b.get("status") in {"TIMEOUT", "EXEC_ERROR", "WARN_LOG"}]
        if not issues and not fails:
            continue

        src_path = Path(fp)
        head_bytes = b""
        is_encrypted = False
        too_big = False
        try:
            if src_path.exists():
                too_big = src_path.stat().st_size > BUNDLE_MAX_SOURCE_SIZE
                with src_path.open("rb") as f:
                    head_bytes = f.read(2048)
            is_encrypted = _is_likely_encrypted(head_bytes)
        except Exception:
            pass

        static_cats = {it.get("category", "") for it in issues}
        batch_sts = {b.get("status", "") for b in fails}
        confidence = _classify_confidence(s.get("status", ""), static_cats,
                                          batch_sts, is_encrypted)

        if conf_order.get(confidence, 9) > min_idx:
            skipped_confidence += 1
            continue

        rel = s.get("rel_path", fp)
        rel_norm = rel.replace("\\", "/")

        entry: dict = {
            "rel_path": rel,
            "rel_path_unix": rel_norm,
            "source_path_original": fp,
            "source_in_bundle": "",
            "prescan_status": s.get("status", ""),
            "extension": s.get("extension", ""),
            "encoding": s.get("encoding", ""),
            "confidence_auto_fix": confidence,
            "is_encrypted": is_encrypted,
            "too_big_to_bundle": too_big,
            "static_issues": [
                {
                    "line_no": it.get("line_no", ""),
                    "severity": it.get("severity", ""),
                    "category": it.get("category", ""),
                    "message": it.get("message", ""),
                    "excerpt": it.get("excerpt", ""),
                }
                for it in issues
            ],
            "batch_failures": [],
            "notes": [],
        }

        # Copie source
        if is_encrypted:
            entry["notes"].append("Fichier probablement chiffre - non copie.")
        elif too_big:
            entry["notes"].append(
                f"Fichier > {BUNDLE_MAX_SOURCE_SIZE // 1024} Ko - non copie."
            )
        elif not src_path.exists():
            entry["notes"].append("Fichier source introuvable au moment du bundling.")
        else:
            target_src = sources_dir / rel_norm
            try:
                target_src.parent.mkdir(parents=True, exist_ok=True)
                target_src.write_bytes(src_path.read_bytes())
                entry["source_in_bundle"] = f"sources/{rel_norm}"
            except Exception as exc:
                entry["notes"].append(f"Copie source impossible : {exc}")

        # Logs LTspice
        for b in fails:
            fail_entry = {
                "target_kind": b.get("target_kind", ""),
                "target_name": b.get("target_name", ""),
                "status": b.get("status", ""),
                "exit_code": b.get("exit_code", ""),
                "error_summary": b.get("error_summary", ""),
                "log_excerpt": "",
                "log_in_bundle": "",
            }
            raw_log = b.get("raw_log_path", "")
            if raw_log:
                src_log = Path(raw_log)
                if src_log.exists():
                    try:
                        if src_log.stat().st_size > BUNDLE_MAX_LOG_SIZE:
                            full_text = src_log.read_text(encoding="utf-8", errors="replace")
                            log_text = (
                                "... [debut tronque, log > "
                                f"{BUNDLE_MAX_LOG_SIZE // 1024} Ko] ...\n"
                                + full_text[-BUNDLE_MAX_LOG_SIZE:]
                            )
                        else:
                            log_text = src_log.read_text(encoding="utf-8", errors="replace")
                        lines = log_text.splitlines()
                        if len(lines) > (BUNDLE_LOG_HEAD_LINES + BUNDLE_LOG_TAIL_LINES + 1):
                            excerpt = "\n".join(
                                lines[:BUNDLE_LOG_HEAD_LINES]
                                + ["... [troncature] ..."]
                                + lines[-BUNDLE_LOG_TAIL_LINES:]
                            )
                        else:
                            excerpt = log_text
                        fail_entry["log_excerpt"] = excerpt
                        log_filename = src_log.name
                        target_log = logs_dir / log_filename
                        target_log.write_text(log_text, encoding="utf-8")
                        fail_entry["log_in_bundle"] = f"logs/{log_filename}"
                    except Exception as exc:
                        fail_entry["log_excerpt"] = (
                            f"(impossible de lire {raw_log} : {exc})"
                        )
            entry["batch_failures"].append(fail_entry)

        entries.append(entry)

    # Tri : confiance haute d'abord, puis chemin
    entries.sort(key=lambda e: (conf_order.get(e["confidence_auto_fix"], 9),
                                 e["rel_path"]))

    total_eligible = len(entries) + skipped_confidence
    truncated = len(entries) > max_files
    if truncated:
        entries = entries[:max_files]

    bundle_data = {
        "audit_root": str(out_dir),
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_files_in_bundle": len(entries),
        "total_errored_files": total_eligible,
        "skipped_by_min_confidence": skipped_confidence,
        "truncated_at_max_files": truncated,
        "min_confidence_filter": min_confidence,
        "max_files_cap": max_files,
        "files": entries,
    }

    (bundle_dir / "errors.json").write_text(
        json.dumps(bundle_data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (bundle_dir / "MANIFEST.md").write_text(
        _build_bundle_manifest(bundle_data), encoding="utf-8"
    )

    summary_lines = [
        f"# Fix Bundle - {len(entries)} fichier(s)",
        f"# Confidence min : {min_confidence} | Cap : {max_files} | "
        f"Tronque : {truncated} | Total eligible : {total_eligible}",
        "",
    ]
    for e in entries:
        flag = ""
        if e["is_encrypted"]:
            flag = " [ENC]"
        elif e["too_big_to_bundle"]:
            flag = " [BIG]"
        elif not e["source_in_bundle"]:
            flag = " [NO-SRC]"
        summary_lines.append(
            f"[{e['confidence_auto_fix']:<11}] "
            f"{e['rel_path']:<48} "
            f"{e['prescan_status']:<13} "
            f"{len(e['static_issues']):>3} stat, "
            f"{len(e['batch_failures']):>3} batch"
            f"{flag}"
        )
    (bundle_dir / "bundle_summary.txt").write_text(
        "\n".join(summary_lines) + "\n", encoding="utf-8"
    )

    print(f"[OK] Fix bundle genere : {bundle_dir}")
    print(f"      {len(entries)} fichier(s) embarques, "
          f"confiance >= {min_confidence}")
    if truncated:
        print(f"      Tronque : {total_eligible} eligibles, cap a {max_files}.")
    if skipped_confidence:
        print(f"      Ignores par filtre confiance : {skipped_confidence}")
    return bundle_dir


# ---------------------------------------------------------------------------
# GUI Tkinter (lazy import : ne charge tkinter qu'en mode --gui)
# ---------------------------------------------------------------------------

GUI_SETTINGS_PATH = Path.home() / ".ltspice_audit_gui_settings.json"
PROGRESS_RE = re.compile(r'(?:Batch[^:]*|Prescan)[^:]*:\s*(\d+)/(\d+)')


def launch_gui() -> int:
    try:
        import tkinter as tk  # noqa: F401
        from tkinter import ttk  # noqa: F401
    except ImportError:
        print("[ERREUR] Tkinter introuvable. Reinstalle Python avec l'option Tcl/Tk.")
        return 2
    app = AuditGUI()
    app.run()
    return 0


class AuditGUI:
    """Interface Tkinter qui pilote l'audit comme sous-processus."""

    def __init__(self):
        import tkinter as tk
        from tkinter import ttk
        import queue as _queue

        self._tk = tk
        self._ttk = ttk
        self._q: "_queue.Queue[Optional[str]]" = _queue.Queue()
        self.process: Optional[subprocess.Popen] = None
        self.reader_thread = None
        self.start_time: Optional[float] = None
        self.last_total = 0
        self.last_completed = 0

        self.root = tk.Tk()
        self.root.title("LTspice Library Auditor")
        self.root.geometry("980x720")
        self.root.minsize(820, 560)

        # Variables liees aux widgets
        self.root_var = tk.StringVar()
        self.out_var = tk.StringVar()
        self.ltspice_var = tk.StringVar()
        self.ext_var = tk.StringVar(value=".lib,.sub,.cir,.mod,.txt,.si")
        self.jobs_var = tk.IntVar(value=max(1, (os.cpu_count() or 2) - 1))
        self.timeout_var = tk.IntVar(value=15)
        self.group_size_var = tk.IntVar(value=20)
        self.max_files_var = tk.IntVar(value=0)
        self.max_subckts_var = tk.IntVar(value=0)
        self.only_suspect_var = tk.BooleanVar(value=False)
        self.skip_broken_var = tk.BooleanVar(value=False)
        self.no_batch_var = tk.BooleanVar(value=False)
        self.no_cache_var = tk.BooleanVar(value=False)
        self.keep_raw_var = tk.BooleanVar(value=False)
        self.no_report_var = tk.BooleanVar(value=False)
        self.fix_bundle_var = tk.BooleanVar(value=False)
        self.bundle_max_files_var = tk.IntVar(value=BUNDLE_DEFAULT_MAX_FILES)
        self.bundle_min_conf_var = tk.StringVar(value="low")
        self.verbose_var = tk.BooleanVar(value=False)

        self._build_ui()
        self._load_settings()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---- UI ----
    def _build_ui(self):
        tk = self._tk
        ttk = self._ttk

        # En-tete
        header = ttk.Frame(self.root, padding=(12, 10, 12, 4))
        header.pack(fill='x')
        ttk.Label(header, text="LTspice Library Auditor",
                  font=('Segoe UI', 14, 'bold')).pack(anchor='w')
        ttk.Label(header,
                  text="Audit parallele d'une librairie LTspice tierce. Detecte les sous-circuits cassesm,"
                       " genere des rapports CSV et un rapport HTML interactif.",
                  foreground='#555').pack(anchor='w')

        # Form (chemins)
        paths = ttk.LabelFrame(self.root, text="Chemins", padding=10)
        paths.pack(fill='x', padx=12, pady=(8, 4))
        paths.columnconfigure(1, weight=1)

        self._make_path_row(paths, 0, "Racine librairie:", self.root_var,
                            self._browse_root, is_dir=True)
        self._make_path_row(paths, 1, "Dossier sortie:", self.out_var,
                            self._browse_out, is_dir=True)
        self._make_path_row(paths, 2, "LTspice.exe (optionnel):", self.ltspice_var,
                            self._browse_ltspice, is_dir=False)

        ttk.Label(paths, text="Extensions scannees:").grid(row=3, column=0, sticky='w', pady=(6, 0))
        ttk.Entry(paths, textvariable=self.ext_var).grid(row=3, column=1, sticky='ew', padx=(8, 0), pady=(6, 0))

        # Options
        opts = ttk.LabelFrame(self.root, text="Options", padding=10)
        opts.pack(fill='x', padx=12, pady=4)
        for c in range(6):
            opts.columnconfigure(c, weight=1)

        ttk.Checkbutton(opts, text="Mode rapide (--only-suspect)",
                        variable=self.only_suspect_var).grid(row=0, column=0, sticky='w', padx=4)
        ttk.Checkbutton(opts, text="Sauter BROKEN_LIKELY au batch",
                        variable=self.skip_broken_var).grid(row=0, column=1, sticky='w', padx=4)
        ttk.Checkbutton(opts, text="Pas de batch (decks seulement)",
                        variable=self.no_batch_var).grid(row=0, column=2, sticky='w', padx=4)
        ttk.Checkbutton(opts, text="Ignorer le cache",
                        variable=self.no_cache_var).grid(row=1, column=0, sticky='w', padx=4)
        ttk.Checkbutton(opts, text="Garder les .raw / .net",
                        variable=self.keep_raw_var).grid(row=1, column=1, sticky='w', padx=4)
        ttk.Checkbutton(opts, text="Pas de rapport HTML",
                        variable=self.no_report_var).grid(row=1, column=2, sticky='w', padx=4)
        ttk.Checkbutton(opts, text="Generer fix bundle",
                        variable=self.fix_bundle_var).grid(row=2, column=0, sticky='w', padx=4)
        ttk.Checkbutton(opts, text="Verbose (logs detailles)",
                        variable=self.verbose_var).grid(row=2, column=1, sticky='w', padx=4)

        # Numeriques
        nums = ttk.LabelFrame(self.root, text="Reglages", padding=10)
        nums.pack(fill='x', padx=12, pady=4)
        ttk.Label(nums, text="Workers (-j):").grid(row=0, column=0, sticky='w')
        ttk.Spinbox(nums, from_=1, to=64, textvariable=self.jobs_var, width=6).grid(row=0, column=1, padx=(4, 16))
        ttk.Label(nums, text="Timeout (s):").grid(row=0, column=2, sticky='w')
        ttk.Spinbox(nums, from_=1, to=600, textvariable=self.timeout_var, width=6).grid(row=0, column=3, padx=(4, 16))
        ttk.Label(nums, text="Group size:").grid(row=0, column=4, sticky='w')
        ttk.Spinbox(nums, from_=1, to=200, textvariable=self.group_size_var, width=6).grid(row=0, column=5, padx=(4, 16))
        ttk.Label(nums, text="Max files:").grid(row=0, column=6, sticky='w')
        ttk.Spinbox(nums, from_=0, to=999999, textvariable=self.max_files_var, width=8).grid(row=0, column=7, padx=(4, 16))
        ttk.Label(nums, text="Max subckts:").grid(row=0, column=8, sticky='w')
        ttk.Spinbox(nums, from_=0, to=999999, textvariable=self.max_subckts_var, width=8).grid(row=0, column=9, padx=(4, 0))

        # Reglages bundle (ligne 2)
        ttk.Label(nums, text="Bundle max files:").grid(row=1, column=0, columnspan=2, sticky='w', pady=(6, 0))
        ttk.Spinbox(nums, from_=1, to=10000, textvariable=self.bundle_max_files_var, width=8).grid(row=1, column=2, padx=(4, 16), pady=(6, 0))
        ttk.Label(nums, text="Bundle min confidence:").grid(row=1, column=3, columnspan=2, sticky='w', pady=(6, 0))
        ttk.Combobox(nums, textvariable=self.bundle_min_conf_var,
                     values=["high", "medium", "low", "manual_only"],
                     state="readonly", width=12).grid(row=1, column=5, columnspan=2, padx=(4, 0), pady=(6, 0), sticky='w')

        # Boutons d'action
        actions = ttk.Frame(self.root, padding=(12, 8, 12, 4))
        actions.pack(fill='x')
        self.start_btn = ttk.Button(actions, text="Demarrer l'audit", command=self._on_start)
        self.start_btn.pack(side='left')
        self.stop_btn = ttk.Button(actions, text="Arreter (sauve cache)", command=self._on_stop, state='disabled')
        self.stop_btn.pack(side='left', padx=6)
        ttk.Button(actions, text="Regenerer rapport", command=self._on_report_only).pack(side='left', padx=6)
        ttk.Button(actions, text="Generer bundle", command=self._on_bundle_only).pack(side='left', padx=6)
        ttk.Button(actions, text="Ouvrir rapport", command=self._open_report).pack(side='left', padx=6)
        ttk.Button(actions, text="Ouvrir dossier", command=self._open_outdir).pack(side='left', padx=6)

        # Progression
        prog = ttk.Frame(self.root, padding=(12, 4))
        prog.pack(fill='x')
        prog.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(prog, length=600, mode='determinate', maximum=100)
        self.progress.grid(row=0, column=0, sticky='ew')
        self.status_label = ttk.Label(prog, text="Pret", foreground='#1a3a5e')
        self.status_label.grid(row=0, column=1, sticky='w', padx=(12, 0))

        # Log
        logf = ttk.LabelFrame(self.root, text="Logs", padding=8)
        logf.pack(fill='both', expand=True, padx=12, pady=(4, 12))
        self.log_text = tk.Text(logf, height=18, wrap='word', font=('Consolas', 9),
                                background='#1e1e1e', foreground='#d4d4d4',
                                insertbackground='#fff')
        log_scroll = ttk.Scrollbar(logf, command=self.log_text.yview)
        self.log_text.config(yscrollcommand=log_scroll.set)
        self.log_text.pack(side='left', fill='both', expand=True)
        log_scroll.pack(side='right', fill='y')
        # Couleurs
        self.log_text.tag_configure('info', foreground='#9cdcfe')
        self.log_text.tag_configure('warn', foreground='#dcdcaa')
        self.log_text.tag_configure('err', foreground='#f48771')
        self.log_text.tag_configure('ok', foreground='#b5cea8')

    def _make_path_row(self, parent, row, label, var, command, is_dir=True):
        ttk = self._ttk
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky='w', pady=2)
        ttk.Entry(parent, textvariable=var).grid(row=row, column=1, sticky='ew', padx=(8, 4), pady=2)
        ttk.Button(parent, text="Parcourir...", command=command).grid(row=row, column=2, pady=2)

    # ---- Helpers UI ----
    def _browse_root(self):
        from tkinter import filedialog
        d = filedialog.askdirectory(title="Choisir la racine de la librairie",
                                     initialdir=self.root_var.get() or str(Path.home()))
        if d:
            self.root_var.set(d)

    def _browse_out(self):
        from tkinter import filedialog
        d = filedialog.askdirectory(title="Choisir le dossier de sortie",
                                     initialdir=self.out_var.get() or str(Path.home()))
        if d:
            self.out_var.set(d)

    def _browse_ltspice(self):
        from tkinter import filedialog
        f = filedialog.askopenfilename(title="Localiser LTspice.exe",
                                        filetypes=[("Executables", "*.exe"), ("Tous", "*.*")],
                                        initialdir=self.ltspice_var.get() or r"C:\Program Files")
        if f:
            self.ltspice_var.set(f)

    def _append_log(self, line: str):
        tag = 'info'
        if '[ERREUR]' in line or 'EXEC_ERROR' in line or 'Traceback' in line:
            tag = 'err'
        elif '[WARN]' in line or 'TIMEOUT' in line or 'FAIL_' in line:
            tag = 'warn'
        elif '[OK]' in line or 'OK ' in line[:6]:
            tag = 'ok'
        self.log_text.insert('end', line + '\n', tag)
        self.log_text.see('end')

    def _process_line(self, line: str):
        self._append_log(line)
        m = PROGRESS_RE.search(line)
        if m:
            completed = int(m.group(1))
            total = int(m.group(2))
            self.last_completed = completed
            self.last_total = total
            elapsed = (time.time() - self.start_time) if self.start_time else 0
            rate = completed / elapsed if elapsed > 0 else 0
            eta = (total - completed) / rate if rate > 0 else 0
            pct = (100 * completed / total) if total else 0
            self.progress['value'] = pct
            self.status_label['text'] = (f'{completed}/{total} ({pct:.1f}%) '
                                         f'- {rate*60:.0f}/min - ETA {fmt_eta(eta)}')

    # ---- Build CLI args from form ----
    def _build_cli_args(self) -> Optional[List[str]]:
        from tkinter import messagebox
        if not self.no_batch_var.get() and not self.root_var.get().strip():
            messagebox.showerror("Erreur", "Le champ 'Racine librairie' est requis.")
            return None
        if not self.out_var.get().strip():
            messagebox.showerror("Erreur", "Le champ 'Dossier sortie' est requis.")
            return None

        a: List[str] = []
        if self.root_var.get().strip():
            a += ["--root", self.root_var.get().strip()]
        a += ["--out", self.out_var.get().strip()]
        if self.ltspice_var.get().strip():
            a += ["--ltspice", self.ltspice_var.get().strip()]
        if self.ext_var.get().strip():
            a += ["--extensions", self.ext_var.get().strip()]
        a += ["-j", str(int(self.jobs_var.get() or 0))]
        a += ["--timeout", str(int(self.timeout_var.get() or 15))]
        a += ["--group-size", str(int(self.group_size_var.get() or 1))]
        if int(self.max_files_var.get() or 0) > 0:
            a += ["--max-files", str(int(self.max_files_var.get()))]
        if int(self.max_subckts_var.get() or 0) > 0:
            a += ["--max-subckts", str(int(self.max_subckts_var.get()))]
        if self.only_suspect_var.get():
            a.append("--only-suspect")
        if self.skip_broken_var.get():
            a.append("--skip-broken-batch")
        if self.no_batch_var.get():
            a.append("--no-batch")
        if self.no_cache_var.get():
            a.append("--no-cache")
        if self.keep_raw_var.get():
            a.append("--keep-raw")
        if self.no_report_var.get():
            a.append("--no-report")
        if self.fix_bundle_var.get():
            a.append("--fix-bundle")
            a += ["--bundle-max-files", str(int(self.bundle_max_files_var.get() or BUNDLE_DEFAULT_MAX_FILES))]
            a += ["--bundle-min-confidence", self.bundle_min_conf_var.get() or "low"]
        if self.verbose_var.get():
            a.append("--verbose")
        return a

    # ---- Sous-processus ----
    def _spawn_streaming(self, cli_args, busy_status="En cours...", op_name="Operation"):
        """Lance le script en sous-processus NON bloquant et streame stdout vers
        la console GUI. Reutilise par audit / rapport / bundle : evite tout freeze
        de l'interface (le thread principal Tkinter n'attend jamais le process).
        Retourne True si lance, False sinon."""
        import threading
        from tkinter import messagebox

        if self.process is not None and self.process.poll() is None:
            messagebox.showwarning("En cours",
                                   "Une operation tourne deja. Attends la fin ou clique Arreter.")
            return False

        # Resoudre python.exe (eviter pythonw.exe sans stdout)
        py_exe = sys.executable
        if py_exe.lower().endswith('pythonw.exe'):
            cand = Path(py_exe).with_name('python.exe')
            if cand.exists():
                py_exe = str(cand)

        script = str(Path(__file__).resolve())
        cmd = [py_exe, "-u", script, *cli_args]
        self._append_log("$ " + " ".join(f'"{c}"' if ' ' in c else c for c in cmd))

        env = dict(os.environ)
        env['PYTHONUNBUFFERED'] = '1'
        env['PYTHONIOENCODING'] = 'utf-8'

        flags = 0
        if sys.platform == 'win32':
            flags = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1,
                creationflags=flags,
                env=env,
            )
        except Exception as exc:
            messagebox.showerror("Erreur", f"Impossible de lancer le sous-processus:\n{exc}")
            self.process = None
            return False

        self.current_op = op_name
        self.status_label['text'] = busy_status
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')

        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()
        self.root.after(80, self._poll_queue)
        return True

    def _on_start(self):
        from tkinter import messagebox

        if self.process is not None and self.process.poll() is None:
            messagebox.showwarning("En cours", "Un audit tourne deja.")
            return

        cli_args = self._build_cli_args()
        if cli_args is None:
            return

        self._save_settings()
        self.log_text.delete('1.0', 'end')
        self.progress['value'] = 0
        self.start_time = time.time()
        self.last_total = 0
        self.last_completed = 0
        self._spawn_streaming(cli_args, busy_status="Demarrage...", op_name="Audit")

    def _reader_loop(self):
        try:
            assert self.process is not None and self.process.stdout is not None
            for line in iter(self.process.stdout.readline, ''):
                self._q.put(line.rstrip('\r\n'))
        except Exception as exc:
            self._q.put(f"[ERREUR] Lecture stdout: {exc}")
        finally:
            self._q.put(None)

    def _poll_queue(self):
        import queue as _queue
        if self.process is None:
            return
        drained = 0
        try:
            while drained < 100:
                line = self._q.get_nowait()
                drained += 1
                if line is None:
                    self._on_finished()
                    return
                self._process_line(line)
        except _queue.Empty:
            pass
        if self.process is not None:
            self.root.after(80, self._poll_queue)

    def _on_finished(self):
        rc = self.process.poll() if self.process else None
        self.process = None
        op = getattr(self, 'current_op', 'Operation')
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        if rc == 0:
            self.status_label['text'] = "Termine"
            self._append_log(f"[GUI] {op} terminee (exit {rc}).")
        else:
            self.status_label['text'] = f"Termine (exit {rc})"
            self._append_log(f"[GUI] {op} terminee avec code {rc}.")

    def _on_stop(self):
        import signal as _signal
        from tkinter import messagebox
        if not self.process or self.process.poll() is not None:
            return
        try:
            if sys.platform == 'win32':
                self.process.send_signal(_signal.CTRL_BREAK_EVENT)
            else:
                self.process.send_signal(_signal.SIGINT)
            self.status_label['text'] = "Arret en cours (sauvegarde du cache)..."
            self._append_log("[GUI] Signal d'arret envoye, attente sauvegarde du cache.")
        except Exception as exc:
            messagebox.showerror("Erreur", f"Impossible d'envoyer le signal: {exc}")

    def _on_report_only(self):
        from tkinter import messagebox
        out = self.out_var.get().strip()
        if not out or not (Path(out) / "reports").exists():
            messagebox.showerror("Erreur", "Pas de CSV trouves dans ce dossier de sortie.")
            return
        # Streaming non bloquant : la GUI reste reactive pendant la generation
        self._spawn_streaming(["--out", out, "--report-only"],
                              busy_status="Generation du rapport HTML...",
                              op_name="Rapport HTML")

    def _on_bundle_only(self):
        from tkinter import messagebox
        out = self.out_var.get().strip()
        if not out or not (Path(out) / "reports").exists():
            messagebox.showerror("Erreur", "Pas de CSV trouves dans ce dossier de sortie.")
            return
        args = ["--out", out, "--fix-bundle-only",
                "--bundle-max-files", str(int(self.bundle_max_files_var.get() or BUNDLE_DEFAULT_MAX_FILES)),
                "--bundle-min-confidence", self.bundle_min_conf_var.get() or "low"]
        if self.verbose_var.get():
            args.append("--verbose")
        # Streaming non bloquant : evite le freeze sur les gros bundles (2000+ fichiers)
        self._spawn_streaming(args,
                              busy_status="Generation du fix bundle...",
                              op_name="Fix bundle")

    def _open_report(self):
        import webbrowser
        from tkinter import messagebox
        out = self.out_var.get().strip()
        if not out:
            messagebox.showerror("Erreur", "Renseigne d'abord le dossier de sortie.")
            return
        p = Path(out) / REPORT_FILENAME
        if not p.exists():
            messagebox.showerror("Erreur", f"Aucun rapport trouve : {p}")
            return
        webbrowser.open(p.as_uri())

    def _open_outdir(self):
        from tkinter import messagebox
        out = self.out_var.get().strip()
        if not out:
            messagebox.showerror("Erreur", "Renseigne d'abord le dossier de sortie.")
            return
        p = Path(out)
        if not p.exists():
            messagebox.showerror("Erreur", f"Dossier inexistant : {p}")
            return
        try:
            if sys.platform == 'win32':
                os.startfile(str(p))  # type: ignore[attr-defined]
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', str(p)])
            else:
                subprocess.Popen(['xdg-open', str(p)])
        except Exception as exc:
            messagebox.showerror("Erreur", f"{exc}")

    # ---- Persistance des reglages ----
    def _save_settings(self):
        data = {
            'root': self.root_var.get(),
            'out': self.out_var.get(),
            'ltspice': self.ltspice_var.get(),
            'extensions': self.ext_var.get(),
            'jobs': int(self.jobs_var.get() or 0),
            'timeout': int(self.timeout_var.get() or 15),
            'group_size': int(self.group_size_var.get() or 20),
            'max_files': int(self.max_files_var.get() or 0),
            'max_subckts': int(self.max_subckts_var.get() or 0),
            'only_suspect': bool(self.only_suspect_var.get()),
            'skip_broken_batch': bool(self.skip_broken_var.get()),
            'no_batch': bool(self.no_batch_var.get()),
            'no_cache': bool(self.no_cache_var.get()),
            'keep_raw': bool(self.keep_raw_var.get()),
            'no_report': bool(self.no_report_var.get()),
            'fix_bundle': bool(self.fix_bundle_var.get()),
            'bundle_max_files': int(self.bundle_max_files_var.get() or BUNDLE_DEFAULT_MAX_FILES),
            'bundle_min_confidence': self.bundle_min_conf_var.get() or 'low',
            'verbose': bool(self.verbose_var.get()),
        }
        try:
            GUI_SETTINGS_PATH.write_text(json.dumps(data, indent=2), encoding='utf-8')
        except Exception:
            pass

    def _load_settings(self):
        if not GUI_SETTINGS_PATH.exists():
            return
        try:
            data = json.loads(GUI_SETTINGS_PATH.read_text(encoding='utf-8'))
        except Exception:
            return
        self.root_var.set(data.get('root', ''))
        self.out_var.set(data.get('out', ''))
        self.ltspice_var.set(data.get('ltspice', ''))
        self.ext_var.set(data.get('extensions', self.ext_var.get()))
        self.jobs_var.set(int(data.get('jobs', self.jobs_var.get())))
        self.timeout_var.set(int(data.get('timeout', 15)))
        self.group_size_var.set(int(data.get('group_size', 20)))
        self.max_files_var.set(int(data.get('max_files', 0)))
        self.max_subckts_var.set(int(data.get('max_subckts', 0)))
        self.only_suspect_var.set(bool(data.get('only_suspect', False)))
        self.skip_broken_var.set(bool(data.get('skip_broken_batch', False)))
        self.no_batch_var.set(bool(data.get('no_batch', False)))
        self.no_cache_var.set(bool(data.get('no_cache', False)))
        self.keep_raw_var.set(bool(data.get('keep_raw', False)))
        self.no_report_var.set(bool(data.get('no_report', False)))
        self.fix_bundle_var.set(bool(data.get('fix_bundle', False)))
        self.bundle_max_files_var.set(int(data.get('bundle_max_files', BUNDLE_DEFAULT_MAX_FILES)))
        self.bundle_min_conf_var.set(str(data.get('bundle_min_confidence', 'low')))
        self.verbose_var.set(bool(data.get('verbose', False)))

    def _on_close(self):
        self._save_settings()
        if self.process and self.process.poll() is None:
            from tkinter import messagebox
            if messagebox.askyesno("Audit en cours",
                                    "Un audit tourne. Le cache sera sauve avant arret. Quitter ?"):
                try:
                    if sys.platform == 'win32':
                        import signal as _signal
                        self.process.send_signal(_signal.CTRL_BREAK_EVENT)
                    else:
                        self.process.terminate()
                except Exception:
                    pass
            else:
                return
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _flush_stdout() -> None:
    """Force le line-buffering de stdout pour eviter l'effet 'freeze' en console
    (les print restent bloques dans le buffer si stdout est redirige)."""
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, OSError):
        pass


def main() -> int:
    _flush_stdout()
    parser = argparse.ArgumentParser(
        description="Audit automatise de librairies LTspice third-party (parallele + cache)"
    )
    parser.add_argument("--root", default="", help="Dossier racine de la librairie a auditer (requis sauf --gui / --report-only)")
    parser.add_argument("--out", default="", help="Dossier de sortie pour rapports et decks (requis sauf --gui)")
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
    parser.add_argument("--fix-bundle", action="store_true",
                        help="Genere un fix_bundle/ a la fin (sources + logs + JSON pour fix assiste)")
    parser.add_argument("--fix-bundle-only", action="store_true",
                        help="Genere uniquement le fix_bundle depuis les CSV existants (pas d'audit)")
    parser.add_argument("--bundle-max-files", type=int, default=BUNDLE_DEFAULT_MAX_FILES,
                        help=f"Cap du nb de fichiers dans le bundle (defaut {BUNDLE_DEFAULT_MAX_FILES})")
    parser.add_argument("--bundle-min-confidence",
                        choices=["high", "medium", "low", "manual_only"],
                        default="low",
                        help="Niveau de confiance minimum pour inclure un fichier (defaut low = tout sauf manual_only)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Logs detailles (rythme de progress accelere, marqueurs de phase plus bavards)")
    parser.add_argument("--group-size", type=int, default=20,
                        help="Sous-circuits regroupes par deck pour amortir le startup LTspice "
                             "(defaut 20 ; 1 = desactive). Les groupes qui echouent sont retestes individuellement.")
    parser.add_argument("--gui", action="store_true",
                        help="Lance l'interface graphique au lieu du mode CLI")
    args = parser.parse_args()

    if args.gui:
        return launch_gui()

    if not args.out:
        print("[ERREUR] --out est requis (sauf en mode --gui).")
        return 2

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

    # Mode --fix-bundle-only : skip audit, regen bundle depuis CSV existants
    if args.fix_bundle_only:
        if not (out / "reports").exists():
            print(f"[ERREUR] {out / 'reports'} introuvable. Lance d'abord un audit complet.")
            return 2
        p = generate_fix_bundle(out, args.bundle_max_files, args.bundle_min_confidence,
                                verbose=args.verbose)
        return 0 if p else 1

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

    print(f"[PHASE] Listage des fichiers candidats sous {root}...")
    t_list = time.time()
    files = list_candidate_files(root, exts)
    if args.max_files and args.max_files > 0:
        files = files[:args.max_files]
    print(f"[PHASE] Listage termine en {time.time() - t_list:.1f}s "
          f"({len(files)} fichier(s) trouves).")

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
        # Migration : requalifie les anciens faux positifs de la banniere LTspice
        n_fixed = _migrate_cache_banner_false_positives(cache)
        if n_fixed:
            print(f"[INFO] Cache migration : {n_fixed} entree(s) requalifiee(s) "
                  f"(banniere LTspice mal classee).")
            save_cache(cache_path, cache)

    # ============================================================
    # PRESCAN PARALLELE (avec hits cache)
    # ============================================================
    t_pre = time.time()

    summaries: List[FileSummary] = []
    static_issues: List[StaticIssue] = []
    subckts: List[SubcktInfo] = []
    models: List[ModelInfo] = []
    file_hashes: Dict[str, str] = {}

    print(f"[PHASE] Verification du cache : calcul des hashes pour {len(files)} fichier(s)...")
    t_hash = time.time()
    to_scan: List[Path] = []
    cached_hits = 0
    hash_progress_every = 200 if args.verbose else 2000
    for i, fp in enumerate(files, start=1):
        if i % hash_progress_every == 0 or i == len(files):
            elapsed = time.time() - t_hash
            rate = i / elapsed if elapsed > 0 else 0
            eta = (len(files) - i) / rate if rate > 0 else 0
            print(f"[INFO] Hash: {i}/{len(files)} ({100*i/len(files):.0f}%) "
                  f"- {rate:.0f} fichiers/s - ETA {fmt_eta(eta)}")
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
    # PREPARATION BATCH (avec groupement de subckts si --group-size > 1)
    # ============================================================
    summary_map: Dict[str, FileSummary] = {x.file_path: x for x in summaries}
    command_rows: List[dict] = []
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

    group_size = max(1, args.group_size)
    if not args.no_batch and ltspice_exe is not None and group_size > 1:
        print(f"[INFO] Groupement      : {group_size} subckts par deck "
              f"(fallback individuel si echec)")

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

    def restore_cached_to_results(cached: dict) -> bool:
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
            return True
        except Exception:
            return False

    def append_result_from_dict(res: dict) -> None:
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

    # ---- A. FILE_PARSE par fichier ----
    print(f"[PHASE] Generation des decks FILE_PARSE ({len(summaries)} fichier(s) candidats)...")
    t_decks_a = time.time()
    file_parse_tasks: List[dict] = []
    file_parse_cache_hits = 0
    deck_progress_every = 200 if args.verbose else 1000
    decks_done_a = 0
    for fs in summaries:
        if file_skip_for_batch(fs):
            continue
        file_path = Path(fs.file_path)
        file_h = file_hashes.get(fs.file_path, "no_hash")
        task_id = f"{file_h}|FILE_PARSE|(file)"

        deck_name = safe_name(fs.rel_path) + "__file_parse_test.cir"
        cir_path = decks_dir / deck_name
        cir_path.write_text(build_file_parse_test_deck(file_path), encoding="utf-8")
        decks_done_a += 1
        if decks_done_a % deck_progress_every == 0:
            print(f"[INFO] Decks FILE_PARSE: {decks_done_a} ecrits "
                  f"({time.time() - t_decks_a:.1f}s)")
        command_rows.append({
            "kind": "FILE_PARSE",
            "file_path": fs.file_path,
            "rel_path": fs.rel_path,
            "target_name": "(file)",
            "cir_path": str(cir_path),
            "suggested_command": make_cmd_str(cir_path),
        })

        cached = cache["batch"].get(task_id) if not args.no_cache else None
        if cached and restore_cached_to_results(cached):
            file_parse_cache_hits += 1
        elif not args.no_batch and ltspice_exe is not None:
            file_parse_tasks.append({
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

    print(f"[PHASE] FILE_PARSE termine : {decks_done_a} deck(s) ecrits en "
          f"{time.time() - t_decks_a:.1f}s "
          f"({file_parse_cache_hits} hit cache, {len(file_parse_tasks)} a executer).")

    # ---- B. SUBCKTS : cache check + groupement par fichier ----
    subs_iter = subckts
    if args.max_subckts and args.max_subckts > 0:
        subs_iter = subs_iter[:args.max_subckts]

    print(f"[PHASE] Verification cache des sous-circuits ({len(subs_iter)} sous-circuit(s))...")
    t_subs = time.time()
    non_cached_subs_per_file: Dict[str, List[SubcktInfo]] = {}
    sub_cache_hits = 0
    sub_cache_progress_every = 500 if args.verbose else 5000
    for i, sub in enumerate(subs_iter, start=1):
        if i % sub_cache_progress_every == 0 or i == len(subs_iter):
            print(f"[INFO] Cache subckts: {i}/{len(subs_iter)} verifies "
                  f"({sub_cache_hits} hit)")
        fs = summary_map.get(sub.file_path)
        if fs and file_skip_for_batch(fs):
            continue
        file_h = file_hashes.get(sub.file_path, "no_hash")
        indiv_id = f"{file_h}|SUBCKT_INSTANTIATION|{sub.name}"
        cached = cache["batch"].get(indiv_id) if not args.no_cache else None
        if cached and restore_cached_to_results(cached):
            sub_cache_hits += 1
        else:
            non_cached_subs_per_file.setdefault(sub.file_path, []).append(sub)

    n_files_to_deck = len(non_cached_subs_per_file)
    print(f"[PHASE] Verification cache subckts terminee en {time.time() - t_subs:.1f}s "
          f"({sub_cache_hits} hit, {n_files_to_deck} fichier(s) avec subckts non-caches).")
    print(f"[PHASE] Generation des decks SUBCKT (groupes de {group_size})...")
    t_decks_b = time.time()
    file_deck_progress_every = 50 if args.verbose else 500
    decks_done_b = 0

    pass1_subckt_tasks: List[dict] = []
    for file_idx, (file_path_str, members) in enumerate(non_cached_subs_per_file.items(), start=1):
        fs = summary_map.get(file_path_str)
        if fs is None:
            continue
        file_h = file_hashes.get(file_path_str, "no_hash")
        abs_file_path = Path(file_path_str)

        # Decoupage en lots de group_size
        chunks_iter = [members[i:i + group_size]
                       for i in range(0, len(members), group_size)]

        if file_idx % file_deck_progress_every == 0 or file_idx == n_files_to_deck:
            print(f"[INFO] Decks SUBCKT: fichier {file_idx}/{n_files_to_deck} "
                  f"- {decks_done_b} deck(s) ecrits ({time.time() - t_decks_b:.1f}s)")

        for chunk_idx, chunk in enumerate(chunks_iter):
            if len(chunk) == 1 or group_size <= 1:
                sub = chunk[0]
                deck_name = safe_name(sub.rel_path + "__" + sub.name) + "__subckt_test.cir"
                cir_path = decks_dir / deck_name
                cir_path.write_text(
                    build_subckt_test_deck(abs_file_path, sub.name, sub.pin_count),
                    encoding="utf-8"
                )
                decks_done_b += 1
                command_rows.append({
                    "kind": "SUBCKT_INSTANTIATION",
                    "file_path": sub.file_path,
                    "rel_path": sub.rel_path,
                    "target_name": sub.name,
                    "cir_path": str(cir_path),
                    "suggested_command": make_cmd_str(cir_path),
                })
                if not args.no_batch and ltspice_exe is not None:
                    pass1_subckt_tasks.append({
                        "task_id": f"{file_h}|SUBCKT_INSTANTIATION|{sub.name}",
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
            else:
                names = [s.name for s in chunk]
                preview = ",".join(names[:3]) + ("..." if len(names) > 3 else "")
                target_name = f"GROUP[{preview}]({len(names)})"
                deck_name = safe_name(fs.rel_path + f"__group{chunk_idx:04d}") + "__subckt_group_test.cir"
                cir_path = decks_dir / deck_name
                cir_path.write_text(
                    build_subckt_group_test_deck(
                        abs_file_path, [(s.name, s.pin_count) for s in chunk]
                    ),
                    encoding="utf-8"
                )
                decks_done_b += 1
                command_rows.append({
                    "kind": "SUBCKT_GROUP",
                    "file_path": fs.file_path,
                    "rel_path": fs.rel_path,
                    "target_name": target_name,
                    "cir_path": str(cir_path),
                    "suggested_command": make_cmd_str(cir_path),
                })
                if not args.no_batch and ltspice_exe is not None:
                    pass1_subckt_tasks.append({
                        "task_id": f"{file_h}|SUBCKT_GROUP|{chunk_idx:04d}|{names[0]}",
                        "target_kind": "SUBCKT_GROUP",
                        "file_path": fs.file_path,
                        "rel_path": fs.rel_path,
                        "target_name": target_name,
                        "cir_path": str(cir_path),
                        "ltspice_exe": str(ltspice_exe),
                        "cmd_prefix": cmd_prefix,
                        "timeout": args.timeout,
                        "keep_raw": args.keep_raw,
                        "members": [
                            {"name": s.name, "rel_path": s.rel_path, "pin_count": s.pin_count}
                            for s in chunk
                        ],
                        "file_h": file_h,
                    })

    print(f"[PHASE] Generation SUBCKT terminee : {decks_done_b} deck(s) en "
          f"{time.time() - t_decks_b:.1f}s.")
    pass1_tasks = file_parse_tasks + pass1_subckt_tasks

    write_csv(
        reports_dir / "batch_commands.csv",
        command_rows,
        fieldnames=["kind", "file_path", "rel_path", "target_name", "cir_path", "suggested_command"],
    )

    total_cache_hits = file_parse_cache_hits + sub_cache_hits
    if not args.no_cache and total_cache_hits:
        print(f"[INFO] Cache batch     : {total_cache_hits} hit "
              f"({file_parse_cache_hits} fichier, {sub_cache_hits} subckt).")

    # ---- C. Helper pour executer une passe en parallele ----
    def _run_pass(tasks_list: List[dict], label: str) -> List[dict]:
        if not tasks_list:
            return []
        print(f"[INFO] {label} : {len(tasks_list)} tests, {jobs} workers, timeout={args.timeout}s")
        t0 = time.time()
        out_results: List[dict] = []
        completed_local = 0
        last_save_local = 0
        try:
            with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as exe:
                futures = {exe.submit(_batch_worker, t): t for t in tasks_list}
                for fut in concurrent.futures.as_completed(futures):
                    t = futures[fut]
                    try:
                        res = fut.result()
                    except Exception as exc:
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
                    # Propage les infos hors-worker (utile pour SUBCKT_GROUP)
                    if t.get("target_kind") == "SUBCKT_GROUP":
                        res["members"] = t.get("members", [])
                        res["file_h"] = t.get("file_h", "no_hash")
                    out_results.append(res)
                    completed_local += 1

                    if not args.no_cache and (completed_local - last_save_local >= CACHE_SAVE_EVERY):
                        save_cache(cache_path, cache)
                        last_save_local = completed_local

                    if completed_local % 50 == 0 or completed_local == len(tasks_list):
                        elapsed = time.time() - t0
                        rate = completed_local / elapsed if elapsed > 0 else 0
                        eta_s = (len(tasks_list) - completed_local) / rate if rate > 0 else 0
                        pct = 100 * completed_local / len(tasks_list)
                        print(f"[INFO] {label}: {completed_local}/{len(tasks_list)} ({pct:.1f}%) "
                              f"- {rate*60:.0f} tests/min - ETA {fmt_eta(eta_s)}")
        except KeyboardInterrupt:
            print("[WARN] Interruption clavier. Sauvegarde du cache avant sortie...")
            if not args.no_cache:
                save_cache(cache_path, cache)
            raise

        if not args.no_cache:
            save_cache(cache_path, cache)
        print(f"[INFO] {label} termine en {fmt_eta(time.time() - t0)}.")
        return out_results

    # ---- D. Passe 1 : FILE_PARSE + SUBCKT_GROUP / individus ----
    pass2_tasks: List[dict] = []
    if pass1_tasks:
        pass1_results = _run_pass(pass1_tasks, "Batch passe 1")
        for res in pass1_results:
            kind = res.get("target_kind", "")
            if kind == "SUBCKT_GROUP":
                members = res.get("members", [])
                file_h = res.get("file_h", "no_hash")
                file_path_s = res["file_path"]
                rel_path_s = res["rel_path"]
                if res["status"] == "OK":
                    # Synthese : chaque membre est marque OK individuellement
                    for m in members:
                        synth = {
                            "task_id": f"{file_h}|SUBCKT_INSTANTIATION|{m['name']}",
                            "target_kind": "SUBCKT_INSTANTIATION",
                            "file_path": file_path_s,
                            "rel_path": rel_path_s,
                            "target_name": m["name"],
                            "test_cir": res["test_cir"],
                            "status": "OK",
                            "exit_code": res["exit_code"],
                            "error_summary": "(via group test)",
                            "raw_log_path": res["raw_log_path"],
                        }
                        append_result_from_dict(synth)
                        if not args.no_cache:
                            cache["batch"][synth["task_id"]] = synth
                else:
                    # Echec: fallback individuel pour chaque membre
                    for m in members:
                        deck_name = safe_name(m["rel_path"] + "__" + m["name"]) + "__subckt_test.cir"
                        cir_path = decks_dir / deck_name
                        cir_path.write_text(
                            build_subckt_test_deck(Path(file_path_s), m["name"], m["pin_count"]),
                            encoding="utf-8"
                        )
                        pass2_tasks.append({
                            "task_id": f"{file_h}|SUBCKT_INSTANTIATION|{m['name']}",
                            "target_kind": "SUBCKT_INSTANTIATION",
                            "file_path": file_path_s,
                            "rel_path": rel_path_s,
                            "target_name": m["name"],
                            "cir_path": str(cir_path),
                            "ltspice_exe": str(ltspice_exe),
                            "cmd_prefix": cmd_prefix,
                            "timeout": args.timeout,
                            "keep_raw": args.keep_raw,
                        })
            else:
                append_result_from_dict(res)
                if not args.no_cache:
                    cache["batch"][res["task_id"]] = res

        if not args.no_cache:
            save_cache(cache_path, cache)

    # ---- E. Passe 2 : fallback individuel pour les groupes echoues ----
    if pass2_tasks:
        print(f"[INFO] Fallback        : {len(pass2_tasks)} tests individuels (groupes echoues).")
        pass2_results = _run_pass(pass2_tasks, "Batch passe 2")
        for res in pass2_results:
            append_result_from_dict(res)
            if not args.no_cache:
                cache["batch"][res["task_id"]] = res
        if not args.no_cache:
            save_cache(cache_path, cache)

    if not pass1_tasks and not args.no_batch and ltspice_exe is not None:
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

    if args.fix_bundle:
        try:
            generate_fix_bundle(out, args.bundle_max_files, args.bundle_min_confidence,
                                verbose=args.verbose)
        except Exception as exc:
            print(f"[WARN] Generation fix bundle echouee: {type(exc).__name__}: {exc}")

    print(f"[OK] Audit termine. Rapports dans : {out}")
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
