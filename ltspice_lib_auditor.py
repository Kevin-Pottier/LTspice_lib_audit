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
import hashlib
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
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit automatise de librairies LTspice third-party (parallele + cache)"
    )
    parser.add_argument("--root", required=True, help="Dossier racine de la librairie a auditer")
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
    print(f"[OK] Audit termine. Rapports dans : {out}")
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
