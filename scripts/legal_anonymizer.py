#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pt-legal-anonymizer v6.1 — Zero-Leak, Working-Copy Isolated, Screenshot-First Local Legal Anonymizer
=========================================================================
100% local, reversible PII anonymization engine for Brazilian/Portuguese and
international legal documents (.docx, .pdf, .txt, .md, .csv) and scanned
image-based PDFs, personal ID cards (CNH, RG), power-of-attorney instruments
(Procurações), and bank receipts (.pdf, .png, .jpg, .jpeg, .webp, .tif) in
tandem with `visual_redactor.py`.

What's New in v6.0 (From Real-World Case Folder Audit):
1. Windows Trailing-Space Filename Safety (`safe_file_stem`):
   - Automatically strips trailing spaces/dots from file stems (`"comp atendimento Tia Lu .pdf"`)
     when creating session/chunk/grid directories and output files so Windows NTFS never
     raises `FileNotFoundError` and original user files never need to be renamed.
2. Zero Source-Folder Clutter (Direct Delivery to `anonimizados/` or `--output-dir`):
   - Never writes intermediate `.anonymized.pdf` or `.anonymized.txt` files into the user's
     original attachment folder. Work-in-progress files live in the session staging directory
     and final deliverables are written directly into `<input_dir>/anonimizados/` (or the
     user's requested `--output-dir`, e.g. `anonymized/`).
3. Native Standalone Image Support (`.jpg`, `.jpeg`, `.png`, `.webp`, `.bmp`, `.tif`):
   - `chunk --dir` and `anonymize --dir` automatically OCR and visually redact standalone
     images (such as `senha da Juliana.jpeg`) alongside PDFs and Word documents.
4. Accent-Insensitive + Multi-Word Fuzzy OCR Coreference & Truncated Receipt Name Linking:
   - Automatically links accent differences (`"Sítio"` <-> `"Sitio"`, `"Conceição"` <-> `"Conceicao"`,
     `"Praça Capitão"` <-> `"Praca Capitao"`), 1-2 character OCR distortions in multi-word names and
     addresses (`"Viviane"` <-> `"VIVANE"`, `"Jose"` <-> `"TOSE"`, `"Praça Capitão"` <-> `"Praga Capitdo"`,
     `"Vista"` <-> `"Vlsta"`), and 32/35-char bank-receipt name truncations
     (`"ANA BEATRIZ PEREIRA DE ALMEIDA CA"`, `"CARLA MENDONCA TAVARES SOCI"`).
5. Municipality Protection & Zero False-Positive Leak Checks on `"logradouro"`:
   - Prevents standalone name parts (`"Aparecida"`, `"Conceição"`, `"Santa"`, `"São"`) from
     corrupting municipality names (`"Município de Conceição da Aparecida-MG"`).
   - Strips generic address nouns (`"logradouro"`, `"domicílio"`, `"residente"`, `"endereço"`)
     from street-core leak checks so `"residente e com domicílio no logradouro"` never
     triggers a false-positive leak on `<ENDERECO_N>`.
6. Non-Overlapping PDF Black Pill Widening:
   - Stops horizontal pill expansion before any adjacent redaction box on the same line so
     neighboring tags (`<ENDERECO_3e>` and `<CEP_3>`) never collide visually.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import difflib
import io
import json
import os
import posixpath
import re
import shutil
import sys
import tempfile
import time
import unicodedata
import urllib.error
from urllib.parse import unquote
import urllib.request
import uuid
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from xml.etree import ElementTree as ET

# Force UTF-8 on Windows consoles to prevent cp1252 mojibake
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

IMAGE_EXTENSIONS: Set[str] = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff"}
SUPPORTED_EXTENSIONS: Set[str] = {".pdf", ".docx", ".txt", ".md", ".csv"} | IMAGE_EXTENSIONS


# ============================================================================
# 1. STORAGE, SAFE WINDOWS PATH STEMS & SESSION MANAGEMENT
# ============================================================================

def safe_file_stem(file_path: Path) -> str:
    """
    Returns a Windows-safe file/directory stem with trailing spaces and dots stripped
    so files like `comp atendimento Tia Lu .pdf` never cause `FileNotFoundError`
    on Windows NTFS when creating subdirectories or output files.
    """
    raw = file_path.stem
    cleaned = re.sub(r'[<>:"/\\|?*]+', "_", raw).strip().rstrip(". ")
    return cleaned or "documento"


def get_vault_root() -> Path:
    env_dir = os.environ.get("PT_LEGAL_ANONYMIZER_HOME")
    if env_dir:
        root = Path(env_dir).expanduser().resolve()
    else:
        root = Path.home() / ".pt_legal_anonymizer"
    (root / "sessions").mkdir(parents=True, exist_ok=True)
    return root


def get_session_dir(session_id: str) -> Path:
    safe_id = re.sub(r"[^a-zA-Z0-9_\-.]", "_", session_id).strip().rstrip(". ")
    sdir = get_vault_root() / "sessions" / safe_id
    sdir.mkdir(parents=True, exist_ok=True)
    return sdir


def create_or_load_session(session_id: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
    if not session_id:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        session_id = f"caso_{ts}_{uuid.uuid4().hex[:6]}"
    sdir = get_session_dir(session_id)
    map_path = sdir / "mapping.json"
    if map_path.exists():
        data = json.loads(map_path.read_text(encoding="utf-8"))
        # Ensure accent-folded lookup table is populated
        surf_map = data.setdefault("surface_to_token", {})
        for tok, orig in data.get("token_to_original", {}).items():
            surf_map.setdefault(normalize_key(orig), tok)
            surf_map.setdefault(normalize_key_fold(orig), tok)
    else:
        data = {
            "session_id": session_id,
            "created_at": datetime.datetime.now().isoformat(),
            "updated_at": datetime.datetime.now().isoformat(),
            "counters": {},
            # token -> original exact surface string (e.g. "<PESSOA_1>": "João Antônio da Silva")
            "token_to_original": {},
            # normalized_surface -> token (for exact/case-folded/accent-folded lookup)
            "surface_to_token": {},
            # canonical_root_id -> {"category": str, "canonical": str, "variants": {surface: token}}
            "canonical_groups": {},
            # whitelist strings that must never be anonymized
            "whitelist": [],
            # audit stats
            "stats": {"files_processed": [], "rule_hits": {}, "ignored_false_positives": []},
        }
        save_session(session_id, data)
    return session_id, data


def _safe_json_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def save_session(session_id: str, data: Dict[str, Any]) -> Path:
    sdir = get_session_dir(session_id)
    data["updated_at"] = datetime.datetime.now().isoformat()
    map_path = sdir / "mapping.json"
    _safe_json_write(map_path, data)
    return map_path


# ============================================================================
# 2. MATHEMATICAL CHECKSUM VALIDATORS (MODULO-11 CPF, CNPJ & PIS/PASEP/NIT)
# ============================================================================

def validate_cpf_checksum(raw: str) -> bool:
    digits = [int(ch) for ch in re.sub(r"\D", "", raw)]
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    s1 = sum(digits[i] * (10 - i) for i in range(9))
    r1 = (s1 * 10) % 11
    if r1 == 10:
        r1 = 0
    if digits[9] != r1:
        return False
    s2 = sum(digits[i] * (11 - i) for i in range(10))
    r2 = (s2 * 10) % 11
    if r2 == 10:
        r2 = 0
    return digits[10] == r2


def validate_cnpj_checksum(raw: str) -> bool:
    digits = [int(ch) for ch in re.sub(r"\D", "", raw)]
    if len(digits) != 14 or len(set(digits)) == 1:
        return False
    w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    s1 = sum(digits[i] * w1[i] for i in range(12))
    r1 = s1 % 11
    d1 = 0 if r1 < 2 else 11 - r1
    if digits[12] != d1:
        return False
    w2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    s2 = sum(digits[i] * w2[i] for i in range(13))
    r2 = s2 % 11
    d2 = 0 if r2 < 2 else 11 - r2
    return digits[13] == d2


def validate_pis_checksum(raw: str) -> bool:
    digits = [int(ch) for ch in re.sub(r"\D", "", raw)]
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    weights = [3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(digits[i] * weights[i] for i in range(10))
    rem = 11 - (total % 11)
    check = 0 if rem in (10, 11) else rem
    return digits[10] == check


# ============================================================================
# 3. DETERMINISTIC BRAZILIAN LEGAL REGEX RULES (PASS 1) & JURISPRUDENCE GUARD
# ============================================================================

DEFAULT_LEGAL_WHITELIST_PATTERNS = [
    # 1. Higher court & state court jurisprudence citations (UlyssesLegalNER-Br JURISprocedimento / JURISprecedente)
    r"\b(?:AgRg|AgInt|EDcl|REsp|AREsp|RE|ADI|ADC|ADPF|HC|RHC|MS|RMS|RO|AIRR|RR|E-RR)\s+(?:no\s+|na\s+|nos\s+|nas\s+)?(?:[A-ZÁÉÍÓÚÂÊÔÃÕÇ\s]+)?N?[º°o.]?\s*[\d.\-/]+(?:\s*[-/]\s*[A-Z]{2})?",
    # 2. State/Federal Appellate Precedent Citations with Tribunal/Relator/Julgamento context
    r"\b(?:TJ[A-Z]{2}|TRF\s*[-–]?\s*[1-6]|STJ|STF|TST)\s*[,;:\-–]\s*(?:Apela[çc][ãa]o(?:\s+C[íi]vel|\s+Criminal)?|Agravo\s+(?:de\s+Instrumento|Interno|Regimental)|Recurso\s+Inominado|Embargos\s+de\s+Declara[çc][ãa]o|Mandado\s+de\s+Seguran[çc]a|Habeas\s+Corpus)\s*(?:n[º°o.:]?\s*)?[\d.\-–/]+",
    r"\b(?:Apela[çc][ãa]o(?:\s+C[íi]vel|\s+Criminal)?|Agravo\s+(?:de\s+Instrumento|Interno|Regimental)|Recurso\s+Inominado|Conflito\s+de\s+Compet[êe]ncia)\s*(?:n[º°o.:]?\s*)?\d[\d.\-–/]{10,28}(?=[,;)\s]{1,15}(?:Rel(?:ator|\.)|[ÓO]rg[ãa]o\s+Julgador|C[âa]mara|Turma|j\.\s*\d|julgado\s+em|Data\s+de\s+Julgamento|TJ[A-Z]{2}|TRF|STJ|STF))",
    # 2b. Who judged a cited case is public: "Rel. Min. Nancy Andrighi", "Relator Des. Fulano de Tal",
    #     "Ministra NANCY ANDRIGHI", "Rel. p/ acórdão Min. ...". Names are matched case-sensitively.
    r"\b(?:Rel(?:ator|atora|\.)?\s*(?:p/\s*(?:o\s+)?ac[óo]rd[ãa]o\s*)?[:.]?\s*(?:(?:Min(?:istr[oa])?|Des(?:embargador(?:a)?|a)?|Ju[íi]za?(?:\s+Convocad[oa])?|Cons(?:elheir[oa])?)\.?)|Ministr[oa](?:\s+Relator(?:a)?)?|Desembargador(?:a)?(?:\s+Relator(?:a)?)?)\s+(?-i:[A-ZÀ-Ý][A-Za-zÀ-ÿ'.]+(?:\s+(?:d[aeo]s?\s+|e\s+)?[A-ZÀ-Ý][A-Za-zÀ-ÿ'.]+){0,5})",
    # 2c. Dates and journals that close a citation ("julgado em 12/03/2024", "DJe 15/03/2024")
    r"\b(?:julgado\s+em|j\.|DJe|DJ|DJEN|DJMG|DJSP|publicado\s+em)\s*:?\s*\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}",
    # 3. State & Federal highways (avoid matching as RG: highways have 2-3 digits like MG-179, BR-116, SP-330)
    r"(?<!\bRG\s)(?<!\bCI\s)\b(?:BR|MG|SP|RJ|PR|SC|RS|BA|GO|DF|ES|PE|CE|MT|MS|PA|AM|MA|PB|RN|AL|SE|PI|TO|RO|AC|AP|RR)\s*[-–]\s*\d{2,3}\b(?!\.?\d{3})",
    # 4. Statutes, Codes, Súmulas, Enunciados, and Temas (LeNER-Br LEGISLACAO)
    r"\b(?:Lei|Decreto|Resolu[çc][ãa]o|Portaria|S[úu]mula|Tema|Enunciado|Instru[çc][ãa]o\s+Normativa|Provimento|Medida\s+Provis[óo]ria)\s+(?:Federal\s+|Estadual\s+|Municipal\s+|Complementar\s+|Vinculante\s+)?n?[º°o.]?\s*[\d.\-]+(?:/\d{2,4})?",
    # 5. PJe / eproc explicit document IDs ("ID 10635709142", "Id. 10543118735")
    r"\b(?:ID|Id\.|id\.?)\s*(?:n[º°o.]?\s*)?\d{7,12}\b",
    # 6. Military / Police Battalions and Companies ("77 CIA PM/12 BPM/18 RPM", "1 GP/4 PEL")
    r"\b\d{1,3}\s*(?:CIA|BPM|RPM|PEL|GP|DP|DRPC)\b",
    # 7. Public Municipality + UF patterns ("Município de Conceição da Aparecida-MG", "cidade de Nova Resende/MG", across newlines)
    r"\b(?:Munic[íi]pio|Municipio|Munic[a-zà-ÿ]+o|Cidade|Comarca|Natural|Foro)[\s\n]+d[eao][\s\n]+[A-ZÀ-Ÿa-zà-ÿ]+(?:[\s\n]+d[aeo]s?[\s\n]+[A-ZÀ-Ÿa-zà-ÿ]+|[\s\n]+[A-ZÀ-Ÿa-zà-ÿ]+){0,3}(?:\s*[-/(\s]\s*[A-Z]{2})?\b",
    # 8. Compound MG/SP Municipality Gazetteer (protects towns sharing personal/saint names like Conceição da Aparecida, Santa Rita de Caldas, São José da Barra, etc.)
    r"\b(?:Concei[çc][ãa]o[\s\n]+da[\s\n]+Aparecida|Santa[\s\n]+Rita[\s\n]+d[eo][\s\n]+[A-ZÀ-Ÿa-zà-ÿ]+|S[ãa]o[\s\n]+(?:Jos[ée]|Jo[ãa]o|Sebasti[ãa]o|Tom[áa]s|Pedro|Louren[çc]o|Gon[çc]alo|Bento|Vicente|Roque|carlos|Paulo|Sim[ãa]o|Tiago)[\s\n]+(?:d[aeo]s?[\s\n]+)?[A-ZÀ-Ÿa-zà-ÿ]+(?:[\s\n]+d[aeo]s?[\s\n]+[A-ZÀ-Ÿa-zà-ÿ]+)?|Bom[\s\n]+Jesus[\s\n]+d[aeo]s?[\s\n]+[A-ZÀ-Ÿa-zà-ÿ]+|Monte[\s\n]+(?:Santo|Belo|Si[ãa]o|Carmelo)(?:[\s\n]+de[\s\n]+Minas)?|Po[çc]os[\s\n]+de[\s\n]+Caldas|Nova[\s\n]+Resende|Carmo[\s\n]+do[\s\n]+Rio[\s\n]+Claro|Ita[úu][\s\n]+de[\s\n]+Minas|Alpin[óo]polis|Alpind?[ée]polis|Muzambinho)(?:\s*[-/(\s]\s*[A-Z]{2})?\b",
]


def is_jurisprudence_context(text: str, start: int, end: int) -> bool:
    left_window = text[max(0, start - 160) : start]
    right_window = text[end : min(len(text), end + 180)]
    if re.search(
        r"\b(?:EMENTA|JURISPRUD[ÊE]NCIA|PRECEDENTE(?:S)?|AC[ÓO]RD[ÃA]O|JULGADO|"
        r"TJ[A-Z]{2}\s*[-–,;:]|TRF\s*[-–]?\s*[1-6]\s*[-–,;:]|STJ\s*[-–,;:]|STF\s*[-–,;:]|"
        r"Apela[çc][ãa]o\s+C[íi]vel\s*(?:n[º°o.:]?\s*)?$|Agravo\s+de\s+Instrumento\s*(?:n[º°o.:]?\s*)?$|"
        r"Recurso\s+Inominado\s*(?:n[º°o.:]?\s*)?$)",
        left_window,
        flags=re.IGNORECASE,
    ):
        if re.search(
            r"\b(?:Rel(?:ator|atora|\.)|Des(?:embargador|a|\.)|[ÓO]rg[ãa]o\s+Julgador|"
            r"C[âa]mara\s+de\s+Direito|C[âa]mara\s+C[íi]vel|Turma\s+Recursal|"
            r"Data\s+do\s+Julgamento|Data\s+de\s+Publica[çc][ãa]o|j\.\s*\d{1,2}[/.\-]\d{1,2}|"
            r"julgado\s+em|DJe|DJMG|DJSP|v\.u\.)",
            left_window + " " + right_window,
            flags=re.IGNORECASE,
        ):
            return True
    if re.search(
        r"^\s*[,;)\-–]?\s*(?:Rel(?:ator|atora|\.)\s+(?:Des|Min)|[ÓO]rg[ãa]o\s+Julgador\s*:|"
        r"Data\s+do\s+Julgamento\s*:|j\.\s*\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4})",
        right_window,
        flags=re.IGNORECASE,
    ):
        return True
    return False


class RegexRule:
    def __init__(
        self,
        rule_id: str,
        category: str,
        pattern: str,
        flags: int = re.IGNORECASE,
        validator: Optional[Callable[[str], bool]] = None,
        group: int = 0,
        check_jurisprudence: bool = False,
    ):
        self.rule_id = rule_id
        self.category = category
        self.regex = re.compile(pattern, flags)
        self.validator = validator
        self.group = group
        self.check_jurisprudence = check_jurisprudence


def build_brazilian_legal_rules() -> List[RegexRule]:
    return [
        # Regra #1: CNJ 20-digit Lawsuit Numbers (formatted NNNNNNN-DD.AAAA.J.TR.OOOO & OCR variants)
        RegexRule(
            rule_id="Regra #1 [PROCESSO_CNJ]",
            category="PROCESSO",
            pattern=r"\b\d{7}\s*[-–]\s*\d{2}\s*\.\s*\d{4}\s*\.\s*\d\s*\.\s*\d{2}\s*\.\s*\d{4}(?:\s*/\s*\d{2,4})?\b",
            check_jurisprudence=True,
        ),
        # Regra #2: Second-Instance / TJ-MG Appeal Lawsuit Format (e.g. 1.0000.25.247738-5/001)
        RegexRule(
            rule_id="Regra #2 [PROCESSO_TJ_2INST]",
            category="PROCESSO",
            pattern=r"\b\d\.\d{4}\.\d{2}\.\d{5,7}-\d(?:/\d{3,4})?\b",
            check_jurisprudence=True,
        ),
        # Regra #3: Unseparated 20-digit CNJ Lawsuit String (when preceded by processo/autos context)
        RegexRule(
            rule_id="Regra #3 [PROCESSO_20DIG]",
            category="PROCESSO",
            pattern=r"\b(?:processo|autos|proc\.|nº|n°)\s{1,4}(\d{20})\b",
            group=1,
            check_jurisprudence=True,
        ),
        # Regra #3B: Private Non-CNJ Proceedings (Inquérito Policial, TCO, PAD, Carta Precatória)
        RegexRule(
            rule_id="Regra #3B [PROCEDIMENTO_PRIVADO]",
            category="PROCESSO",
            pattern=r"\b(?:Inqu[ée]rito\s+Policial|IP|Termo\s+Circunstanciado|TCO|Processo\s+Administrativo(?:\s+Disciplinar)?|PAD|Sindic[âa]ncia|Carta\s+Precat[óo]ria|Carta\s+de\s+Ordem|Autos)\s*(?:n[º°o.:]+|[:\-–])\s*([A-Z0-9.\-–/]{4,25})\b",
            group=1,
            check_jurisprudence=True,
        ),
        # Regra #4: CNPJ Formatted (XX.XXX.XXX/XXXX-XX or OCR comma-dotted) with Modulo-11 validation
        RegexRule(
            rule_id="Regra #4 [CNPJ_FORMATADO]",
            category="CNPJ",
            pattern=r"\b\d{2}\s*[.,]\s*\d{3}\s*[.,]\s*\d{3}\s*/\s*\d{4}\s*[-–]\s*\d{2}\b",
            validator=validate_cnpj_checksum,
        ),
        # Regra #5: CNPJ Unformatted 14 digits (with Modulo-11 validation)
        RegexRule(
            rule_id="Regra #5 [CNPJ_14DIG]",
            category="CNPJ",
            pattern=r"\b\d{14}\b",
            validator=validate_cnpj_checksum,
        ),
        # Regra #6: CPF Formatted (XXX.XXX.XXX-XX or OCR comma/space/dotted, even when glued to 'e' like '123.456.789-09e')
        RegexRule(
            rule_id="Regra #6 [CPF_FORMATADO]",
            category="CPF",
            pattern=r"(?<!\d)(\d{3}\s*[.,\s]\s*\d{3}\s*[.,\s]\s*\d{3}\s*[-–/]\s*\d{2})(?!\d)",
            group=1,
            validator=validate_cpf_checksum,
        ),
        # Regra #6B: CPF written as 9 digits, then "/" or "-" and the 2 check digits ("123456789/09", "123456789-09")
        RegexRule(
            rule_id="Regra #6B [CPF_9_2]",
            category="CPF",
            pattern=r"(?<![\d./])(\d{9}\s*[-–/]\s*\d{2})(?![\d/])",
            group=1,
            validator=validate_cpf_checksum,
        ),
        # Regra #6C: anything labelled CPF, even with odd OCR separators, when the check digits agree
        RegexRule(
            rule_id="Regra #6C [CPF_ROTULADO]",
            category="CPF",
            pattern=r"\bC\.?\s?P\.?\s?F\.?\s*(?:/\s*MF\s*)?(?:n[º°o.]*\s*|sob\s+o\s+n[º°o.]*\s*|:\s*)*((?:\d[\s.,\-–/]{0,2}){10}\d)(?!\d)",
            group=1,
            validator=validate_cpf_checksum,
        ),
        # Regra #7: Partially Masked CPF (e.g. ***.456.789-** or XXX.456.789-XX)
        RegexRule(
            rule_id="Regra #7 [CPF_MASCARADO]",
            category="CPF",
            pattern=r"(?:\*{2,3}|X{2,3})[.,]?\d{3}[.,]\d{3}[-\s]*(?:\*{2}|X{2}|\d{2})",
        ),
        # Regra #8: CPF Unformatted 11 digits (ONLY if valid Modulo-11 AND not preceded by ID/Id.)
        RegexRule(
            rule_id="Regra #8 [CPF_11DIG_CHECKSUM]",
            category="CPF",
            pattern=r"(?<!\bID\s)(?<!\bId\.\s)(?<!\d)\b\d{11}\b(?!\d)",
            validator=validate_cpf_checksum,
        ),
        # Regra #9: OAB Registration (two-branch: inline OAB/UF + number OR multiline OAB[/UF] + 'sob o número \n n 123.456', zero false positives on laws/contracts)
        RegexRule(
            rule_id="Regra #9 [OAB]",
            category="OAB",
            pattern=r"\bOAB\s*(?:[/\-–]\s*[A-Z]{2}|\s+[A-Z]{2})\s*(?:sob\s+(?:o\s+)?(?:n[úu]mero\s+)?|inscri[çc][ãa]o\s+|[:\-–]\s*|n[º°o.:]+\s*)?\d{1,3}(?:[.,]\d{3}|\d{3,5})(?:\s*[-–]\s*[A-Z]\b)?|\bOAB(?:\s*[/\-–]?\s*[A-Z]{2})?\s+(?:sob\s+(?:o\s+)?(?:n[úu]mero)?|inscri[çc][ãa]o|n[º°o.:]+)(?:[\s:]+|\s*\n\s*)(?:n[º°o.:]?\s*)?\d{1,3}(?:[.,]\d{3}|\d{3,5})(?:\s*[-–]\s*[A-Z]\b)?",
        ),
        # Regra #10: RG / Cédula de Identidade (inline or multiline 'sob o número', tolerating OCR comma separators)
        RegexRule(
            rule_id="Regra #10 [RG]",
            category="RG",
            pattern=r"\b(?:(?:RG|R\.G\.|C[ée]dula\s+de\s+Identidade|DOC\.\s*IDENTIDADE|REGISTRO\s+GERAL|Identidade|CI)\s*(?:sob\s+(?:o\s+)?n[úu]mero\s*|[:\-–]|n[º°o.:]+|\n\s*(?:n[º°o.:]?\s*)?){0,2}\s*(?:[A-Z]{2}\s*[-–]?\s*)?(?:\d{1,2}[.,]?\d{3}[.,]?\d{3}|\d{6,10})(?:\s*[-–]\s*[0-9Xx])?(?:\s*(?:SSP|PC|DETRAN|SESP|IFP)(?:[/\s][A-Z]{2})?)?|(?:MG|SP|RJ|PR|SC|RS|BA|GO|DF|ES|PE|CE|MT|MS|PA|AM|MA|PB|RN|AL|SE|PI|TO|RO|AC|AP|RR)\s*[-–]?\s*(?:\d{1,2}[.,]\d{3}[.,]\d{3}|\d{7,10}))\b",
        ),
        # Regra #10B: Multi-line Form Table RG (REDS / BO / CNH / Ficha Civil)
        RegexRule(
            rule_id="Regra #10B [RG_FORMULARIO]",
            category="RG",
            pattern=r"(?:CARTEIRA\s+DE\s+IDENTIDADE(?:\s+CIVIL)?|N[ÚU]MERO\s+(?:DO\s+)?DOCUMENTO\s+(?:DE\s+)?IDENTIDADE|DOC\.\s*IDENTIDADE\s*/\s*[ÓO]RG\s*EMISSOR)\s*[^\n]*\n\s*([A-Z]{0,2}\s*[-–]?\s*\d{6,10}(?:[-–][\dXx])?)\b|\b([A-Z]{0,2}\s*[-–]?\s*\d{6,10}(?:[-–][\dXx])?)\s*\n\s*N[ÚU]MERO\s+(?:DO\s+)?DOCUMENTO\s+(?:DE\s+)?IDENTIDADE",
            group=1,
        ),
        # Regra #11: Bank Agency, Cooperative & Account Numbers (including OCR-spaced accounts `12. 433-8` and boleto `0001 / 1234567-0`)
        RegexRule(
            rule_id="Regra #11 [CONTA_BANCARIA]",
            category="CONTA_BANCARIA",
            pattern=r"\b(?:(?:Ag(?:[êe]ncia|\.)|Cooperativa|Coop\.)\s*(?:[:\-–]|n[º°o.:]+)?\s*\d{3,5}(?:\s*[-–]\s*[\dXx]{1,2})?(?:\s*[,;/e\-–]\s*(?:C/?C|Conta(?:\s+Corrente|\s+Poupan[çc]a)?)\s*(?:[:\-–]|n[º°o.:]+)?\s*[\d.\s\-–Xx]+)?|(?:Conta\s+Corrente|Conta\s+Poupan[çc]a|Conta\s*[:\-]|C/C)\s*(?:[:\-–]|n[º°o.:]+)?\s*\d{1,6}(?:\s*[.\s]\s*\d{3})*(?:\s*[-–.]\s*[\dXx])?|\d{3,5}\s*/\s*\d{5,10}\s*[-–]\s*[\dXx])\b",
        ),
        # Regra #12: Property Registry Matrícula (e.g. matrícula nº 17.800)
        RegexRule(
            rule_id="Regra #12 [MATRICULA_IMOVEL]",
            category="MATRICULA_IMOVEL",
            pattern=r"\b[Mm]atr[íi]cula\s+(?:imobili[áa]ria\s+)?(?:[:\-–]|n[º°o.:]+)?\s*\d{1,3}(?:\.\d{3})+\b",
        ),
        # Regra #13: Email Addresses (including OCR space before `@` and OCR comma before `.com` like `Ifulano-silva@hotmail,.com`)
        RegexRule(
            rule_id="Regra #13 [EMAIL]",
            category="EMAIL",
            pattern=r"\b[A-Za-z0-9._%+\-]+\s*@\s*[A-Za-z0-9.\-]+[,;]*\.[A-Za-z]{2,}\b",
        ),
        # Regra #14: Brazilian Phone & WhatsApp Numbers (including compact REDS `(35)123-148-148` & `(XX) 9XXXX-XXXX`)
        RegexRule(
            rule_id="Regra #14 [TELEFONE]",
            category="TELEFONE",
            pattern=r"(?:\+55\s*)?(?:\(\s*\d{2}\s*\)\s*(?:\d{3}\s*[-–.]\s*\d{3}\s*[-–.]\s*\d{2,3}|9?\s*\d{4}\s*[-–.\s]?\s*\d{4})|\b\d{2}\s+9\s*\d{4}\s*[-–]\s*\d{4})\b",
        ),
        # Regra #15: CEP (Postal Code — XXXXX-XXX or XX.XXX-XXX)
        RegexRule(
            rule_id="Regra #15 [CEP]",
            category="CEP",
            pattern=r"\b(?:CEP\s*[:nº°o.]?\s*)?\d{2}\.?\d{3}\s*[-–]\s*\d{3}\b",
        ),
        # Regra #15B: CEP after its label, also without the hyphen or with OCR dots ("CEP 37860000", "CEP: 37.860.000")
        RegexRule(
            rule_id="Regra #15B [CEP_ROTULADO]",
            category="CEP",
            pattern=r"\bCEP\s*[:nº°o.]*\s*(\d{2}[.\s]?\d{3}[.\s\-–]?\d{3})(?!\d)",
            group=1,
        ),
        # Regra #16: Vehicle License Plates (inline `placa ABC-1234` OR multi-line form cell `PLACA \n ABC1D23`)
        RegexRule(
            rule_id="Regra #16 [PLACA]",
            category="PLACA",
            pattern=r"\b(?:placa(?:\s+da\s+viatura)?|ve[íi]culo\s+placa)\s*(?:[:nº°o.]|\n|\s){1,4}([A-Z]{3}\s*[-–]?\s*(?:\d{4}|\d[A-Z]\d{2}))\b|\b([A-Z]{3}(?:\d{4}|\d[A-Z]\d{2}))\s*\n\s*PREFIXO\s+/\s+[ÓO]RG[ÃA]O",
            group=1,
        ),
        # Regra #17: PIS / PASEP / NIT / NIS (XXX.XXXXX.XX-X) with Modulo-11 validation
        RegexRule(
            rule_id="Regra #17 [PIS_PASEP_NIT]",
            category="PIS_PASEP",
            pattern=r"\b\d{3}\.\d{4,5}\.\d{2,3}\s*[-–]\s*\d\b",
            validator=validate_pis_checksum,
        ),
        # Regra #18: CNH (Carteira Nacional de Habilitação inline OR CNH table `Nº REGISTRO` 11-digit number)
        RegexRule(
            rule_id="Regra #18 [CNH]",
            category="CNH",
            pattern=r"\b(?:(?:CNH|Habilita[çc][ãa]o)\s*(?:[:\-–]|n[º°o.:]+)?\s*(\d{9,11})|N[º°o.]?\s*REGISTRO[^\n]*\n[^\n]*?\b(\d{10,11}))\b",
            group=1,
        ),
        # Regra #19: CTPS (Carteira de Trabalho e Previdência Social + Série)
        RegexRule(
            rule_id="Regra #19 [CTPS]",
            category="CTPS",
            pattern=r"\bCTPS\s*(?:[:\-–]|n[º°o.:]+)?\s*\d{3,8}(?:\s*[,/\-–]\s*S[ée]rie\s*(?:[:\-–]|n[º°o.:]+)?\s*[\dA-Za-z\-]+)?\b",
        ),
        # Regra #20: Random PIX EVP Key (UUID) or PIX EndToEndId (`E` + 31 chars)
        RegexRule(
            rule_id="Regra #20 [CHAVE_PIX_UUID]",
            category="CHAVE_PIX",
            pattern=r"\b(?:(?:PIX|Chave\s+PIX|chave\s+aleat[óo]ria)\s*[:\-–]?\s*)?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|E\d{20}[A-Za-z0-9]{11})\b",
            group=1,
        ),
        # Regra #21: REDS / Boletim de Ocorrência (BO) Protocol Number (e.g. 2025-035867821-001)
        RegexRule(
            rule_id="Regra #21 [PROTOCOLO_BO_REDS]",
            category="PROTOCOLO_BO",
            pattern=r"\b\d{4}\s*[-–]\s*\d{7,10}\s*[-–]\s*\d{3}\b",
        ),
        # Regra #22: Police / Public Servant Functional Matrícula (`PM1576503`, `MATRÍCULA \n 1425321`)
        RegexRule(
            rule_id="Regra #22 [MATRICULA_FUNCIONAL]",
            category="MATRICULA",
            pattern=r"\b(?:PM|PC|BM|GM)\s*\d{5,9}\b|(?:MATR[ÍI]CULA|REGISTRO\s+GERAL)\s*\n\s*(\d{4,10})\b|\b(\d{5,9})\s*\n\s*(?:CARGO|MATR[ÍI]CULA)\b",
        ),
        # Regra #23: Exact GPS Latitude / Longitude Coordinates
        RegexRule(
            rule_id="Regra #23 [COORDENADA_GPS]",
            category="GPS",
            pattern=r"[-+]?\d{1,2}\s*[º°]\s*\d{1,2}\s*['’]\s*\d{1,2}(?:[.,]\d+)?\s*[\"”]|[-+]?\d{1,2}\s+\d{1,2}\s+\d{1,2}[.,]\d+\s*(?:[º°'\"”]+\s*){1,3}",
        ),
        # Regra #24: Form-Split House / Complement Numbers in Police Reports
        RegexRule(
            rule_id="Regra #24 [NUMERO_ENDERECO_FORM]",
            category="NUMERO",
            pattern=r"(?:N[ÚU]MERO|COMPLEMENTO)\s*\n\s*([1-9]\d{0,4}[A-Za-z]?)\b(?!\s*(?:/|\.\d|CIA|BPM|RPM|PEL|GP|GRAU|CLASSE|SARGENTO))|\b([1-9]\d{1,4}[A-Za-z]?)\s*\n\s*(?:N[ÚU]MERO|KM|COMPLEMENTO)\b(?!\s*DOCUMENTO)",
            group=1,
        ),
        # Regra #25: Bank Receipt Authentication / Envelope / Boleto Linha Digitável & Continuous Barcodes / BB Terminal IDs / Queue Tickets
        RegexRule(
            rule_id="Regra #25 [ID_TRANSACAO_BANCARIA]",
            category="ID_TRANSACAO",
            pattern=r"\b(?:(?:NR\.?\s*)?AUTENTICA[ÇC][ÃA][OD](?:\s+ELETR[ÔO]NICA)?|NR\.?\s*ENVELOPE|NOSSO\s+N[ÚU]MERO|ID\s*(?:DA\s+)?TRANSA[ÇC][ÃA]O|C[ÓO]DIGO\s+DE\s+AUTENTICA[ÇC][ÃA]O)\s*[:\-–—\n\s]*([A-Z0-9][A-Z0-9.,\s\-–/]{4,42}?)(?=\n|$|\s{2,})|\b(\d{5}[.\s]\d{5}\s+\d{5}[.\s]\d{6}\s+\d{5}[.\s]\d{6}\s+\d\s+\d{14}|\d{44,48}|\d(?:[ ]?\d){43,53}|46191\d{15,35}(?:\s+\d{1,20}){1,4}|\d{8,10}\s+0\d{3})\b|\bPROTOCOLO\s*[:\-–— \t]+(\d{6,20})\b|\bSENHA\s*[:=\-–]\s*([A-Z0-9]{4,6})\b",
            group=1,
            validator=lambda v: (
                (
                    sum(ch.isdigit() for ch in v) >= 4
                    or bool(re.match(r"^[A-Z0-9]{4,6}$", v.strip()))
                    or bool(re.match(r"^[0-9A-FO](?:\.[0-9A-F]{3}){4,5}$", v.strip(), re.IGNORECASE))
                )
                and not re.search(
                    r"\b(?:COMPROVANTE|DEPOSITO|PROCESSADO|DOCUMENTO|ESP[ÉE]CIE|QUANTIDADE|VALOR|ENTREGA|ABERTOS|SUJEITO)\b",
                    v,
                    re.IGNORECASE,
                )
            ),
        ),
        # Regra #26: Professional Council Registrations (CRM, CREA, CAU, CRC, COREN, CRO, CRP, CRF, CREFITO)
        RegexRule(
            rule_id="Regra #26 [CONSELHO_PROFISSIONAL]",
            category="CONSELHO_PROFISSIONAL",
            pattern=r"\b(?:CRM|CREA|CAU|CRC|COREN|CRO|CRP|CRF|CREFITO|CRN|CRBM|CRESS)\s*(?:[-–/]\s*[A-Z]{2}|\s+[A-Z]{2}|(?:AC|AL|AP|AM|BA|CE|DF|ES|GO|MA|MT|MS|MG|PA|PB|PR|PE|PI|RJ|RN|RS|RO|RR|SC|SP|SE|TO)(?=[\s:\-–n]))?\s*(?:[:\-–]|n[º°o.:]+)?\s*\d{2,4}(?:\.?\d{3})*(?:\s*[-–/]\s*[A-Za-z0-9]{1,4})?\b",
        ),
        # Regra #27: Notarial & Civil Registry Coordinates (Livro, Folha, Termo & RG DOC. ORIGEM)
        RegexRule(
            rule_id="Regra #27 [CARTORIO_LIVRO_FOLHA]",
            category="REGISTRO_CARTORIO",
            pattern=r"\bLivro\s+[A-Za-z0-9\-]+\s*,\s*(?:fls\.?|Folha(?:s)?)\s*(?:n[º°o.]?\s*)?\d+[A-Za-z0-9\-]*(?:\s*,\s*Termo\s*(?:n[º°o.]?\s*)?\d+)?\b|\bTermo\s+de\s+(?:Nascimento|Casamento|[ÓO]bito)\s*(?:[:\-–]|n[º°o.:]+)?\s*\d{2,10}\b|\b(?:C\.|TERMO\s*)\d+\s+FLS\.?\s*\d+[A-Za-z0-9]*\s+L\.?\s*[A-Za-z0-9\-]+\b",
        ),
        # Regra #28: Private Company / Law Firm Domain URLs (excluding .gov.br / .jus.br / .leg.br / .mp.br / .def.br / bb.com.br)
        RegexRule(
            rule_id="Regra #28 [URL_DOMINIO_PRIVADO]",
            category="EMAIL",
            pattern=r"\bhttps?\s?:\s?/{1,2}\s?(?:www\.)?[A-Za-z0-9\-]+\.[A-Za-z0-9.\-/]+",   # OCR reads `https: /site.com.br/`
            validator=lambda v: not re.search(r"\b(?:gov\.br|jus\.br|leg\.br|mp\.br|def\.br|bb\.com\.br|caixa\.gov\.br|serpro\.gov\.br)\b", v, re.IGNORECASE),
        ),
    ]


# ============================================================================
# 4. ENTITY VAULT, ACCENT-INSENSITIVE & FUZZY OCR COREFERENCE ENGINE
# ============================================================================

PORTUGUESE_COMMON_WORD_STOPWORDS: Set[str] = {
    "autor", "autora", "autores", "reu", "réu", "reus", "réus", "executado", "executada",
    "exequente", "apelante", "apelado", "apelada", "agravante", "agravado", "agravada",
    "embargante", "embargado", "embargada", "reclamante", "reclamado", "reclamada",
    "impetrante", "impetrado", "solicitante", "vitima", "vítima", "testemunha", "gerente",
    "cliente", "envolvido", "envolvida", "condutor", "condutora", "relator", "relatora",
    "juiz", "juiza", "juíza", "direito", "justica", "justiça", "estado", "federal",
    "civil", "militar", "policia", "polícia", "delegacia", "comarca", "vara", "camara",
    "câmara", "tribunal", "ministerio", "ministério", "publico", "público", "publica",
    "pública", "defesa", "social", "seguranca", "segurança", "passos", "resende",
    "nova", "novo", "horizonte", "belo", "centro", "bairro", "cidade", "municipio",
    "município", "brasil", "minas", "gerais", "paulo", "santo", "santa", "sao", "são",
    "avenida", "rua", "praca", "praça", "praga", "travessa", "alameda", "rodovia", "estrada",
    "logradouro", "domicilio", "domicílio", "residente", "endereco", "endereço", "sala",
    "andar", "conjunto", "condominio", "condomínio", "alpinopolis", "alpinópolis",
    "conceicao", "conceição", "conceigao", "pocos", "poços", "pogos", "caldas", "aparecida",
    "fazenda", "sitio", "sítio", "chacara", "chácara", "casa", "bloco", "apto", "lote",
    "quadra", "supermercado", "mercearia", "sacolao", "sacolão", "banco", "cooperativa",
    "credito", "crédito", "conta", "corrente", "poupanca", "poupança", "cartao", "cartão",
    "pagamento", "valor", "reais", "centavos", "compra", "compras", "produto", "produtos",
    "caixa", "sistema", "erro", "erros", "fila", "copia", "cópia", "comprovante", "fatos",
    "data", "hora", "local", "meio", "causa", "sexo", "feminino", "masculino", "idade",
    "branca", "parda", "preta", "amarela", "casado", "casada", "solteiro", "solteira",
    "rural", "produtor", "produtora", "ensino", "fundamental", "medio", "médio",
    "completo", "incompleto", "primeiro", "primeiros", "segundo", "terceiro", "anos",
    "estudo", "carteira", "identidade", "orgao", "órgão", "expedidor", "secretaria",
    "viatura", "placa", "prefixo", "padrao", "padrão", "soldado", "sargento", "cabo",
    "tenente", "capitao", "capitão", "capitdo", "major", "coronel", "perito", "pericia", "perícia",
    "recibo", "cargo", "unidade", "corporacao", "corporação", "assinatura", "registro",
    "geral", "numero", "número", "complemento", "cep", "email", "telefone", "celular",
    "comercial", "residencial", "motivo", "ausencia", "ausência", "informacao",
    "informação", "desconhecida", "ignorado", "ignorada", "outros", "outras", "acoes",
    "ações", "ato", "consumado", "tentado", "via", "acesso", "mediato", "imediato",
    "processo", "autos", "peticao", "petição", "sentenca", "sentença", "decisao",
    "decisão", "acordao", "acórdão", "recurso", "apelacao", "apelação", "agravo",
    "instrumento", "inquerito", "inquérito", "policial", "boletim", "ocorrencia",
    "ocorrência", "presenca", "presença", "interior", "advogado", "advogada", "sociedade",
    "individual", "advocacia", "outorgante", "outorgantes", "outorgado", "outorgados",
    "silva", "santos", "souza", "sousa", "oliveira", "pereira", "ferreira", "almeida",
    "nascimento", "lima", "araujo", "araújo", "fernandes", "carvalho", "gomes", "martins",
    "rocha", "ribeiro", "alves", "monteiro", "mendes", "barros", "freitas", "barbosa",
    "pinto", "moura", "cavalcanti", "dias", "castro", "campos", "cardoso", "teixeira",
    "melo", "mello", "moreira", "ramos", "vieira", "machado", "marques", "fonseca",
    "andrade", "cruz", "costa", "rosa", "clara", "reis", "pires", "leite", "neto",
    "filho", "junior", "júnior", "sobrinho", "maria", "jose", "josé", "joao", "joão",
    "antonio", "antônio", "paulo", "carlos", "pedro", "lucas", "marcos", "francisco",
    "jesus", "inocencia", "inocência",
}

STREET_PREFIX_ALTERNATIVES = (
    r"(?:Logradouro\s+)?(?:Avenida|Av\.?|Rua|R\.|Alameda|Al\.|Travessa|Tv\.|"
    r"Pra[çc]a|Praga|P[çc]a\.?|Rodovia|Rod\.|Estrada|Est\.|S[íi]tio|Fazenda|"
    r"Ch[áa]cara|Largo|Viela|Beco)"
)

CATEGORY_ALIASES: Dict[str, str] = {
    "PERSON": "PESSOA",
    "NOME": "PESSOA",
    "PARTE": "PESSOA",
    "NICKNAME": "APELIDO",
    "ALCUNHA": "APELIDO",
    "VULGO": "APELIDO",
    "ORG": "EMPRESA",
    "ORGANIZACAO": "EMPRESA",
    "ADDRESS": "ENDERECO",
    "LOCAL": "ENDERECO",
    "PROCESSO_PRIVADO": "PROCESSO",
    "PROCEDIMENTO": "PROCESSO",
    "INQUERITO": "PROCESSO",
    "PIX": "CHAVE_PIX",
    "PIX_KEY": "CHAVE_PIX",
    "BANK_ACCOUNT": "CONTA_BANCARIA",
    "CONTA": "CONTA_BANCARIA",
    "PHONE": "TELEFONE",
    "TELEFONE_ADICIONAL": "TELEFONE",
    "CELULAR": "TELEFONE",
    "PLATE": "PLACA",
    "PLACA_VEICULO": "PLACA",
    "CARTORIO": "REGISTRO_CARTORIO",
    "CARTORIO_REGISTRO": "REGISTRO_CARTORIO",
    "LIVRO_FOLHA": "REGISTRO_CARTORIO",
    "CRM": "CONSELHO_PROFISSIONAL",
    "CREA": "CONSELHO_PROFISSIONAL",
    "CRC": "CONSELHO_PROFISSIONAL",
    "COREN": "CONSELHO_PROFISSIONAL",
    "SIGNATURE": "ASSINATURA",
    "PHOTO": "FOTO",
    "FOTO_PESSOA": "FOTO",
}


def strip_accents(text: str) -> str:
    return "".join(
        ch for ch in unicodedata.normalize("NFKD", text) if unicodedata.category(ch) != "Mn"
    )


def normalize_key(surface: str) -> str:
    return re.sub(r"\s+", " ", surface.strip()).casefold()


def normalize_key_fold(surface: str) -> str:
    return strip_accents(re.sub(r"\s+", " ", surface.strip())).casefold()


def canonicalize_category(category: str) -> str:
    raw = re.sub(r"[^A-Z0-9_]", "_", category.upper().strip())
    return CATEGORY_ALIASES.get(raw, raw)


def strip_corporate_suffixes(name: str) -> str:
    cleaned = re.sub(r"[.,\-–/]+", " ", name)
    cleaned = re.sub(
        r"\b(?:S\s+A|SA|LTDA|MEI|ME|EPP|EIRELI|SOCIEDADE(?:\s+INDIVIDUAL)?(?:\s+DE\s+ADVOCACIA)?|"
        r"SOCIEDADE\s+AN[ÔO]NIMA|COOPERATIVA\s+DE\s+CR[ÉE]DITO|SUPERMERCADO|SUPERMERCADOS|"
        r"MERCEARIA|COMERCIO|COM[ÉE]RCIO|INDUSTRIA|IND[ÚU]STRIA)\b",
        " ",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    # Never return bare country/state phrases like "DO BRASIL" or "BRASIL" as a corporate core!
    if normalize_key_fold(cleaned) in ("do brasil", "brasil", "banco do brasil", "de minas", "minas gerais", "sao paulo"):
        return ""
    return cleaned


def extract_address_core(address: str) -> Tuple[Optional[str], Optional[str], List[str]]:
    clean = re.sub(r"\s+", " ", address.strip())
    # Strip leading generic word "logradouro"
    clean = re.sub(r"^(?:no\s+)?logradouro\s+", "", clean, flags=re.IGNORECASE).strip()
    house_nums = [
        m.group(1)
        for m in re.finditer(r"(?:,\s*|\bn[º°o.]?\s*|\bnum\.?\s*)([1-9]\d{0,4}[A-Za-z]?)\b", clean, flags=re.IGNORECASE)
    ]
    head = re.split(
        r"\s*[,;\-–]\s*|\s+\bn[º°o.]\s*\d+|\s+\bno\s+Munic[íi]pio\b|\s+\bna\s+cidade\b",
        clean,
        maxsplit=1,
        flags=re.IGNORECASE,
    )[0].strip()
    m = re.match(rf"^({STREET_PREFIX_ALTERNATIVES})\b\s*(.+)$", head, flags=re.IGNORECASE)
    if m:
        prefix = m.group(1).strip()
        core = m.group(2).strip(" .,;-")
        core = re.sub(r"\s+\d+[A-Za-z]?$", "", core).strip()
        return prefix, (core if len(core) >= 4 else None), house_nums
    return None, (head if len(head) >= 5 else None), house_nums


def register_entity(
    session_data: Dict[str, Any],
    surface: str,
    category: str,
    canonical_hint: Optional[str] = None,
) -> str:
    surface_clean = re.sub(r"\s+", " ", surface.strip())
    if not surface_clean:
        return surface

    norm = normalize_key(surface_clean)
    norm_fold = normalize_key_fold(surface_clean)
    for w in session_data.get("whitelist", []):
        if normalize_key_fold(w) == norm_fold:
            return surface

    if norm in session_data["surface_to_token"]:
        return session_data["surface_to_token"][norm]
    if norm_fold in session_data["surface_to_token"]:
        tok_existing = session_data["surface_to_token"][norm_fold]
        session_data["surface_to_token"][norm] = tok_existing
        return tok_existing

    cat_upper = canonicalize_category(category)
    groups = session_data.setdefault("canonical_groups", {})

    matched_group_id: Optional[str] = None
    hint_fold = normalize_key_fold(canonical_hint) if canonical_hint else None

    for gid, ginfo in groups.items():
        canon_fold = normalize_key_fold(ginfo["canonical"])
        if hint_fold and (
            hint_fold == canon_fold
            or hint_fold in [normalize_key_fold(v) for v in ginfo["variants"]]
        ):
            matched_group_id = gid
            break
        if ginfo["category"] != cat_upper:
            continue
        if cat_upper == "PESSOA" and len(surface_clean) >= 4:
            canon_words = [w for w in canon_fold.split() if len(w) > 2]
            surf_words = [w for w in norm_fold.split() if len(w) > 2]
            if len(surf_words) >= 2 and all(w in canon_words for w in surf_words):
                matched_group_id = gid
                break
            if len(canon_words) >= 2 and all(w in surf_words for w in canon_words):
                matched_group_id = gid
                break
            if len(surf_words) >= 2 and len(canon_words) >= 2 and difflib.SequenceMatcher(None, norm_fold, canon_fold).ratio() >= 0.85:
                matched_group_id = gid
                break
        elif cat_upper == "EMPRESA" and len(surface_clean) >= 4:
            root_existing = normalize_key_fold(strip_corporate_suffixes(ginfo["canonical"]))
            root_new = normalize_key_fold(strip_corporate_suffixes(surface_clean))
            if root_existing and root_new and (
                root_existing == root_new
                or root_existing in root_new
                or root_new in root_existing
            ):
                matched_group_id = gid
                break
        elif cat_upper == "ENDERECO" and len(surface_clean) >= 5:
            _, core_existing, _ = extract_address_core(ginfo["canonical"])
            _, core_new, _ = extract_address_core(surface_clean)
            if core_existing and core_new:
                ce_fold = normalize_key_fold(core_existing)
                cn_fold = normalize_key_fold(core_new)
                if ce_fold == cn_fold or difflib.SequenceMatcher(None, ce_fold, cn_fold).ratio() >= 0.82:
                    matched_group_id = gid
                    break
        elif cat_upper == "MATRICULA" and len(surface_clean) >= 5:
            digits_existing = re.sub(r"\D", "", ginfo["canonical"])
            digits_new = re.sub(r"\D", "", surface_clean)
            if digits_existing and digits_existing == digits_new:
                matched_group_id = gid
                break

    if matched_group_id is None:
        idx = session_data["counters"].get(cat_upper, 0) + 1
        session_data["counters"][cat_upper] = idx
        base_id = f"{cat_upper}_{idx}"
        token = f"<{base_id}>"
        groups[base_id] = {
            "category": cat_upper,
            "canonical": surface_clean,
            "variants": {surface_clean: token},
        }
        session_data["token_to_original"][token] = surface_clean
        session_data["surface_to_token"][norm] = token
        session_data["surface_to_token"][norm_fold] = token
        return token
    else:
        ginfo = groups[matched_group_id]
        variant_idx = len(ginfo["variants"])
        suffix = chr(ord("a") + variant_idx - 1) if variant_idx <= 26 else f"v{variant_idx}"
        token = f"<{matched_group_id}{suffix}>"
        ginfo["variants"][surface_clean] = token
        session_data["token_to_original"][token] = surface_clean
        session_data["surface_to_token"][norm] = token
        session_data["surface_to_token"][norm_fold] = token
        return token


def unmask_jurisprudence_or_whitelist_item(session_data: Dict[str, Any], item: str) -> Optional[str]:
    clean = item.strip()
    if not clean:
        return None

    token_to_orig = session_data.get("token_to_original", {})
    surf_to_tok = session_data.get("surface_to_token", {})
    groups = session_data.get("canonical_groups", {})

    tok_candidate = clean if clean.startswith("<") else f"<{clean.strip('[]<> ')}>"
    orig_surface = token_to_orig.get(tok_candidate)
    if not orig_surface:
        norm = normalize_key(clean)
        tok_found = surf_to_tok.get(norm) or surf_to_tok.get(normalize_key_fold(clean))
        if tok_found:
            tok_candidate = tok_found
            orig_surface = token_to_orig.get(tok_found, clean)
        else:
            orig_surface = clean

    if tok_candidate in token_to_orig:
        del token_to_orig[tok_candidate]
    surf_to_tok.pop(normalize_key(orig_surface), None)
    surf_to_tok.pop(normalize_key_fold(orig_surface), None)

    base_gid = tok_candidate.strip("<>")
    if base_gid in groups:
        for var_surf, var_tok in list(groups[base_gid].get("variants", {}).items()):
            token_to_orig.pop(var_tok, None)
            surf_to_tok.pop(normalize_key(var_surf), None)
            surf_to_tok.pop(normalize_key_fold(var_surf), None)
        del groups[base_gid]

    wl = set(session_data.get("whitelist", []))
    wl.add(orig_surface)
    session_data["whitelist"] = sorted(wl)
    return orig_surface


def apply_external_entities_payload(session_data: Dict[str, Any], payload: Dict[str, Any]) -> int:
    added_count = 0
    if not isinstance(payload, dict):
        return 0

    for wl_key in ("JURISPRUDENCIA_CITADA", "JURISPRUDENCIA", "WHITELIST", "UNMASK_JURISPRUDENCIA"):
        wl_items = payload.get(wl_key)
        if isinstance(wl_items, list):
            for w_item in wl_items:
                if isinstance(w_item, str) and w_item.strip():
                    unmask_jurisprudence_or_whitelist_item(session_data, w_item)

    for vr_key in ("VISUAL_REDACTIONS", "VISUAL", "SCANNED_REDACTIONS"):
        vr_val = payload.get(vr_key)
        if isinstance(vr_val, dict):
            stored_vr = session_data.setdefault("visual_redactions_by_file", {})
            for fname_key, fpayload in vr_val.items():
                if isinstance(fpayload, dict):
                    clean_k = re.sub(r'[<>:"/\\|?*]+', "_", Path(fname_key).stem).strip().rstrip(". ").casefold()
                    stored_vr[clean_k] = fpayload
                    stored_vr[fname_key.strip().casefold()] = fpayload

    for raw_cat, val in payload.items():
        if raw_cat.upper() in (
            "JURISPRUDENCIA_CITADA",
            "JURISPRUDENCIA",
            "WHITELIST",
            "UNMASK_JURISPRUDENCIA",
            "VISUAL_REDACTIONS",
            "VISUAL",
            "SCANNED_REDACTIONS",
        ):
            continue
        cat = canonicalize_category(raw_cat)

        if isinstance(val, dict):
            for canon_name, aliases in val.items():
                if isinstance(canon_name, str) and len(canon_name.strip()) >= 2:
                    parent_cat = "PESSOA" if cat in ("PESSOA", "APELIDO") else cat
                    register_entity(session_data, canon_name, parent_cat)
                    added_count += 1
                    if isinstance(aliases, list):
                        for al in aliases:
                            if isinstance(al, str) and len(al.strip()) >= 2:
                                register_entity(session_data, al, parent_cat, canonical_hint=canon_name)
                                added_count += 1
        elif isinstance(val, list):
            for entry in val:
                if isinstance(entry, str) and len(entry.strip()) >= 2:
                    if re.match(r"^<[A-Z0-9_]+>$", entry.strip()):
                        continue
                    clean_entry = entry.strip()
                    if cat == "APELIDO":
                        register_entity(session_data, clean_entry, "APELIDO")
                        added_count += 1
                        bare_nick = re.sub(
                            r"^(?:vulgo|conhecid[oa]\s+como|apelido)\s+[\"“”']?|[\"“”']+$",
                            "",
                            clean_entry,
                            flags=re.IGNORECASE,
                        ).strip()
                        if len(bare_nick) >= 3 and bare_nick.casefold() != clean_entry.casefold():
                            register_entity(session_data, bare_nick, "APELIDO", canonical_hint=clean_entry)
                    else:
                        register_entity(session_data, clean_entry, cat)
                        added_count += 1
                elif isinstance(entry, dict):
                    cname = entry.get("name") or entry.get("canonical") or entry.get("nome")
                    aliases = entry.get("aliases") or entry.get("apelidos") or entry.get("variants") or []
                    if isinstance(cname, str) and len(cname.strip()) >= 2:
                        register_entity(session_data, cname, cat)
                        added_count += 1
                        if isinstance(aliases, list):
                            for al in aliases:
                                if isinstance(al, str) and len(al.strip()) >= 2:
                                    register_entity(session_data, al, cat, canonical_hint=cname)
                                    added_count += 1
        elif isinstance(val, str) and len(raw_cat.strip()) >= 2:
            register_entity(session_data, raw_cat, val)
            added_count += 1

    return added_count


def _clean_word_for_fuzzy(s: str) -> str:
    return strip_accents(re.sub(r"^[^\wÀ-ÿ]+|[^\wÀ-ÿ]+$", "", s)).casefold()


_FUZZY_TOKENS_CACHE: Dict[int, Tuple[str, List[Tuple[str, str, int, int]]]] = {}


def _fuzzy_doc_tokens(text: str) -> List[Tuple[str, str, int, int]]:
    """The text's words, cleaned once per text (propagation asks for them once per vault entry)."""
    key = hash(text)
    hit = _FUZZY_TOKENS_CACHE.get(key)
    if hit is not None and hit[0] is text:
        return hit[1]
    toks = [(m.group(0), _clean_word_for_fuzzy(m.group(0)), m.start(), m.end())
            for m in re.finditer(r"[\wÀ-ÿ]+(?:[./\-][\wÀ-ÿ]+)*", text)]
    toks = [t for t in toks if t[1]]
    if len(_FUZZY_TOKENS_CACHE) > 8:
        _FUZZY_TOKENS_CACHE.clear()
    _FUZZY_TOKENS_CACHE[key] = (text, toks)
    return toks


def find_fuzzy_multiword_spans(text: str, target_phrase: str) -> List[str]:
    """
    Finds all n-word spans in `text` that match `target_phrase` under accent-folding
    or 1-2 character OCR distortions (e.g. `"VIVANE CAROLINA DA ROCHA LIMA"` for
    `"Viviane Carolina da Rocha Lima"`, `"TOAO PEDRO NUNES FIGUEIREDO SILVA"` for
    `"Joao Pedro Nunes Figueiredo Silva"`, `"Praga Coronel Antdnio Bento"` for
    `"Praça Coronel Antônio Bento"`, `"Sitio Boa Vlsta..."` for `"Sítio Boa Vista..."`).
    """
    target_words = [_clean_word_for_fuzzy(w) for w in target_phrase.split() if _clean_word_for_fuzzy(w)]
    n = len(target_words)
    if n < 2:
        return []
    target_joined = " ".join(target_words)
    doc_tokens = _fuzzy_doc_tokens(text)
    if len(doc_tokens) < n:
        return []
    tl = len(target_joined)

    hits: List[str] = []
    for i in range(len(doc_tokens) - n + 1):
        win_toks = [doc_tokens[i + k][1] for k in range(n)]
        if win_toks[0][0] != target_words[0][0] and win_toks[-1][0] != target_words[-1][0]:
            continue
        win_joined = " ".join(win_toks)
        span_str = text[doc_tokens[i][2] : doc_tokens[i + n - 1][3]]
        if win_joined == target_joined:
            hits.append(span_str)
            continue
        wl_ = len(win_joined)
        if min(wl_, tl) < 0.71 * max(wl_, tl):  # ratio can't reach 0.83
            continue
        sm_ = difflib.SequenceMatcher(None, win_joined, target_joined)
        if sm_.real_quick_ratio() < 0.83 or sm_.quick_ratio() < 0.83:
            continue
        ratio = sm_.ratio()
        if ratio >= 0.83:
            close_words = sum(
                1
                for a, b in zip(win_toks, target_words)
                if a == b or difflib.SequenceMatcher(None, a, b).ratio() >= 0.72
            )
            if close_words >= max(2, n - 1):
                hits.append(span_str)
    return hits


def propagate_name_variants(text: str, session_data: Dict[str, Any]) -> None:
    """
    Cour de cassation (`juritools`) + TAB + Fuzzy OCR Coreference Engine (v6.0):
    1. `PESSOA`:
       - Multi-word fuzzy OCR & accent-folded span matching (`"LELIANE..."`, `"TOSE MARIA..."`)
       - Bank-receipt 32/35-char truncated name matching (`"ANA BEATRIZ PEREIRA DE ALMEIDA CA"`,
         `"CARLA MENDONCA TAVARES SOCI"`)
       - First + Last name, Honorific + Name, Role + Name, Dotted Initials (`J.A.S.`),
         and 1-char OCR/Whisper spelling variants on distinctive name tokens.
    2. `EMPRESA`:
       - Multi-word fuzzy OCR spans, legal-suffix-stripped, and business-prefix-stripped variants.
    3. `ENDERECO`:
       - Multi-word fuzzy OCR spans on full addresses and street cores (`"Praga Coronel Antdnio Bento"`,
         `"Sitio Boa Vlsta"` <-> `"Sítio Boa Vista"`), street-type expansions (`Av.` <-> `Avenida`, `R.` <-> `Rua`,
         `Praça` <-> `Praca` <-> `Praga`), and form-split house numbers.
    """
    vulgo_pat = re.compile(
        r"\b(?:vulgo|conhecid[oa]\s+pela\s+alcunha\s+de|de\s+alcunha)\s+[\"“”']?([A-ZÀ-Ÿ][A-Za-zÀ-ÿ]{2,20}(?:\s+d[aeo]\s+[A-ZÀ-Ÿ][A-Za-zÀ-ÿ]{2,20})?)[\"“”']?\b"
    )
    for vm in vulgo_pat.finditer(text):
        nick = vm.group(1).strip()
        if nick.casefold() not in PORTUGUESE_COMMON_WORD_STOPWORDS:
            register_entity(session_data, nick, "APELIDO")

    doc_words_6plus = set(re.findall(r"\b[A-Za-zÀ-ÿ]{6,25}\b", text))
    groups = list(session_data.get("canonical_groups", {}).items())
    portuguese_connectors = {"de", "da", "do", "das", "dos", "e"}

    for gid, ginfo in groups:
        cat = ginfo["category"]
        canonical = ginfo["canonical"]
        if cat in ("PESSOA", "PERSON"):
            # A. Multi-word fuzzy OCR & accent-folded matching on full canonical name and known variants
            for seed_phrase in [canonical] + list(ginfo.get("variants", {}).keys()):
                if len(seed_phrase.split()) >= 2:
                    for hit_span in find_fuzzy_multiword_spans(text, seed_phrase):
                        register_entity(session_data, hit_span, cat, canonical_hint=canonical)

            # B. Bank-receipt truncated name matching (e.g. "ANA BEATRIZ PEREIRA DE ALMEIDA CA", "CARLA MENDONCA TAVARES SOCI")
            raw_words = [w for w in canonical.split() if w]
            if len(raw_words) >= 3:
                for cut_idx in range(2, len(raw_words)):
                    prefix_words = raw_words[:cut_idx]
                    next_word_fold = _clean_word_for_fuzzy(raw_words[cut_idx])
                    if len(next_word_fold) >= 3:
                        pw_rx = r"\s+".join(re.escape(w) for w in prefix_words)
                        trunc_pat = re.compile(rf"\b({pw_rx}(?:\s+([A-Za-zÀ-ÿ]{{1,{len(next_word_fold)}}}))?)\b", re.IGNORECASE)
                        for m in trunc_pat.finditer(text):
                            full_m = m.group(1)
                            tail_m = m.group(2)
                            if tail_m is None or next_word_fold.startswith(_clean_word_for_fuzzy(tail_m)):
                                register_entity(session_data, full_m, cat, canonical_hint=canonical)

            tokens = [t for t in canonical.split() if t.casefold() not in portuguese_connectors]
            if len(tokens) >= 1:
                first_name = tokens[0]
                last_name = tokens[-1]
                full_rx = r"\s+".join(re.escape(t) for t in canonical.split())
                hon_full_pat = re.compile(
                    r"\b(?:Sr\.|Sra\.|Srta\.|Dr\.|Dra\.|Esp[óo]lio\s+de)\s+" + full_rx + r"\b",
                    re.IGNORECASE,
                )
                for m in hon_full_pat.finditer(text):
                    register_entity(session_data, m.group(0), cat, canonical_hint=canonical)

                if len(tokens) >= 3:
                    pattern_fl = re.compile(
                        r"\b" + re.escape(first_name) + r"\s+" + re.escape(last_name) + r"\b",
                        re.IGNORECASE,
                    )
                    for m in pattern_fl.finditer(text):
                        register_entity(session_data, m.group(0), cat, canonical_hint=canonical)

                if len(tokens) >= 2:
                    initials_letters = [re.sub(r"[^\wÀ-ÿ]", "", t)[0] for t in tokens if re.sub(r"[^\wÀ-ÿ]", "", t)]
                    if len(initials_letters) >= 2:
                        init_rx = r"\.\s*".join(re.escape(ch) for ch in initials_letters) + r"\."
                        for m in re.finditer(r"\b" + init_rx, text, flags=re.IGNORECASE):
                            register_entity(session_data, m.group(0), cat, canonical_hint=canonical)

                # C. Honorific / Role + Name & Standalone distinctive tokens (excluding common words/municipalities)
                all_distinctive_tokens = []
                for t in tokens:
                    ct = re.sub(r"[^\wÀ-ÿ]", "", t)
                    if len(ct) >= 4 and ct not in all_distinctive_tokens:
                        all_distinctive_tokens.append(ct)

                for clean_target in all_distinctive_tokens:
                    hon_pat = re.compile(
                        r"\b(?:Sr\.|Sra\.|Srta\.|Dr\.|Dra\.|Esp[óo]lio\s+de)\s+"
                        + re.escape(clean_target)
                        + r"\b",
                        re.IGNORECASE,
                    )
                    for m in hon_pat.finditer(text):
                        register_entity(session_data, m.group(0), cat, canonical_hint=canonical)

                    role_pat = re.compile(
                        r"\b(?:senhor|senhora|doutor|doutora|dona|autor|autora|r[ée]u|r[ée]|executado|executada|"
                        r"exequente|embargante|embargado|apelante|apelada|apelado|agravante|agravada|agravado|"
                        r"reclamante|reclamada|reclamado|impetrante|impetrado|inventariante|devedor|devedora|"
                        r"credor|credora|de\s+cujus|perito|perita|testemunha|solicitante|v[íi]tima|gerente|"
                        r"cliente|condutor|condutora|envolvido|envolvida|sargento|soldado|cabo|tenente|capit[ãa]o)\s+"
                        r"(?:respons[áa]vel\s*,\s*(?:senhora|senhor)\s+)?("
                        + re.escape(clean_target)
                        + r")\b",
                        re.IGNORECASE,
                    )
                    for m in role_pat.finditer(text):
                        register_entity(session_data, m.group(1), cat, canonical_hint=canonical)

                    if (
                        clean_target.casefold() not in PORTUGUESE_COMMON_WORD_STOPWORDS
                        and normalize_key_fold(clean_target) not in PORTUGUESE_COMMON_WORD_STOPWORDS
                    ):
                        bare_pat = re.compile(r"\b" + re.escape(clean_target) + r"\b", re.IGNORECASE)
                        for m in bare_pat.finditer(text):
                            register_entity(session_data, m.group(0), cat, canonical_hint=canonical)

                        if len(clean_target) >= 6:
                            ct_low = normalize_key_fold(clean_target)
                            for dw in doc_words_6plus:
                                dw_low = normalize_key_fold(dw)
                                if (
                                    dw_low != ct_low
                                    and abs(len(dw_low) - len(ct_low)) <= 1
                                    and dw_low[0] == ct_low[0]
                                    and dw_low not in PORTUGUESE_COMMON_WORD_STOPWORDS
                                ):
                                    if difflib.SequenceMatcher(None, ct_low, dw_low).ratio() >= 0.85:
                                        register_entity(session_data, dw, cat, canonical_hint=canonical)

        elif cat in ("EMPRESA", "ORG", "ORGANIZACAO"):
            for hit_span in find_fuzzy_multiword_spans(text, canonical):
                register_entity(session_data, hit_span, cat, canonical_hint=canonical)
            no_legal_suffix = re.sub(r"[.,\-–/]+", " ", canonical)
            no_legal_suffix = re.sub(
                r"\b(?:S\s+A|SA|LTDA|MEI|ME|EPP|EIRELI|SOCIEDADE\s+AN[ÔO]NIMA)\b",
                " ",
                no_legal_suffix,
                flags=re.IGNORECASE,
            )
            no_legal_suffix = re.sub(r"\s+", " ", no_legal_suffix).strip()
            short_corp = strip_corporate_suffixes(canonical)
            for cand_corp in (no_legal_suffix, short_corp):
                if len(cand_corp) >= 4 and cand_corp.casefold() != canonical.casefold():
                    for hit_span in find_fuzzy_multiword_spans(text, cand_corp):
                        register_entity(session_data, hit_span, cat, canonical_hint=canonical)
                    core_parts = [re.escape(p) for p in cand_corp.split() if p]
                    if core_parts:
                        pat_c = re.compile(r"\b" + r"\s+".join(core_parts) + r"\b", re.IGNORECASE)
                        for m in pat_c.finditer(text):
                            register_entity(session_data, m.group(0), cat, canonical_hint=canonical)

        elif cat in ("ENDERECO", "ADDRESS", "LOCAL"):
            # 1. Fuzzy multi-word span matching on the full canonical address and any variants
            for seed_addr in [canonical] + list(ginfo.get("variants", {}).keys()):
                clean_seed = re.sub(r"^(?:no\s+)?logradouro\s+", "", seed_addr.strip(), flags=re.IGNORECASE)
                for hit_span in find_fuzzy_multiword_spans(text, clean_seed):
                    register_entity(session_data, hit_span, cat, canonical_hint=canonical)

            prefix, street_core, house_nums = extract_address_core(canonical)
            if street_core and len(street_core) >= 4:
                # 2. Fuzzy multi-word matching on `prefix + street_core` and `street_core`
                if prefix:
                    for hit_span in find_fuzzy_multiword_spans(text, f"{prefix} {street_core}"):
                        register_entity(session_data, hit_span, cat, canonical_hint=canonical)
                for hit_span in find_fuzzy_multiword_spans(text, street_core):
                    register_entity(session_data, hit_span, cat, canonical_hint=canonical)

                core_parts = [re.escape(p) for p in street_core.split() if p]
                core_rx = r"\s+".join(core_parts)
                addr_var_pat = re.compile(
                    rf"\b{STREET_PREFIX_ALTERNATIVES}\s+{core_rx}(?:\s*,\s*(?:n[º°o.]?\s*)?\d+[A-Za-z]?)?\b",
                    re.IGNORECASE,
                )
                for m in addr_var_pat.finditer(text):
                    register_entity(session_data, m.group(0), cat, canonical_hint=canonical)
                if len(core_parts) >= 2 and normalize_key_fold(street_core) not in {
                    "novo horizonte", "belo horizonte", "nova resende", "minas gerais", "pocos de caldas", "conceicao da aparecida"
                }:
                    bare_core_pat = re.compile(rf"\b{core_rx}\b", re.IGNORECASE)
                    for m in bare_core_pat.finditer(text):
                        register_entity(session_data, m.group(0), cat, canonical_hint=canonical)
            for hnum in house_nums:
                if len(hnum) >= 2:
                    h_pat = re.compile(
                        rf"(?:N[ÚU]MERO|COMPLEMENTO)\s*\n\s*({re.escape(hnum)})\b|\b({re.escape(hnum)})\s*\n\s*(?:N[ÚU]MERO|KM|COMPLEMENTO|BAIRRO)",
                        re.IGNORECASE,
                    )
                    for m in h_pat.finditer(text):
                        val = m.group(1) or m.group(2)
                        if val:
                            register_entity(session_data, val, "NUMERO")

        elif cat == "MATRICULA":
            digits = re.sub(r"\D", "", canonical)
            if len(digits) >= 6 and digits != canonical:
                d_pat = re.compile(r"\b" + re.escape(digits) + r"\b")
                for m in d_pat.finditer(text):
                    register_entity(session_data, m.group(0), cat, canonical_hint=canonical)


# ============================================================================
# 5. CORE TEXT ANONYMIZATION ENGINE (LONGEST-TO-SHORTEST REPLACEMENT)
# ============================================================================


    # 4. Thermal-Receipt Right-Truncated Name Variants & OCR Initial-Comma Variants (v6.3):
    # Matches e.g. `ANA BEATRIZ PEREIRA DE ALMEIDA CA` (where `CA` is a truncated prefix of `CASTRO`)
    # or `CARLA MENDONCA TAVARES SOCI` (where `SOCI` is a truncated prefix of `SOCIEDADE`),
    # and OCR comma-in-initials (`JOAO PEDRO N. F, SILVA`).
    for gid, ginfo in list(session_data.get("canonical_groups", {}).items()):
        cat = ginfo["category"]
        canonical = ginfo["canonical"]
        if cat not in ("PESSOA", "PERSON", "EMPRESA", "ORG"):
            continue
        c_words = [w for w in canonical.split() if w]
        if len(c_words) >= 3:
            # Register contiguous prefix phrases of length >= 2 words that appear in text
            for k in range(len(c_words) - 1, 1, -1):
                prefix_str = " ".join(c_words[:k])
                next_w_fold = normalize_key_fold(c_words[k])
                if len(prefix_str) >= 10:
                    # Check if prefix_str + partial next word appears at end of a line in text
                    pat_trunc = re.compile(
                        r"\b(" + r"\s+".join(re.escape(w) for w in c_words[:k]) + r"(?:\s+[A-Za-zÀ-ÿ]{2,6})?)(?=\s*(?:\n|$))",
                        flags=re.IGNORECASE,
                    )
                    for mt in pat_trunc.finditer(text):
                        hit_s = re.sub(r"\s+", " ", mt.group(1)).strip()
                        hit_words = hit_s.split()
                        if len(hit_words) == k + 1:
                            tail_fold = normalize_key_fold(hit_words[-1])
                            if next_w_fold.startswith(tail_fold):
                                register_entity(session_data, hit_s, cat, canonical_hint=canonical)
                        elif len(hit_words) == k:
                            register_entity(session_data, hit_s, cat, canonical_hint=canonical)

        # Also check OCR initial-comma variants in text (e.g. `JOAO PEDRO N. F, SILVA`)
        if "." in canonical:
            pat_init = re.sub(r"\\\.", r"[.,]", re.escape(strip_accents(canonical)))
            pat_init = pat_init.replace(r"\ ", r"\s+")
            for mi in re.finditer(pat_init, strip_accents(text), flags=re.IGNORECASE):
                raw_hit = text[mi.start() : mi.end()].strip()
                if raw_hit:
                    register_entity(session_data, raw_hit, cat, canonical_hint=canonical)


def compute_whitelist_spans(text: str, extra_whitelist: List[str]) -> List[Tuple[int, int]]:
    spans: List[Tuple[int, int]] = []
    for pat in DEFAULT_LEGAL_WHITELIST_PATTERNS:
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            spans.append((m.start(), m.end()))
    for item in extra_whitelist:
        if item.strip():
            parts = [re.escape(p) for p in item.strip().split() if p]
            for m in re.finditer(r"\s+".join(parts), text, flags=re.IGNORECASE):
                spans.append((m.start(), m.end()))
    return spans


def is_span_whitelisted(start: int, end: int, wl_spans: List[Tuple[int, int]]) -> bool:
    for ws, we in wl_spans:
        if start < we and end > ws:
            return True
    return False



def _scan_deterministic_legal_labels_and_qualifications(
    text: str,
    session_data: Dict[str, Any],
    wl_spans: List[Tuple[int, int]],
) -> None:
    """
    Deterministic Label, Qualification-Clause, Receipt, Boleto & MRZ Extractor (v6.3):
    Extracts structured Brazilian legal entities without needing an LLM:
    1. Party & Attorney Qualification Clauses (`[NOME COMPLETO], brasileiro(a), casado(a)...`)
    2. Explicit Legal / Bank Receipt Labels (`OUTORGANTE(S):`, `FAVORECIDO`, `PAGADOR:`, `FILIAÇÃO`, `Dra. ...`)
    3. Multi-line Thermal Receipt / Boleto Beneficiary & Fantasy Names (`BENEFICIARIO:\n...`, `MENDONCA ADVOCACIA`)
    4. Structured Street Addresses (`no logradouro ...`, `com escritório na ...`, `AVENIDA ..., Nº ..., CENTRO`)
    5. CNH-e MRZ Lines (`FULANO<<BELTRANO<DE<TAL<<<`)
    """
    def _clean_person_candidate(raw: str) -> str:
        s = re.sub(r"\s+", " ", raw).strip(" .,;:-–_()[]")
        # Strip leading role/conjunction prefixes
        s = re.sub(
            r"^(?:OUTORGANTES?\s*:?\s*|OUTORGADO(?:\(S\))?\s*:?\s*|AUTOR(?:A|ES)?\s*:?\s*|"
            r"REQUERENTE(?:S)?\s*:?\s*|SOLICITANTE\s*:?\s*|PAGADOR(?:A)?\s*:?\s*|"
            r"FAVORECID[O0]+|FAVORECIOO\s*:?\s*|caus[íi]dico(?:\(s\))?\s*|pelo\(a\)\s+|pela\s+|pelo\s+|"
            r"Dr(?:\(a\)|a)?\.?\s+|Advogad[oa](?:\(s\))?\s+|e\s+)+",
            "",
            s,
            flags=re.IGNORECASE,
        ).strip(" .,;:-–_()[]")
        return s

    def _is_valid_person_name(s: str) -> bool:
        if len(s) < 6 or len(s) > 75 or any(ch.isdigit() for ch in s):
            return False
        words = [w for w in re.split(r"\s+", s) if w]
        if len(words) < 2:
            return False
        uf = normalize_key_fold(s)
        bad_kw = (
            "declaracao", "imposto", "renda", "pessoa fisica", "procuracao", "autorizacao",
            "banco do brasil", "comprovante", "atendimento", "republica", "federativa",
            "ministerio", "secretaria", "transito", "carteira", "habilitacao", "identidade",
            "assinatura", "data de", "municipio", "conceicao", "alpinopolis", "nova resende",
            "pocos de caldas", "belo horizonte", "curitiba", "finalidade", "especifica",
        )
        return not any(b in uf for b in bad_kw)

    # 0. Health professionals next to their council stamp: "Dr. Fulano de Tal\nCRM-MG 12345", "Fulano de Tal - CRM 12345",
    #    "CRM 12345 Dra. Fulana". A cited relator is never touched (whitelisted spans are skipped).
    _council = r"(?:CRM|CRO|CRP|COREN|CRF|CREFITO|CRN|CRBM|CRESS)"
    for rx_ in (
        rf"(?:Dr(?:\(a\)|a)?\.?\s+)?(?-i:([A-ZÀ-Ý][A-Za-zÀ-ÿ'.]+(?:[ \t]+(?:d[aeo]s?[ \t]+|e[ \t]+)?[A-ZÀ-Ý][A-Za-zÀ-ÿ'.]+){{1,5}}))[ \t]*(?:[-–,|]|\n)[ \t]*(?:M[ée]dic[oa][^\n]{{0,40}}\n?\s*)?{_council}(?:[A-Z]{{2}})?\b",
        rf"{_council}\s*[-–/]?\s*[A-Z]{{0,2}}\s*[:nº°o.]*\s*[\d.\-]{{3,9}}[ \t]*(?:[-–,|]|\n)?[ \t]*Dr(?:\(a\)|a)?\.?\s+(?-i:([A-ZÀ-Ý][A-Za-zÀ-ÿ'.]+(?:[ \t]+(?:d[aeo]s?[ \t]+|e[ \t]+)?[A-ZÀ-Ý][A-Za-zÀ-ÿ'.]+){{1,5}}))",
    ):
        for m in re.finditer(rx_, text, flags=re.IGNORECASE):
            if is_span_whitelisted(m.start(1), m.end(1), wl_spans):
                continue
            cand = _clean_person_candidate(m.group(1))
            if _is_valid_person_name(cand) and not re.search(r"\b(?:Hospital|Cl[íi]nica|Santa\s+Casa|Unidade|Secretaria|Conselho)\b", cand, re.IGNORECASE):
                register_entity(session_data, cand, "PESSOA")

    # 1. Qualification Clauses: `<NAME>, brasileiro(a)` or `<NAME>. brasileiro(a)`
    for m in re.finditer(
        r"(?:^|[\n:;])\s*([A-ZÀ-Ÿ][A-Za-zÀ-ÿ.,\s]{6,85}?)\s*[,.]\s*\n?\s*brasileir[oa](?:\(a\))?\b",
        text,
        flags=re.MULTILINE,
    ):
        if is_span_whitelisted(m.start(1), m.end(1), wl_spans):
            continue
        seg = m.group(1)
        # If multiple names are joined by 'e' or ':', split on the last colon/newline
        if ":" in seg:
            seg = seg.rsplit(":", 1)[-1]
        cand = _clean_person_candidate(seg)
        if _is_valid_person_name(cand):
            register_entity(session_data, cand, "PESSOA")

    # 2. Inline 'e <NAME>, brasileiro(a)' or 'causídico(s) <NAME>, brasileiro(a)' or 'Dra. <NAME>, inscrita na OAB'
    for m in re.finditer(
        r"(?:\be\s+|\bcaus[íi]dico(?:\(s\))?\s+|\bDr(?:\(a\)|a)?\.?\s+)([A-ZÀ-Ÿ][A-Za-zÀ-ÿ.,\s]{6,65}?)(?=\s*[,.]\s*\n?\s*(?:brasileir[oa]|inscrit[oa]\s+na\s+OAB|OAB))",
        text,
        flags=re.IGNORECASE,
    ):
        cand = _clean_person_candidate(m.group(1))
        if _is_valid_person_name(cand):
            register_entity(session_data, cand, "PESSOA")

    # 3. `filiação <PARENT 1> e <PARENT 2>,`
    for m in re.finditer(
        r"\bfilia[çc][ãa]o\s+([A-ZÀ-Ÿ][A-Za-zÀ-ÿ\s]{5,45}?)\s+e\s+([A-ZÀ-Ÿ][A-Za-zÀ-ÿ\s]{5,45}?)(?=\s*[,;\n]|\s+sem\s+endere|$)",
        text,
        flags=re.IGNORECASE,
    ):
        for g_idx in (1, 2):
            cand = _clean_person_candidate(m.group(g_idx))
            if _is_valid_person_name(cand):
                register_entity(session_data, cand, "PESSOA")

    # 4. Receipt / Deposit / Boleto Payer & Payee (`FAVORECIDO` / `FAVORECIOO` with or without colon, `PAGADOR:` inline or next line)
    for m in re.finditer(
        r"\b(?:FAVORECI[DO0]{2}|PAGADOR(?:A)?|SOLICITANTE|OUTORGANTES?)\s*:?\s*(?:\n\s*)?([A-ZÀ-Ÿ][A-ZÀ-Ÿa-zà-ÿ. \t]{5,60}?)(?=\n|CPF|CNPJ|[,.]\s*brasileir|$)",
        text,
    ):
        cand = _clean_person_candidate(m.group(1))
        if _is_valid_person_name(cand):
            register_entity(session_data, cand, "PESSOA")

    # 5. CNH-e MRZ Line 3 (`FULANO<<BELTRANO<DE<TAL<<<`)
    for m in re.finditer(r"\b([A-Z]{2,}(?:<+[A-Z]{2,})+)<{2,}", text):
        mrz_raw = m.group(1)
        if not mrz_raw.startswith("BRA"):
            mrz_name = re.sub(r"<+", " ", mrz_raw).strip()
            if _is_valid_person_name(mrz_name):
                register_entity(session_data, mrz_name, "PESSOA")

    # 6. Receipt / Boleto Beneficiary & Fantasy Name (`BENEFICIARIO:`, `NOME FANTASIA:`, `BENEFICIARIO FINAL:`, `ADVOCACIA`)
    for m in re.finditer(
        r"\b(?:BENEFICI[ÁA]RIO(?:\s+FINAL)?|NOME\s+FANTASIA|CEDENTE)\s*:\s*(?:\n\s*)?([A-ZÀ-Ÿ][A-ZÀ-Ÿ0-9 \t.&\-]{4,65}?)(?=\n|CNPJ|CPF|$)",
        text,
    ):
        comp = re.sub(r"\s+", " ", m.group(1)).strip(" .,;:-–")
        uf = normalize_key_fold(comp)
        if len(comp) >= 5 and not any(k in uf for k in ("avenida", "rua ", "cobranca", "vencimento", "valor")):
            register_entity(session_data, comp, "EMPRESA")

    for m in re.finditer(
        r"\b([A-ZÀ-Ÿ][A-ZÀ-Ÿ \t.&\-]{3,55}?\b(?:ADVOCACIA|SOCIEDADE(?:\s+INDIVIDUAL(?:\s+DE\s+ADVOCACIA)?)?|SOCIEDADE\s+DE\s+ADVOGADOS))\b",
        text,
    ):
        comp = re.sub(r"\s+", " ", m.group(1)).strip(" .,;:-–")
        if len(comp) >= 6:
            register_entity(session_data, comp, "EMPRESA")

    # 7. Structured Street Addresses (`no logradouro ...`, `com escritório na ...`, and Boleto/Receipt `AVENIDA/RUA ..., Nº ...`)
    for m in re.finditer(
        r"(?:no\s+logradouro|com\s+escrit[óoéea]rio\s+na|residente\s+e\s+domiciliad[oa]\s+na)\s+([^\n;]{5,70}?)(?=,\s*(?:no\s+Munic|na\s+cidade|CEP)|;|\n|$)",
        text,
        flags=re.IGNORECASE,
    ):
        addr = re.sub(r"\s+", " ", m.group(1)).strip(" .,;")
        if len(addr) >= 5:
            register_entity(session_data, addr, "ENDERECO")

    for m in re.finditer(
        r"\b((?:AVENIDA|AV\.|RUA|R\.|PRA[ÇC]A|ALAMEDA|TRAVESSA|RODOVIA)\s+[A-ZÀ-Ÿ][A-Za-zÀ-ÿ0-9\s.\-]{3,45}?,\s*(?:N[º°o.*®]?\s*)?\d{1,5}[A-Za-z]?(?:\s*,\s*[A-ZÀ-Ÿ][A-Za-zÀ-ÿ\s\-]{2,25}?)?)(?=\s*,\s*[A-ZÀ-Ÿ][A-Za-zÀ-ÿ\s]{2,30}?(?:\s*/\s*[A-Z]{2}|\s*[-–]\s*[A-Z]{2})|\s*,\s*CEP|\n|$)",
        text,
    ):
        addr = re.sub(r"\s+", " ", m.group(1)).strip(" .,;")
        if len(addr) >= 8:
            register_entity(session_data, addr, "ENDERECO")


    # 8. Boleto table `Nosso Número` on the next row (even when preceded by `N | 10/04/2026` in left columns)
    for m in re.finditer(r"\bNosso(?:\s+N[úu]mero)?[^\n]*\n[^\n]*?\b(\d{7,12})\b", text, flags=re.IGNORECASE):
        register_entity(session_data, m.group(1), "ID_TRANSACAO")

    # 9. Uppercase Person Name line immediately preceding a standalone `CPF: XXX.XXX.XXX-XX` line on receipts
    for m in re.finditer(r"(?:^|\n)\s*([A-ZÀ-Ÿ]{3,}(?:\s+[A-ZÀ-Ÿ]{2,}){2,7})\s*\n\s*CPF\s*:\s*\d{3}", text):
        cand = _clean_person_candidate(m.group(1))
        if _is_valid_person_name(cand):
            register_entity(session_data, cand, "PESSOA")


def scan_deterministic_regexes(text: str, session_data: Dict[str, Any]) -> None:
    wl_spans = compute_whitelist_spans(text, session_data.get("whitelist", []))
    rules = build_brazilian_legal_rules()
    stats = session_data.setdefault("stats", {"files_processed": [], "rule_hits": {}, "ignored_false_positives": []})

    for rule in rules:
        for m in rule.regex.finditer(text):
            target_group = rule.group
            if target_group > 0 and m.group(target_group) is None:
                for g_idx in range(1, (m.lastindex or 0) + 1):
                    if m.group(g_idx) is not None:
                        target_group = g_idx
                        break
            elif target_group == 0 and m.lastindex:
                for g_idx in range(1, m.lastindex + 1):
                    if m.group(g_idx) is not None:
                        target_group = g_idx
                        break

            val = m.group(target_group)
            if not val:
                continue
            s, e = m.start(target_group), m.end(target_group)
            if is_span_whitelisted(s, e, wl_spans):
                continue
            if rule.check_jurisprudence and is_jurisprudence_context(text, m.start(), m.end()):
                wl_set = set(session_data.get("whitelist", []))
                wl_set.add(val.strip())
                session_data["whitelist"] = sorted(wl_set)
                wl_spans.append((s, e))
                continue
            if rule.validator is not None and not rule.validator(val):
                if len(stats["ignored_false_positives"]) < 200:
                    stats["ignored_false_positives"].append({"rule": rule.rule_id, "value_length": len(val)})
                continue
            register_entity(session_data, val, rule.category)
            stats["rule_hits"][rule.rule_id] = stats["rule_hits"].get(rule.rule_id, 0) + 1

    _scan_deterministic_legal_labels_and_qualifications(text, session_data, wl_spans)


def build_longest_first_replacement_pairs(session_data: Dict[str, Any]) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    seen_surfaces: Set[str] = set()
    for token, orig in session_data.get("token_to_original", {}).items():
        if orig and orig.strip():
            clean_o = orig.strip()
            if (
                " " not in clean_o
                and re.match(r"^[A-Za-zÀ-ÿ]+$", clean_o)
                and (
                    clean_o.casefold() in PORTUGUESE_COMMON_WORD_STOPWORDS
                    or normalize_key_fold(clean_o) in PORTUGUESE_COMMON_WORD_STOPWORDS
                )
            ):
                continue
            for candidate_surf in (orig, strip_accents(orig)):
                cs_key = candidate_surf.strip().casefold()
                if cs_key and cs_key not in seen_surfaces:
                    seen_surfaces.add(cs_key)
                    pairs.append((candidate_surf, token))
    pairs.sort(key=lambda item: (-len(item[0]), item[0]))
    return pairs


def build_entity_boundary_pattern(orig: str) -> str:
    clean = orig.strip()
    if not clean:
        return re.escape(orig)
    parts = [re.escape(p) for p in clean.split() if p]
    body = r"\s+".join(parts)
    prefix = r"\b" if re.match(r"^[\wÀ-ÿ]", clean) else ""
    # Allow CPF/RG/numbers glued to a trailing 'e' or comma in OCR (e.g. '123.456.789-09e')
    if re.search(r"\d$", clean) and any(ch in clean for ch in ".-/"):
        suffix = r"(?!\d)"
    else:
        suffix = r"\b" if re.search(r"[\wÀ-ÿ]$", clean) else ""
    if re.match(r"^\d{1,4}$", clean):
        return rf"(?<![/.,:\-\d])\b{body}\b(?![/.,:\-\d]|\s*(?:CIA|BPM|RPM|PEL|GP|GRAU|CLASSE|SARGENTO|HORAS|MIN|ANOS))"
    return f"{prefix}{body}{suffix}"


def apply_longest_first_replacements(text: str, session_data: Dict[str, Any]) -> str:
    pairs = build_longest_first_replacement_pairs(session_data)
    if not pairs:
        return text

    wl_spans = compute_whitelist_spans(text, session_data.get("whitelist", []))
    placeholder_pat = r"<[A-Z0-9_]+_\d+[a-z0-9]*>"
    escaped_surfaces = [build_entity_boundary_pattern(orig) for orig, _ in pairs]

    combined_pattern = re.compile(
        f"({placeholder_pat})|(" + "|".join(escaped_surfaces) + ")",
        flags=re.IGNORECASE,
    )

    norm_map = session_data.get("surface_to_token", {})

    def _replacer(match: re.Match) -> str:
        if match.group(1) is not None:
            return match.group(1)
        matched_str = match.group(0)
        # Only skip whitelist spans for single-token or non-address matches; if a full registered
        # rural address ("Sitio Boa Vista, no Município de Conceição da Aparecida-MG") includes the
        # municipality suffix, allow the registered address replacement to proceed.
        token = norm_map.get(normalize_key(matched_str)) or norm_map.get(normalize_key_fold(matched_str))
        if is_span_whitelisted(match.start(), match.end(), wl_spans):
            if not (token and token.startswith("<ENDERECO_") and len(matched_str) >= 18):
                return matched_str
        return token if token else matched_str

    return combined_pattern.sub(_replacer, text)


# ============================================================================
# 6. FORMATTING-SAFE WORD (.DOCX) XML SURGERY & EMBEDDED IMAGE ANONYMIZATION
# ============================================================================

DOCX_W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
DOCX_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
DOCX_XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
DOCX_W_P = f"{{{DOCX_W_NS}}}p"
DOCX_TEXT_TAGS = {
    f"{{{DOCX_W_NS}}}t",
    f"{{{DOCX_W_NS}}}delText",
    f"{{{DOCX_W_NS}}}instrText",
}


def _docx_xml_parser() -> Any:
    from lxml import etree

    return etree.XMLParser(resolve_entities=False, no_network=True, remove_blank_text=False)


def _docx_paragraph_text_nodes(paragraph_elm: Any) -> List[Any]:
    """
    Collects text nodes (`w:t`, `w:delText`, `w:instrText`) directly belonging to
    `paragraph_elm` without duplicating nested textbox paragraphs (`w:p` inside `w:txbxContent`).
    """
    found: List[Any] = []

    def _walk(element: Any) -> None:
        for child in element:
            if child.tag == DOCX_W_P:
                continue
            if child.tag in DOCX_TEXT_TAGS:
                found.append(child)
            else:
                _walk(child)

    _walk(paragraph_elm)
    return found


def _replace_across_xml_text_nodes(text_nodes: List[Any], transform_fn: Callable[[str], str]) -> int:
    if not text_nodes:
        return 0

    run_texts = [n.text or "" for n in text_nodes]
    full_text = "".join(run_texts)
    if not full_text.strip():
        return 0

    new_text = transform_fn(full_text)
    if new_text == full_text:
        return 0

    run_spans: List[Tuple[int, int]] = []
    cursor = 0
    for rt in run_texts:
        run_spans.append((cursor, cursor + len(rt)))
        cursor += len(rt)

    matcher = difflib.SequenceMatcher(a=full_text, b=new_text, autojunk=False)
    opcodes = matcher.get_opcodes()

    new_run_buffers: List[List[str]] = [[] for _ in text_nodes]

    def _run_index_for_char(pos: int) -> int:
        for idx, (rs, re_) in enumerate(run_spans):
            if rs <= pos < re_:
                return idx
        return len(text_nodes) - 1

    for tag, i1, i2, j1, j2 in opcodes:
        if tag == "equal":
            for pos_offset in range(i2 - i1):
                orig_pos = i1 + pos_offset
                r_idx = _run_index_for_char(orig_pos)
                new_run_buffers[r_idx].append(new_text[j1 + pos_offset])
        elif tag in ("replace", "insert"):
            target_r_idx = _run_index_for_char(i1 if i1 < len(full_text) else max(0, len(full_text) - 1))
            new_run_buffers[target_r_idx].append(new_text[j1:j2])
        elif tag == "delete":
            pass

    for idx, node in enumerate(text_nodes):
        updated_str = "".join(new_run_buffers[idx])
        node.text = updated_str
        if updated_str[:1].isspace() or updated_str[-1:].isspace():
            node.set(DOCX_XML_SPACE, "preserve")

    return 1


def replace_in_paragraph_runs(paragraph: Any, transform_fn: Callable[[str], str]) -> int:
    p_elm = paragraph._p
    text_nodes = _docx_paragraph_text_nodes(p_elm)
    if not text_nodes:
        return 0
    return _replace_across_xml_text_nodes(text_nodes, transform_fn)


def iter_all_docx_paragraphs(doc: Any):
    for p in doc.paragraphs:
        yield p
    for t in doc.tables:
        yield from _iter_table_paragraphs(t)
    for section in doc.sections:
        for hf in (
            section.header,
            section.first_page_header,
            section.even_page_header,
            section.footer,
            section.first_page_footer,
            section.even_page_footer,
        ):
            if hf is not None:
                for p in hf.paragraphs:
                    yield p
                for t in hf.tables:
                    yield from _iter_table_paragraphs(t)


def _iter_table_paragraphs(table: Any):
    seen_cells = set()
    for row in table.rows:
        for cell in row.cells:
            if id(cell._tc) in seen_cells:
                continue
            seen_cells.add(id(cell._tc))
            for p in cell.paragraphs:
                yield p
            for nested in cell.tables:
                yield from _iter_table_paragraphs(nested)


def _docx_relationship_source_part(rels_name: str) -> str:
    rels_dir, rels_file = posixpath.split(rels_name)
    source_dir = posixpath.dirname(rels_dir)
    source_file = rels_file[:-5] if rels_file.endswith(".rels") else rels_file
    return posixpath.normpath(posixpath.join(source_dir, source_file))


def extract_docx_embedded_images(docx_path: Path, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Discovers all embedded images inside a `.docx` package across `word/document.xml`,
    headers, footers, footnotes, and comments via `*/_rels/*.rels`.
    """
    from lxml import etree

    images: List[Dict[str, Any]] = []
    if not zipfile.is_zipfile(docx_path):
        return images

    sdir = get_session_dir(session_id) if session_id else None
    img_extract_dir = (sdir / "docx_images" / safe_file_stem(docx_path)) if sdir else None
    if img_extract_dir:
        img_extract_dir.mkdir(parents=True, exist_ok=True)

    seen_media: Set[str] = set()
    with zipfile.ZipFile(docx_path, "r") as z:
        namelist = set(z.namelist())
        for rels_name in sorted(namelist):
            if not (rels_name.endswith(".rels") and "/_rels/" in rels_name):
                continue
            try:
                rel_root = etree.fromstring(z.read(rels_name), parser=_docx_xml_parser())
            except Exception:
                continue
            source_part = _docx_relationship_source_part(rels_name)
            source_label = Path(source_part).stem

            for rel in rel_root.findall(f"{{{DOCX_REL_NS}}}Relationship"):
                if not (rel.get("Type") or "").endswith("/image"):
                    continue
                if rel.get("TargetMode") == "External":
                    continue
                rid = rel.get("Id") or "sem_id"
                target = unquote((rel.get("Target") or "").split("?", 1)[0])
                if not target:
                    continue
                if target.startswith("/"):
                    media_path = posixpath.normpath(target.lstrip("/"))
                else:
                    media_path = posixpath.normpath(posixpath.join(posixpath.dirname(source_part), target))
                if media_path not in namelist or media_path in seen_media:
                    continue
                seen_media.add(media_path)

                raw_bytes = z.read(media_path)
                suffix = Path(media_path).suffix or ".png"
                file_name = (
                    f"img_{rid}{suffix}"
                    if source_part == "word/document.xml"
                    else f"img_{source_label}_{rid}{suffix}"
                )
                disk_path: Optional[Path] = None
                if img_extract_dir:
                    disk_path = img_extract_dir / file_name
                    disk_path.write_bytes(raw_bytes)
                images.append(
                    {
                        "rid": rid,
                        "source_part": source_part,
                        "media_path": media_path,
                        "file": file_name,
                        "path": str(disk_path) if disk_path else None,
                        "bytes": raw_bytes,
                    }
                )
    return images


def generate_docx_placeholder_image_bytes(
    image_bytes: bytes,
    media_path: str,
    label_override: Optional[str] = None,
) -> bytes:
    """
    Generates an opaque neutral placeholder image (`IMAGEM REMOVIDA`) matching the
    original dimensions and container format (PNG, JPEG, WEBP, BMP, TIFF, SVG) so no
    pixels of the original embedded photo/screenshot remain in the anonymized `.docx`.
    """
    extension = Path(media_path).suffix.lower()
    if extension == ".svg":
        from lxml import etree

        try:
            root = etree.fromstring(image_bytes, parser=_docx_xml_parser())
            width = root.get("width", "800")
            height = root.get("height", "450")
            view_box = root.get("viewBox", "0 0 800 450")
        except Exception:
            width, height, view_box = "800", "450", "0 0 800 450"
        svg_label = label_override or "IMAGEM REMOVIDA"
        svg = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<svg xmlns="http://www.w3.org/2000/svg" '
            f'width="{width}" height="{height}" viewBox="{view_box}">'
            '<rect width="100%" height="100%" fill="#f1f3f5"/>'
            '<rect x="2%" y="2%" width="96%" height="96%" '
            'fill="none" stroke="#9aa1a9" stroke-width="4"/>'
            '<line x1="42%" y1="37%" x2="58%" y2="63%" '
            'stroke="#8b929a" stroke-width="5" stroke-linecap="round"/>'
            '<line x1="58%" y1="37%" x2="42%" y2="63%" '
            'stroke="#8b929a" stroke-width="5" stroke-linecap="round"/>'
            '<text x="50%" y="78%" text-anchor="middle" '
            'font-family="Arial, sans-serif" font-size="24" '
            f'fill="#555d66">{svg_label}</text></svg>'
        )
        return svg.encode("utf-8")

    from PIL import Image, ImageDraw, ImageFont

    with Image.open(io.BytesIO(image_bytes)) as source:
        image_format = source.format or ("PNG" if extension == ".png" else "JPEG")
        width, height = source.size
        width = max(1, width)
        height = max(1, height)

        image = Image.new("RGB", (width, height), (241, 243, 245))
        draw = ImageDraw.Draw(image)
        border = max(1, min(width, height) // 80)
        inset = max(border + 1, min(width, height) // 30)
        draw.rectangle(
            (inset, inset, max(inset, width - inset - 1), max(inset, height - inset - 1)),
            outline=(145, 152, 160),
            width=border,
        )

        font = None
        font_size = max(8, min(36, min(width, height) // 7))
        for font_cand in (
            "arial.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ):
            try:
                font = ImageFont.truetype(font_cand, font_size)
                break
            except Exception:
                continue
        if font is None:
            font = ImageFont.load_default()

        base_lbl = label_override or "IMAGEM REMOVIDA"
        label = base_lbl if (width >= 130 and height >= 45) else "REMOVIDA"
        if width < 45 or height < 25:
            label = "X"
        bbox = draw.textbbox((0, 0), label, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        x = max(0, (width - text_width) // 2)
        y = max(0, (height - text_height) // 2)
        draw.text((x, y), label, fill=(75, 83, 92), font=font)

        output = io.BytesIO()
        save_kwargs: Dict[str, Any] = {}
        if image_format.upper() in {"JPEG", "JPG"}:
            save_kwargs["quality"] = 90
        elif image_format.upper() == "PNG":
            save_kwargs["optimize"] = True
        try:
            image.save(output, format=image_format, **save_kwargs)
        except Exception:
            image.save(output, format="PNG")
        return output.getvalue()


def _transform_docx_xml_part(
    xml_name: str,
    raw: bytes,
    transform_fn: Callable[[str], str],
    is_restore: bool = False,
) -> bytes:
    if xml_name.endswith(".rels") or xml_name == "[Content_Types].xml":
        return raw
    from lxml import etree

    try:
        root = etree.fromstring(raw, parser=_docx_xml_parser())
    except Exception:
        return raw
    changed = False

    if xml_name.startswith("word/"):
        for paragraph in root.iter(DOCX_W_P):
            nodes = _docx_paragraph_text_nodes(paragraph)
            if nodes and _replace_across_xml_text_nodes(nodes, transform_fn):
                changed = True

        # Also anonymize/restore XML attributes (image alt-text descr/title, hyperlink tooltips, etc.)
        for element in root.iter():
            for attr, value in list(element.attrib.items()):
                if not value or len(value) < 3 or attr.endswith(("}id", "}val", "}type", "}uri", "Id", "Type", "Target")):
                    continue
                replaced = transform_fn(value)
                if replaced != value:
                    element.set(attr, replaced)
                    changed = True

    elif xml_name.startswith(("docProps/", "customXml/")):
        for element in root.iter():
            if element.text and len(element.text.strip()) >= 3:
                replaced = transform_fn(element.text)
                if replaced != element.text:
                    element.text = replaced
                    changed = True
            if is_restore and element.tail and len(element.tail.strip()) >= 3:
                replaced_tail = transform_fn(element.tail)
                if replaced_tail != element.tail:
                    element.tail = replaced_tail
                    changed = True
            for attr, value in list(element.attrib.items()):
                if not value or len(value) < 3:
                    continue
                replaced = transform_fn(value)
                if replaced != value:
                    element.set(attr, replaced)
                    changed = True

    if not changed:
        return raw
    return etree.tostring(root, encoding="UTF-8", xml_declaration=True, standalone=True)


def rewrite_docx_package_atomic(
    source_docx: Path,
    dest_docx: Path,
    transform_fn: Callable[[str], str],
    image_updates: Optional[Dict[str, bytes]] = None,
    is_restore: bool = False,
) -> None:
    """
    Atomically rewrites a `.docx` ZIP archive across all `word/*.xml`, `docProps/*.xml`,
    and `customXml/*.xml` parts (plus `image_updates` for `word/media/*`), then validates
    ZIP integrity via `testzip()` before replacing `dest_docx`.
    """
    image_updates = image_updates or {}
    dest_docx.parent.mkdir(parents=True, exist_ok=True)
    temp_path = dest_docx.with_name(dest_docx.name + ".tmp")

    try:
        with zipfile.ZipFile(source_docx, "r") as zin:
            names = set(zin.namelist())
            if "[Content_Types].xml" not in names or "word/document.xml" not in names:
                raise ValueError(f"Invalid .docx structure: {source_docx}")

            with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_DEFLATED) as zout:
                for info in zin.infolist():
                    data = zin.read(info.filename)
                    if info.filename in image_updates:
                        data = image_updates[info.filename]
                    elif info.filename.endswith(".xml"):
                        data = _transform_docx_xml_part(info.filename, data, transform_fn, is_restore=is_restore)
                    zout.writestr(info, data)

        with zipfile.ZipFile(temp_path, "r") as check:
            bad_member = check.testzip()
            if bad_member:
                raise ValueError(f"Generated .docx has corrupted ZIP member: {bad_member}")
            if "word/document.xml" not in check.namelist():
                raise ValueError("Generated .docx is missing word/document.xml.")
        temp_path.replace(dest_docx)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def process_docx_extra_xml_parts(docx_path: Path, transform_fn: Callable[[str], str]) -> int:
    rewrite_docx_package_atomic(docx_path, docx_path, transform_fn, image_updates=None, is_restore=False)
    return 1


def anonymize_docx_embedded_images(
    docx_path: Path,
    session_id: str,
    session_data: Dict[str, Any],
    image_mode: str = "placeholder",
) -> Tuple[Dict[str, bytes], Dict[str, int]]:
    """
    Processes embedded images in a `.docx` file and backs up original bytes in the
    session vault (`docx_image_backups[doc_key][media_path]`) for 100% lossless restoration:
    - `image_mode == "placeholder"` (default, from `anonimize2.py`): replaces every embedded
      image with an opaque neutral `IMAGEM REMOVIDA (N)` placeholder of identical dimensions
      and format so zero pixels of WhatsApp prints, bank receipts, or ID photos leak.
    - `image_mode == "redact"`: runs `visual_redactor` OCR + black-box redaction on the image,
      falling back to the opaque placeholder if visual redaction fails.
    - `image_mode == "keep"`: leaves embedded images untouched.
    """
    if image_mode == "keep":
        return {}, {"images_extracted": 0, "images_replaced": 0}

    images = extract_docx_embedded_images(docx_path, session_id=session_id)
    image_updates: Dict[str, bytes] = {}
    doc_key = safe_file_stem(docx_path)
    backups = session_data.setdefault("docx_image_backups", {}).setdefault(doc_key, {})

    for idx, info in enumerate(images, start=1):
        media_path = info["media_path"]
        orig_bytes: bytes = info["bytes"]
        if media_path not in backups:
            backups[media_path] = base64.b64encode(orig_bytes).decode("ascii")

        replaced_bytes: Optional[bytes] = None
        if image_mode == "redact" and info.get("path"):
            try:
                script_dir = Path(__file__).resolve().parent
                if str(script_dir) not in sys.path:
                    sys.path.insert(0, str(script_dir))
                import visual_redactor

                img_disk_path = Path(info["path"])
                red_out = img_disk_path.with_name(f"redacted_{img_disk_path.name}")
                res = visual_redactor.apply_visual_redactions(
                    file_path=img_disk_path,
                    session_id=session_id,
                    redactions_payload={},
                    output_path=red_out,
                    delivery_dir=img_disk_path.parent,
                )
                if res.get("redacted_visual_file") and Path(res["redacted_visual_file"]).exists():
                    replaced_bytes = Path(res["redacted_visual_file"]).read_bytes()
            except Exception:
                replaced_bytes = None

        if replaced_bytes is None:
            try:
                replaced_bytes = generate_docx_placeholder_image_bytes(
                    orig_bytes,
                    media_path,
                    label_override=f"IMAGEM REMOVIDA ({idx})",
                )
            except Exception:
                continue

        image_updates[media_path] = replaced_bytes

    return image_updates, {
        "images_extracted": len(images),
        "images_replaced": len(image_updates),
    }


def get_docx_restored_images(docx_path: Path, session_data: Dict[str, Any]) -> Dict[str, bytes]:
    """
    Retrieves original embedded image bytes from the session vault for `restore`.
    """
    all_backups: Dict[str, Dict[str, str]] = session_data.get("docx_image_backups", {})
    if not all_backups:
        return {}
    stem_clean = re.sub(r"\.(?:anonymized|restored)$", "", safe_file_stem(docx_path), flags=re.IGNORECASE)
    doc_backups = all_backups.get(stem_clean) or {}
    if not doc_backups and len(all_backups) == 1:
        doc_backups = next(iter(all_backups.values()))

    image_updates: Dict[str, bytes] = {}
    for media_path, b64_str in doc_backups.items():
        try:
            image_updates[media_path] = base64.b64decode(b64_str, validate=True)
        except Exception:
            continue
    return image_updates


def embed_docx_session_metadata(docx_path: Path, session_id: str, scrub_author: bool = True) -> None:
    from docx import Document

    doc = Document(str(docx_path))
    props = doc.core_properties
    props.comments = f"pt-legal-anonymizer:session_id={session_id}"
    if scrub_author:
        props.author = "Anonimizado Localmente (LGPD)"
        props.last_modified_by = "Anonimizado Localmente (LGPD)"
    doc.save(str(docx_path))


def extract_docx_session_id(docx_path: Path) -> Optional[str]:
    from docx import Document

    doc = Document(str(docx_path))
    comments = doc.core_properties.comments or ""
    m = re.search(r"pt-legal-anonymizer:session_id=([A-Za-z0-9_\-.]+)", comments)
    return m.group(1) if m else None


def extract_text_from_file(file_path: Path, session_id: Optional[str] = None) -> str:
    ext = file_path.suffix.lower()
    if ext in (".txt", ".md", ".csv", ".json", ".html", ".xml"):
        raw_bytes = file_path.read_bytes()
        for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
            try:
                return raw_bytes.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw_bytes.decode("utf-8", errors="replace")

    if ext in IMAGE_EXTENSIONS:
        ocr_txt = _try_ocr_pdf_page(file_path, 1, session_id=session_id) or ""
        return f"--- [IMAGEM 1 (OCR ESCANEADO)] ---\n{ocr_txt}"

    if ext == ".docx":
        from lxml import etree

        lines: List[str] = []
        with zipfile.ZipFile(file_path, "r") as zf:
            namelist = sorted(zf.namelist())
            for part in namelist:
                if part.startswith("word/") and part.endswith(".xml") and not part.endswith(".rels"):
                    try:
                        root = etree.fromstring(zf.read(part), parser=_docx_xml_parser())
                        for p_elm in root.iter(DOCX_W_P):
                            tnodes = _docx_paragraph_text_nodes(p_elm)
                            txt = "".join(n.text or "" for n in tnodes)
                            if txt.strip():
                                lines.append(txt)
                    except Exception:
                        pass

        # Also OCR any embedded images inside the .docx so PII inside screenshots/receipts is discovered!
        embedded_imgs = extract_docx_embedded_images(file_path, session_id=session_id)
        for idx, info in enumerate(embedded_imgs, start=1):
            img_p = info.get("path")
            if img_p and Path(img_p).exists():
                ocr_txt = _try_ocr_pdf_page(Path(img_p), 1, session_id=session_id) or ""
                if ocr_txt.strip():
                    lines.append(f"--- [IMAGEM INCORPORADA DOCX {idx}: {info['media_path']} (OCR)] ---\n{ocr_txt}")

        return "\n".join(lines)

    if ext == ".pdf":
        page_texts: List[str] = []
        fitz = _import_fitz()
        hybrid_page_flags: List[bool] = []
        if fitz is not None:
            doc = fitz.open(str(file_path))
            for page in doc:
                page_texts.append(page.get_text("text") or "")
                hybrid_page_flags.append(_fitz_page_has_large_embedded_images(page))
            doc.close()
        else:
            try:
                import pdfplumber

                with pdfplumber.open(str(file_path)) as pdf:
                    for page in pdf.pages:
                        page_texts.append(page.extract_text() or "")
                        hybrid_page_flags.append(len(getattr(page, "images", []) or []) >= 2)
            except ImportError:
                from pypdf import PdfReader

                reader = PdfReader(str(file_path))
                for page in reader.pages:
                    page_texts.append(page.extract_text() or "")
                    hybrid_page_flags.append(False)

        formatted_pages: List[str] = []
        for i, ptxt in enumerate(page_texts):
            non_cam = re.sub(r"digitalizadocomcamscanner|\s+", "", ptxt, flags=re.IGNORECASE)
            is_hybrid = hybrid_page_flags[i] if i < len(hybrid_page_flags) else False
            if len(non_cam) < 40 or is_hybrid:
                ocr_txt = _try_ocr_pdf_page(file_path, i + 1, session_id=session_id)
                if ocr_txt and len(re.sub(r"\s+", "", ocr_txt)) >= 15:
                    if len(non_cam) >= 40 and is_hybrid:
                        formatted_pages.append(f"--- [PÁGINA {i + 1} (HÍBRIDA DIGITAL + OCR)] ---\n{ptxt}\n{ocr_txt}")
                    else:
                        formatted_pages.append(f"--- [PÁGINA {i + 1} (OCR ESCANEADO)] ---\n{ocr_txt}")
                    continue
            formatted_pages.append(f"--- [PÁGINA {i + 1}] ---\n{ptxt}")
        return "\n\n".join(formatted_pages)

    raise ValueError(f"Unsupported file format: {ext}")



_RUNTIME_DEPS_CHECKED = False


def ensure_runtime_requirements(auto_install: bool = True) -> Dict[str, Any]:
    """
    Step-0 Automatic Dependency Verifier & Installer (v6.3):
    Checks for required Python packages (`pymupdf`/`fitz`, `pillow`, `numpy`, `opencv-python`
    with `CascadeClassifier`, and `python-docx`) and automatically installs/repairs any
    missing package via `pip` before running anonymization.
    """
    global _RUNTIME_DEPS_CHECKED
    status: Dict[str, Any] = {"installed_now": [], "missing": [], "ok": True}
    if _RUNTIME_DEPS_CHECKED:
        return status
    _RUNTIME_DEPS_CHECKED = True

    import importlib
    import subprocess

    pkg_checks = [
        ("fitz", "pymupdf"),
        ("PIL", "pillow"),
        ("numpy", "numpy"),
        ("cv2", "opencv-python"),
        ("docx", "python-docx"),
    ]
    for mod_name, pip_pkg in pkg_checks:
        need_install = False
        try:
            mod = importlib.import_module(mod_name)
            if mod_name == "cv2" and not hasattr(mod, "CascadeClassifier"):
                need_install = True
        except ImportError:
            need_install = True

        if need_install and auto_install:
            try:
                cmd = [sys.executable, "-m", "pip", "install", "--quiet", "--upgrade"]
                if mod_name == "cv2":
                    cmd.append("--force-reinstall")
                cmd.append(pip_pkg)
                subprocess.run(cmd, timeout=90, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                importlib.invalidate_caches()
                if mod_name in sys.modules:
                    importlib.reload(sys.modules[mod_name])
                else:
                    importlib.import_module(mod_name)
                status["installed_now"].append(pip_pkg)
            except Exception:
                status["missing"].append(pip_pkg)
                status["ok"] = False

    return status



def _fitz_page_has_large_embedded_images(page: Any) -> bool:
    """
    Returns True if a PyMuPDF `page` contains at least one embedded raster image
    covering >= 5.5% of the page area (`rw_1000 * rh_1000 >= 55000`) with pixel size >= 180x140
    (such as hybrid SENATRAN e-CNH cards and QR codes on `CNH-e Dudu.pdf`, while ignoring tiny header logos).
    """
    try:
        imgs = page.get_images(full=True)
        if not imgs:
            return False
        pw = max(1.0, float(page.rect.width))
        ph = max(1.0, float(page.rect.height))
        for im_info in imgs:
            xref = im_info[0]
            im_w, im_h = int(im_info[2]), int(im_info[3])
            if im_w < 180 or im_h < 140:
                continue
            for r in page.get_image_rects(xref):
                rw_1000 = (float(r.width) / pw) * 1000.0
                rh_1000 = (float(r.height) / ph) * 1000.0
                if rw_1000 * rh_1000 >= 55000.0:
                    return True
    except Exception:
        pass
    return False


def _import_fitz() -> Any:
    try:
        import pymupdf as fitz
        return fitz
    except ImportError:
        try:
            import fitz
            return fitz
        except ImportError:
            return None


def _try_ocr_pdf_page(file_path: Path, page_number: int, session_id: Optional[str] = None) -> Optional[str]:
    try:
        script_dir = Path(__file__).resolve().parent
        if str(script_dir) not in sys.path:
            sys.path.insert(0, str(script_dir))
        import visual_redactor

        return visual_redactor.ocr_single_pdf_page_text(file_path, page_number, session_id=session_id)
    except Exception:
        return None


# ============================================================================
# 7. CHUNKING OPTIMIZED FOR QWEN 3.6 35B (256K CONTEXT) & LOCAL LLM SCANNER
# ============================================================================

def split_into_overlapping_chunks(text: str, max_chars: int = 45000, overlap_chars: int = 1200) -> List[Dict[str, Any]]:
    paragraphs = re.split(r"(\n\s*\n|\n)", text)
    chunks: List[Dict[str, Any]] = []
    current = ""
    char_cursor = 0
    chunk_start = 0

    for piece in paragraphs:
        if len(current) + len(piece) > max_chars and current.strip():
            chunks.append(
                {
                    "chunk_index": len(chunks) + 1,
                    "start_char": chunk_start,
                    "end_char": char_cursor,
                    "text": current,
                }
            )
            tail = current[-overlap_chars:] if len(current) > overlap_chars else current
            nl_pos = tail.find("\n")
            if nl_pos != -1 and nl_pos < len(tail) // 2:
                tail = tail[nl_pos + 1 :]
            current = tail + piece
            chunk_start = char_cursor - len(tail)
        else:
            current += piece
        char_cursor += len(piece)

    if current.strip():
        chunks.append(
            {
                "chunk_index": len(chunks) + 1,
                "start_char": chunk_start,
                "end_char": char_cursor,
                "text": current,
            }
        )
    return chunks


OLLAMA_LEGAL_NER_SYSTEM_PROMPT = """Você é um extrator jurídico determinístico de dados pessoais (LGPD / CNJ Res. 615/2025) em peças processuais, boletins de ocorrência (REDS/BO), comprovantes bancários, transcrições e decisões judiciais brasileiras.
Sua ÚNICA tarefa é analisar o trecho pré-mascarado e retornar um objeto JSON puro contendo as entidades sensíveis encontradas.
NÃO reescreva o texto. NÃO resuma. Retorne APENAS JSON válido no formato de duas camadas (omita listas vazias):
{
  "PESSOA": ["nomes completos ou parciais de partes, autores, réus, executados, vítimas, solicitantes, pais, mães, de cujus, espólios, testemunhas, policiais, sargentos, soldados, peritos, advogados"],
  "APELIDO": ["alcunhas, vulgos ('Baiano', 'Zezinho'), primeiros nomes informais ('Jaci'), nomes sociais ou @usuarios"],
  "EMPRESA": ["nomes empresariais, razões sociais, nomes fantasia, supermercados, lojas, bancos privados, cooperativas de crédito, MEIs, empregadores"],
  "ENDERECO": ["logradouros privados, ruas, avenidas com ou sem número, quadras/lotes, fazendas, sítios, locais de trabalho privados"],
  "PROCESSO_PRIVADO": ["números de processos judiciais das próprias partes, execuções conexas, Cartas Precatórias, Inquéritos Policiais (IP), TCOs ou PADs que ainda não estejam mascarados"],
  "JURISPRUDENCIA_CITADA": ["se algum marcador <PROCESSO_N> ou número CNJ aparecer DENTRO de uma ementa ou citação de jurisprudência pública de tribunal (TJSP, TJMG, STJ, STF), liste-o aqui para ser mantido público"],
  "CPF": ["qualquer CPF residual não mascarado"],
  "RG": ["qualquer RG ou documento civil residual não mascarado"],
  "CONTA_BANCARIA": ["qualquer agência, cooperativa ou conta bancária residual"],
  "CHAVE_PIX": ["qualquer chave PIX ou ID de transação residual"],
  "TELEFONE": ["qualquer telefone residual"],
  "PLACA": ["qualquer placa de veículo residual"],
  "CONSELHO_PROFISSIONAL": ["qualquer CRM, CREA, CRC, COREN, OAB residual"],
  "REGISTRO_CARTORIO": ["qualquer matrícula imobiliária, livro, folha ou termo de cartório residual"]
}
REGRAS RÍGIDAS DE EXCLUSÃO (NÃO INCLUA EM HIPÓTESE ALGUMA):
1. NÃO inclua cidades, estados ou comarcas isoladas (ex.: 'Comarca de Poços de Caldas/MG', 'Passos/MG', 'Nova Resende/MG', 'São Paulo/SP') — a competência territorial deve permanecer legível.
2. NÃO inclua órgãos públicos, tribunais, delegacias ou batalhões (ex.: 'TJMG', 'STJ', 'STF', '16ª Delegacia de Polícia Civil', '77 CIA PM', 'Ministério Público', 'Defensoria Pública').
3. NÃO inclua leis, artigos, súmulas ou ementas de jurisprudência pública em PROCESSO_PRIVADO.
4. NÃO inclua datas, prazos ou valores monetários (R$) — são essenciais para prescrição e liquidação.
"""


def query_local_ollama_ner(
    chunk_text: str,
    model: str = "gemma4:e4b",
    ollama_url: str = "http://127.0.0.1:11434",
    timeout: int = 300,
) -> Dict[str, Any]:
    messages = [
        {"role": "system", "content": OLLAMA_LEGAL_NER_SYSTEM_PROMPT},
        {"role": "user", "content": f"Extraia as entidades sensíveis deste trecho jurídico:\n\n{chunk_text}"},
    ]
    openai_style = "/v1" in ollama_url or ollama_url.rstrip("/").endswith("/chat/completions")
    if openai_style:
        url = ollama_url.rstrip("/")
        if not url.endswith("/chat/completions"):
            url += "/chat/completions"
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": 0.0,
            "stream": False,
            "max_tokens": 2048,
            "response_format": {"type": "json_object"},
            "chat_template_kwargs": {"enable_thinking": False},
        }
        headers = {"Content-Type": "application/json"}
        if os.environ.get("LLM_API_KEY"):
            headers["Authorization"] = "Bearer " + os.environ["LLM_API_KEY"]
    else:
        url = f"{ollama_url.rstrip('/')}/api/chat"
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "think": False,
            "format": "json",
            "options": {"temperature": 0.0},
        }
        headers = {"Content-Type": "application/json"}

    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))

    if openai_style:
        content = ((body.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    else:
        content = body.get("message", {}).get("content", "")

    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
    m = re.search(r"\{.*\}", content, flags=re.DOTALL)
    if not m:
        return {}
    try:
        parsed = json.loads(m.group(0))
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


# ============================================================================
# 8. TOLERANT RESTORATION ENGINE WITH UNRESOLVED TAG AUDIT (`pii-roundtrip`)
# ============================================================================

def tolerant_restore_text(text: str, session_data: Dict[str, Any]) -> Tuple[str, int, List[str]]:
    token_map: Dict[str, str] = session_data.get("token_to_original", {})
    if not token_map:
        return text, 0, []

    core_map: Dict[str, str] = {}
    for tok, orig in token_map.items():
        core = tok.strip("<>[] ").upper()
        core_map[core] = orig

    pattern = re.compile(
        r"(?:<|\[)\s*\*{0,2}([A-Za-z0-9_]+_\d+[a-z0-9]*)\*{0,2}\s*(?:>|\])|\b([A-Z]{3,22}_\d+[a-z0-9]*)\b"
    )
    restored_count = 0
    unresolved: List[str] = []

    def _restore_match(m: re.Match) -> str:
        nonlocal restored_count
        key = (m.group(1) or m.group(2) or "").upper()
        if key in core_map:
            restored_count += 1
            return core_map[key]
        if m.group(0).startswith(("<", "[")) and m.group(0) not in unresolved:
            unresolved.append(m.group(0))
        return m.group(0)

    return pattern.sub(_restore_match, text), restored_count, unresolved


# ============================================================================
# 9. TRUE STRUCTURAL PDF REDACTION (`redact_pdf`) WITH GUARANTEED WHITE
#    PLACEHOLDER OVERLAY & NON-OVERLAPPING PILL WIDENING
# ============================================================================

def _clean_pdf_word_token(wtext: str) -> str:
    return strip_accents(re.sub(r"^[^\wÀ-ÿ]+|[^\wÀ-ÿ]+$", "", wtext)).casefold()


def _is_whole_word_pdf_rect(page_words: List[Any], rect: Any, original: str) -> bool:
    clean_orig = original.strip()
    if re.match(r"^\d{1,5}[A-Za-z]?$", clean_orig):
        target_digits = _clean_pdf_word_token(clean_orig)
        for w in page_words:
            wx0, wy0, wx1, wy1, wtext = w[0], w[1], w[2], w[3], w[4]
            if min(rect.x1, wx1) > max(rect.x0, wx0) and min(rect.y1, wy1) > max(rect.y0, wy0):
                clean_w = _clean_pdf_word_token(wtext)
                if clean_w != target_digits:
                    return False
        return True

    if not re.match(r"^[A-Za-zÀ-ÿ]+$", clean_orig):
        return True
    target_norm = _clean_pdf_word_token(clean_orig)
    for w in page_words:
        wx0, wy0, wx1, wy1, wtext = w[0], w[1], w[2], w[3], w[4]
        if min(rect.x1, wx1) > max(rect.x0, wx0) and min(rect.y1, wy1) > max(rect.y0, wy0):
            clean_w = _clean_pdf_word_token(wtext)
            if clean_w and clean_w != target_norm and target_norm in clean_w:
                return False
    return True


def _search_page_rects_tolerant(fitz: Any, page: Any, page_words: List[Any], original: str, textpage: Any = None) -> List[Any]:
    kw = {"textpage": textpage} if textpage is not None else {}
    rects: List[Any] = list(page.search_for(original, **kw))
    if " " in original:
        dbl = re.sub(r"\s+", "  ", original.strip())
        if dbl != original:
            rects.extend(page.search_for(dbl, **kw))

    orig_parts = [_clean_pdf_word_token(p) for p in original.strip().split() if _clean_pdf_word_token(p)]
    if orig_parts and page_words:
        n = len(orig_parts)
        cleaned_page_words = [_clean_pdf_word_token(w[4]) for w in page_words]
        for idx in range(len(page_words) - n + 1):
            if cleaned_page_words[idx : idx + n] == orig_parts:
                line_groups: Dict[Tuple[int, int], List[Any]] = {}
                for k in range(n):
                    w = page_words[idx + k]
                    wx0, wy0, wx1, wy1, wtext = float(w[0]), float(w[1]), float(w[2]), float(w[3]), str(w[4])
                    if k == n - 1 and len(wtext) > len(orig_parts[-1]):
                        trailing_chars = len(wtext) - len(wtext.rstrip(".,;:!?)"))
                        if trailing_chars > 0 and len(wtext) > trailing_chars:
                            wx1 = wx0 + (wx1 - wx0) * ((len(wtext) - trailing_chars) / len(wtext))
                    key = (int(w[5]), int(w[6]))
                    line_groups.setdefault(key, []).append(fitz.Rect(wx0, wy0, wx1, wy1))
                for group_rects in line_groups.values():
                    u = group_rects[0]
                    for gr in group_rects[1:]:
                        u = u | gr
                    rects.append(u)
    return rects


def _draw_pdf_placeholder_on_black_box(
    fitz: Any,
    page: Any,
    rect: Any,
    token: str,
    page_words: List[Any],
    redacted_rects: List[Any],
) -> None:
    try:
        unit_w = fitz.get_text_length(token, fontname="helv", fontsize=1.0)
    except Exception:
        unit_w = max(1.0, len(token) * 0.53)
    unit_w = max(unit_w, 0.1)

    fs_height = min(8.0, max(4.2, rect.height * 0.72))
    avail_w = max(1.0, rect.width - 1.6)
    fs_in_rect = avail_w / unit_w

    pill_rect = fitz.Rect(rect.x0, rect.y0, rect.x1, rect.y1)
    if fs_in_rect >= 4.4:
        fs = min(fs_height, fs_in_rect)
    else:
        target_fs = min(fs_height, 5.2)
        needed_w = unit_w * target_fs + 2.4
        max_x1 = min(float(page.rect.x1) - 3.0, float(rect.x0) + max(float(rect.width), needed_w))

        # Stop before any unredacted word to the right on the same line
        for w in page_words:
            wx0, wy0, wx1, wy1 = float(w[0]), float(w[1]), float(w[2]), float(w[3])
            v_overlap = min(float(rect.y1), wy1) - max(float(rect.y0), wy0)
            if v_overlap > 2.0 and wx0 >= float(rect.x1) - 1.5:
                w_rect = fitz.Rect(wx0, wy0, wx1, wy1)
                w_area = max(w_rect.get_area(), 1e-6)
                if any((w_rect & rr).get_area() / w_area >= 0.45 for rr in redacted_rects):
                    continue
                max_x1 = min(max_x1, wx0 - 1.2)

        # Also stop before any other redaction box to the right on the same line!
        for rr in redacted_rects:
            if rr == rect:
                continue
            v_overlap = min(float(rect.y1), float(rr.y1)) - max(float(rect.y0), float(rr.y0))
            if v_overlap > 2.0 and float(rr.x0) >= float(rect.x1) - 2.0:
                max_x1 = min(max_x1, float(rr.x0) - 1.5)

        if max_x1 > float(rect.x1):
            pill_rect = fitz.Rect(rect.x0, rect.y0, max_x1, rect.y1)
            page.draw_rect(pill_rect, color=(0, 0, 0), fill=(0, 0, 0))

        final_avail_w = max(1.0, float(pill_rect.width) - 1.4)
        fs = max(3.5, min(fs_height, final_avail_w / unit_w))

    baseline_y = float(pill_rect.y0) + (float(pill_rect.height) + fs * 0.72) * 0.5
    baseline_y = min(float(pill_rect.y1) - 1.0, max(float(pill_rect.y0) + fs * 0.75, baseline_y))
    page.insert_text(
        fitz.Point(float(pill_rect.x0) + 0.8, baseline_y),
        token,
        fontname="helv",
        fontsize=fs,
        color=(1, 1, 1),
    )


def _get_visual_redactions_for_file(file_path: Path, session_data: Dict[str, Any]) -> Dict[str, Any]:
    vr_map: Dict[str, Any] = session_data.get("visual_redactions_by_file") or {}
    if not vr_map:
        return {}
    stem_k = safe_file_stem(file_path).casefold()
    name_k = file_path.name.strip().casefold()
    for k in (stem_k, name_k, f"{stem_k}{file_path.suffix.lower()}"):
        if k in vr_map and isinstance(vr_map[k], dict):
            return vr_map[k]
    return {}


def redact_pdf(
    input_path: Path,
    session_data: Dict[str, Any],
    session_id: Optional[str] = None,
    output_pdf_path: Optional[Path] = None,
    pages_work_dir: Optional[Path] = None,
) -> Tuple[Optional[Path], List[int], List[int], List[str]]:
    fitz = _import_fitz()
    pairs = build_longest_first_replacement_pairs(session_data)
    out = output_pdf_path or input_path.with_name(f"{safe_file_stem(input_path)}.anonymized.pdf")
    out.parent.mkdir(parents=True, exist_ok=True)

    file_vr_payload = _get_visual_redactions_for_file(input_path, session_data)
    if fitz is None:
        out_f, s_red, s_unred, prevs = _redact_pdf_fallback_without_fitz(
            input_path,
            out,
            pairs,
            session_data,
            session_id=session_id,
            file_vr_payload=file_vr_payload,
            pages_work_dir=pages_work_dir,
        )
        return out_f, s_red, s_unred, prevs

    doc = fitz.open(str(input_path))
    scanned_redacted_pages: List[int] = []
    scanned_unredacted_pages: List[int] = []

    for page_idx, page in enumerate(doc):
        page_text = page.get_text("text").strip()
        non_cam_chars = len(re.sub(r"digitalizadocomcamscanner|\s+", "", page_text, flags=re.IGNORECASE))
        has_large_imgs = _fitz_page_has_large_embedded_images(page)

        vector_only = non_cam_chars < 40 and _fitz_page_is_vector_drawn(page)
        if vector_only:
            # Letters drawn as curves ("print to PDF" with outlined fonts, bank/SCR reports): there is no text to
            # search, so the page is OCR'd like a scan. Flatten it to pixels first, so the black boxes cover pixels
            # and no glyph outline survives underneath.
            _flatten_fitz_page_to_image(fitz, page)
        if non_cam_chars < 40 and (len(page.get_images()) > 0 or vector_only):
            redacted_count = _try_visual_redact_fitz_page(
                fitz,
                doc,
                page_idx,
                input_path,
                session_data,
                session_id=session_id,
                file_vr_payload=file_vr_payload,
            )
            if redacted_count > 0:
                scanned_redacted_pages.append(page_idx + 1)
            else:
                scanned_unredacted_pages.append(page_idx + 1)
            continue

        page_words = page.get_text("words")
        done_items: List[Tuple[Any, str]] = []
        try:
            tpage = page.get_textpage()  # built once; each search_for used to rebuild it (≈20 ms × every vault entry)
        except Exception:
            tpage = None
        folded_page = strip_accents(page_text).casefold()
        for original, token in pairs:
            # cheap pre-check: skip entries whose words are nowhere on the page
            first_w = strip_accents(original.strip().split()[0]).casefold() if original.strip() else ""
            if first_w and len(first_w) >= 3 and first_w not in folded_page:
                continue
            for rect in _search_page_rects_tolerant(fitz, page, page_words, original, textpage=tpage):
                rect_area = max(rect.get_area(), 1e-6)
                if any((rect & r).get_area() / rect_area >= 0.45 for r, _ in done_items):
                    continue
                if not _is_whole_word_pdf_rect(page_words, rect, original):
                    continue
                done_items.append((rect, token))
                page.add_redact_annot(rect, fill=(0, 0, 0))

        if done_items:
            page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
            all_rects = [r for r, _ in done_items]
            for rect, token in done_items:
                _draw_pdf_placeholder_on_black_box(fitz, page, rect, token, page_words, all_rects)

        # If this is a hybrid page (digital text + large embedded images, e.g. SENATRAN `CNH-e Dudu.pdf`),
        # ALSO visually redact the embedded images!
        if has_large_imgs:
            redacted_count = _try_visual_redact_fitz_page(
                fitz,
                doc,
                page_idx,
                input_path,
                session_data,
                session_id=session_id,
                file_vr_payload=file_vr_payload,
            )
            if redacted_count > 0 and (page_idx + 1) not in scanned_redacted_pages:
                scanned_redacted_pages.append(page_idx + 1)

    if scanned_unredacted_pages and len(scanned_unredacted_pages) == len(doc):
        doc.close()
        if out.exists():
            out.unlink()
        return None, scanned_redacted_pages, scanned_unredacted_pages, []

    doc.set_metadata({})
    doc.save(str(out), garbage=4, deflate=True)
    doc.close()

    preview_imgs: List[str] = []
    if scanned_redacted_pages and out.exists():
        preview_imgs = _render_redacted_pdf_previews(out, scanned_redacted_pages, session_id=session_id, pages_work_dir=pages_work_dir)
    return out, scanned_redacted_pages, scanned_unredacted_pages, preview_imgs


def _build_extra_boxes_for_page_from_vr_payload(
    input_path: Path,
    page_num: int,
    session_id: Optional[str],
    session_data: Dict[str, Any],
    file_vr_payload: Dict[str, Any],
) -> List[Dict[str, Any]]:
    if not file_vr_payload:
        return []
    try:
        script_dir = Path(__file__).resolve().parent
        if str(script_dir) not in sys.path:
            sys.path.insert(0, str(script_dir))
        import visual_redactor

        entities_d, norm_lids, norm_bxs = visual_redactor._normalize_redactions_payload(file_vr_payload)
        if entities_d:
            apply_external_entities_payload(session_data, entities_d)
        extra: List[Dict[str, Any]] = []
        lay = visual_redactor.extract_ocr_layout_for_page(input_path, page_number=page_num, session_id=session_id)
        img_p, _, _ = visual_redactor.render_page_to_pil_image(input_path, page_number=page_num, dpi=200)
        for item in norm_lids:
            lid = int(item.get("id", 0))
            explicit_p = int(item.get("page", 0))
            # Support both globally unique page-offset IDs (#101..#199 -> page 2) and explicit page numbers
            inferred_p = (lid // 100) + 1 if lid >= 100 else (explicit_p if explicit_p >= 1 else 1)
            if inferred_p != page_num and explicit_p != page_num:
                continue
            cat = str(item.get("category", "PESSOA"))
            for line in lay.get("lines", []):
                line_id_val = int(line["id"])
                local_idx = line_id_val - (page_num - 1) * 100 if line_id_val >= 100 else line_id_val
                if line_id_val == lid or (explicit_p == page_num and local_idx == lid):
                    raw_t = item.get("text") or line["text"]
                    if str(raw_t).startswith("[INK_REGION_"):
                        cat = "ASSINATURA" if cat == "PESSOA" else cat
                    tok = register_entity(session_data, str(raw_t), cat)
                    extra.append({"bbox_1000": line["bbox_1000"], "token": tok, "original": str(raw_t)})
        for item in norm_bxs:
            b1000 = item.get("bbox_1000")
            if isinstance(b1000, list) and len(b1000) == 4:
                raw_b = [int(round(float(x))) for x in b1000]
                mapped_p, mapped_b = visual_redactor.unproject_box_from_2up_if_applicable(
                    input_path, int(item.get("page", 1)), raw_b, session_id=session_id
                )
                if mapped_p != page_num:
                    continue
                final_b = visual_redactor.snap_box_to_ink_1000(img_p, mapped_b) if item.get("snap", True) else mapped_b
                cat = str(item.get("category", "PESSOA"))
                raw_t = str(item.get("text") or f"regiao_visual_p{page_num}_{final_b[0]}_{final_b[1]}")
                tok = register_entity(session_data, raw_t, cat)
                extra.append({"bbox_1000": final_b, "token": tok, "original": raw_t})
        return extra
    except Exception:
        return []


def _render_redacted_pdf_previews(
    redacted_pdf_path: Path,
    page_numbers: List[int],
    session_id: Optional[str] = None,
    pages_work_dir: Optional[Path] = None,
) -> List[str]:
    previews: List[str] = []
    try:
        script_dir = Path(__file__).resolve().parent
        if str(script_dir) not in sys.path:
            sys.path.insert(0, str(script_dir))
        import visual_redactor

        clean_stem = re.sub(r"\.anonymized$", "", safe_file_stem(redacted_pdf_path), flags=re.IGNORECASE)
        vis_dir = pages_work_dir if pages_work_dir else ((get_session_dir(session_id) / "visual_grids" / clean_stem) if session_id else redacted_pdf_path.parent)
        vis_dir.mkdir(parents=True, exist_ok=True)
        for p_num in page_numbers:
            r_img, _, _ = visual_redactor.render_page_to_pil_image(redacted_pdf_path, page_number=p_num, dpi=150)
            scaled_img = visual_redactor._rescale_pil_to_1024_token_budget(r_img.convert("RGB"), max_tokens=1024)
            prev_jpg = vis_dir / f"{clean_stem}.page_{p_num:04d}.redacted_preview.jpg"
            scaled_img.save(str(prev_jpg), format="JPEG", quality=88, subsampling=0, optimize=True)
            if session_id:
                ws_prev, _ = _mirror_grid_to_active_workspace_if_outside(prev_jpg, session_id)
                previews.append(ws_prev)
            else:
                previews.append(str(prev_jpg.resolve()))
    except Exception:
        pass
    return previews


def _fitz_page_is_vector_drawn(page: Any, min_items: int = 400) -> bool:
    """A page with no text layer but thousands of path segments: text printed as outlines."""
    try:
        n = 0
        for d in page.get_drawings():
            n += len(d.get("items", ()))
            if n >= min_items:
                return True
    except Exception:
        return False
    return False


def _flatten_fitz_page_to_image(fitz: Any, page: Any, dpi: int = 200) -> None:
    pix = page.get_pixmap(dpi=dpi)
    page.add_redact_annot(page.rect, fill=(1, 1, 1))
    page.apply_redactions(images=getattr(fitz, "PDF_REDACT_IMAGE_REMOVE", 1),
                          graphics=getattr(fitz, "PDF_REDACT_LINE_ART_REMOVE_IF_TOUCHED", 2))
    page.insert_image(page.rect, pixmap=pix)


def _try_visual_redact_fitz_page(
    fitz: Any,
    doc: Any,
    page_idx: int,
    input_path: Path,
    session_data: Dict[str, Any],
    session_id: Optional[str] = None,
    file_vr_payload: Optional[Dict[str, Any]] = None,
) -> int:
    try:
        script_dir = Path(__file__).resolve().parent
        if str(script_dir) not in sys.path:
            sys.path.insert(0, str(script_dir))
        import visual_redactor

        extra_boxes = _build_extra_boxes_for_page_from_vr_payload(
            input_path, page_idx + 1, session_id, session_data, file_vr_payload or {}
        )
        return visual_redactor.redact_scanned_fitz_page_in_place(
            fitz=fitz,
            doc=doc,
            page_idx=page_idx,
            pdf_path=input_path,
            session_data=session_data,
            session_id=session_id,
            extra_boxes_1000=extra_boxes,
        )
    except Exception:
        return 0


def _redact_pdf_fallback_without_fitz(
    input_path: Path,
    out_path: Path,
    pairs: List[Tuple[str, str]],
    session_data: Dict[str, Any],
    session_id: Optional[str] = None,
    file_vr_payload: Optional[Dict[str, Any]] = None,
    pages_work_dir: Optional[Path] = None,
) -> Tuple[Optional[Path], List[int], List[int], List[str]]:
    try:
        script_dir = Path(__file__).resolve().parent
        if str(script_dir) not in sys.path:
            sys.path.insert(0, str(script_dir))
        import visual_redactor

        p_cnt = visual_redactor.get_pdf_page_count(input_path)
        extra_by_page: Dict[int, List[Dict[str, Any]]] = {}
        if file_vr_payload:
            for p_num in range(1, p_cnt + 1):
                eb = _build_extra_boxes_for_page_from_vr_payload(
                    input_path, p_num, session_id, session_data, file_vr_payload
                )
                if eb:
                    extra_by_page[p_num] = eb
        out_f, s_red, s_unred = visual_redactor.redact_pdf_with_pillow_fallback(
            input_path=input_path,
            out_path=out_path,
            pairs=pairs,
            session_data=session_data,
            session_id=session_id,
            extra_boxes_by_page=extra_by_page,
        )
        prevs: List[str] = []
        if out_f and out_f.exists() and s_red:
            prevs = _render_redacted_pdf_previews(out_f, s_red, session_id=session_id, pages_work_dir=pages_work_dir)
        return out_f, s_red, s_unred, prevs
    except Exception:
        return None, [], [], []


# ============================================================================
# 10. DEEP COMPONENT-TOKEN & MODULO-11 LEAK AUDITOR (`find_leaks`)
# ============================================================================

def find_leaks(
    anon_text: str,
    session_data: Dict[str, Any],
    scanned_unredacted_pages: Optional[List[int]] = None,
    pdf_redacted_path: Optional[Path] = None,
) -> List[str]:
    out: List[str] = []
    body = anon_text.replace(CLOUD_LLM_HEADER_PT, "")
    wl_spans = compute_whitelist_spans(body, session_data.get("whitelist", []))

    for original, token in build_longest_first_replacement_pairs(session_data):
        if len(original.strip()) < 3:
            continue
        pat = re.compile(build_entity_boundary_pattern(original), flags=re.IGNORECASE)
        leaked = any(not is_span_whitelisted(m.start(), m.end(), wl_spans) for m in pat.finditer(body))
        if leaked:
            out.append(f"{token} still appears in text output")

    for gid, ginfo in session_data.get("canonical_groups", {}).items():
        cat = ginfo["category"]
        canonical = ginfo["canonical"]
        if cat in ("PESSOA", "PERSON"):
            for part in canonical.split():
                clean_p = re.sub(r"[^\wÀ-ÿ]", "", part)
                if (
                    len(clean_p) >= 4
                    and clean_p.casefold() not in PORTUGUESE_COMMON_WORD_STOPWORDS
                    and normalize_key_fold(clean_p) not in PORTUGUESE_COMMON_WORD_STOPWORDS
                ):
                    p_pat = re.compile(r"\b" + re.escape(clean_p) + r"\b", re.IGNORECASE)
                    if any(not is_span_whitelisted(m.start(), m.end(), wl_spans) for m in p_pat.finditer(body)):
                        msg = f"Component name token of <{gid}> still appears in output"
                        if msg not in out:
                            out.append(msg)
        elif cat in ("ENDERECO", "ADDRESS", "LOCAL"):
            _, street_core, _ = extract_address_core(canonical)
            if street_core:
                for part in street_core.split():
                    clean_p = re.sub(r"[^\wÀ-ÿ]", "", part)
                    if (
                        len(clean_p) >= 5
                        and clean_p.casefold() not in PORTUGUESE_COMMON_WORD_STOPWORDS
                        and normalize_key_fold(clean_p) not in PORTUGUESE_COMMON_WORD_STOPWORDS
                    ):
                        p_pat = re.compile(r"\b" + re.escape(clean_p) + r"\b", re.IGNORECASE)
                        if any(not is_span_whitelisted(m.start(), m.end(), wl_spans) for m in p_pat.finditer(body)):
                            msg = f"Street name token of <{gid}> still appears in output"
                            if msg not in out:
                                out.append(msg)

    cpf_rx = re.compile(r"\b\d{3}\s*\.\s*\d{3}\s*\.\s*\d{3}\s*[-–]\s*\d{2}\b")
    cpf_leaks = [
        m.group(0)
        for m in cpf_rx.finditer(body)
        if not is_span_whitelisted(m.start(), m.end(), wl_spans) and validate_cpf_checksum(m.group(0))
    ]
    if cpf_leaks:
        out.append(f"{len(cpf_leaks)} valid CPF(s) left")

    cnpj_rx = re.compile(r"\b\d{2}\s*\.\s*\d{3}\s*\.\s*\d{3}\s*/\s*\d{4}\s*[-–]\s*\d{2}\b")
    cnpj_leaks = [
        m.group(0)
        for m in cnpj_rx.finditer(body)
        if not is_span_whitelisted(m.start(), m.end(), wl_spans) and validate_cnpj_checksum(m.group(0))
    ]
    if cnpj_leaks:
        out.append(f"{len(cnpj_leaks)} valid CNPJ(s) left")

    email_rx = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
    email_leaks = [m.group(0) for m in email_rx.finditer(body) if not is_span_whitelisted(m.start(), m.end(), wl_spans)]
    if email_leaks:
        out.append(f"{len(email_leaks)} e-mail(s) left")

    phone_rx = re.compile(r"\(\s*\d{2}\s*\)\s*\d[\d\s.\-–]{6,12}\d\b")
    phone_leaks = [m.group(0) for m in phone_rx.finditer(body) if not is_span_whitelisted(m.start(), m.end(), wl_spans)]
    if phone_leaks:
        out.append(f"{len(phone_leaks)} phone number(s) left")

    if scanned_unredacted_pages:
        out.append(
            f"Scanned image page(s) {scanned_unredacted_pages} got no redaction box: nothing on the page matched a rule or a registered entity. View the page's .grid.jpg, then add what must be hidden to discovered_entities.json (names under PESSOA/APELIDO, blue #ID numbers under VISUAL_REDACTIONS line_ids, or a region as \"boxes\": [[xmin, ymin, xmax, ymax]] read from the 0-1000 tick marks) and run anonymize again with the same --session"
        )

    if pdf_redacted_path and pdf_redacted_path.exists():
        fitz = _import_fitz()
        if fitz is not None:
            try:
                pdoc = fitz.open(str(pdf_redacted_path))
                pdf_text = "\n".join(p.get_text("text") for p in pdoc)
                pdoc.close()
                pdf_wl = compute_whitelist_spans(pdf_text, session_data.get("whitelist", []))
                for original, token in build_longest_first_replacement_pairs(session_data):
                    if len(original.strip()) < 4:
                        continue
                    pat = re.compile(build_entity_boundary_pattern(original), flags=re.IGNORECASE)
                    if any(not is_span_whitelisted(m.start(), m.end(), pdf_wl) for m in pat.finditer(pdf_text)):
                        msg = f"{token} still appears in redacted PDF text layer"
                        if msg not in out:
                            out.append(msg)
            except Exception:
                pass

    return out


# ============================================================================
# 11. HIGH-LEVEL FILE ANONYMIZATION, RESTORATION & CLEAN DELIVERY PIPELINES
# ============================================================================

CLOUD_LLM_HEADER_PT = """[AVISO DE DOCUMENTO JURÍDICO ANONIMIZADO LOCALMENTE]
Os dados pessoais e identificadores sensíveis deste documento foram substituídos por marcadores semânticos determinísticos no formato `<CATEGORIA_ID>` e variantes `<CATEGORIA_IDa>` (ex.: `<PESSOA_1>`, `<EMPRESA_1>`, `<EMPRESA_1a>`, `<CPF_1>`, `<PROCESSO_1>`).
REGRAS DE PRESERVAÇÃO PARA O MODELO:
1. O mesmo identificador (`<PESSOA_1>`) refere-se sempre à mesma parte em todos os documentos desta sessão. Variantes com letra (`<EMPRESA_1a>`) referem-se à forma abreviada da mesma entidade (`<EMPRESA_1>`).
2. PRESERVE todos os marcadores `<CATEGORIA_ID>` exatamente como estão ao redigir petições, pareceres, minutas ou resumos.
3. NÃO traduza, não omita, não altere a numeração e não tente adivinhar os valores reais por trás dos marcadores.
================================================================================
"""


def resolve_anonymization_workspace(
    source_path: Path,
    explicit_output_dir: Optional[str | Path] = None,
) -> Dict[str, Path]:
    """
    Resolves the self-contained `<source_dir>/anonymization/` workspace (or `explicit_output_dir`
    if provided) so the user's original source folder is treated as 100% READ-ONLY:
    - `delivery_dir`: `<source_dir>/anonymization/` (top-level Cloud-ready deliverables)
    - `work_dir`: `<delivery_dir>/_work/`
    - `originals_copy_dir`: `<delivery_dir>/_work/originals_copy/` (working copies with trailing spaces stripped)
    - `pages_dir`: `<delivery_dir>/_work/pages/` (full-page `.view.png`, `.grid.png`, and `.redacted_preview.png` screenshots)
    - `session_work_dir`: `<delivery_dir>/_work/session/` (`discovered_entities.json`, `mapping.json`, `visual_redactions.json`)
    """
    base_dir = source_path if source_path.is_dir() else source_path.parent
    if explicit_output_dir:
        delivery_dir = Path(explicit_output_dir).expanduser().resolve()
    else:
        delivery_dir = (base_dir / "anonymization").resolve()

    work_dir = delivery_dir / "_work"
    originals_copy_dir = work_dir / "originals_copy"
    pages_dir = work_dir / "pages"
    session_work_dir = work_dir / "session"

    for d in (delivery_dir, work_dir, originals_copy_dir, pages_dir, session_work_dir):
        d.mkdir(parents=True, exist_ok=True)

    return {
        "source_dir": base_dir.resolve(),
        "delivery_dir": delivery_dir,
        "work_dir": work_dir,
        "originals_copy_dir": originals_copy_dir,
        "pages_dir": pages_dir,
        "session_work_dir": session_work_dir,
    }


def stage_working_copy(source_file: Path, originals_copy_dir: Path) -> Path:
    """
    Copies `source_file` into `originals_copy_dir` with a normalized Windows-safe stem
    (`"procuração tia Lu .pdf"` -> `"procuração tia Lu.pdf"`) so the user's original
    file is never touched or modified.
    """
    originals_copy_dir.mkdir(parents=True, exist_ok=True)
    clean_name = f"{safe_file_stem(source_file)}{source_file.suffix.lower()}"
    dest = originals_copy_dir / clean_name
    if not dest.exists() or dest.stat().st_size != source_file.stat().st_size:
        shutil.copy2(source_file, dest)
    return dest


def _mirror_grid_to_active_workspace_if_outside(grid_path: Path, session_id: str) -> Tuple[str, Optional[str]]:
    """
    If the user's case folder (`grid_path`) is outside the agent's current working directory
    (`os.getcwd()`, e.g. `LocalChat Workspace`), automatically mirrors `grid_path` into
    `<cwd>/anonymization_pages/<session_id>/<grid_path.name>` and returns the workspace-relative
    path as `primary_path` so `show_file` works on the very first call without `xcopy`!
    """
    abs_grid = str(grid_path.resolve())
    try:
        cwd = Path.cwd().resolve()
        try:
            rel = grid_path.resolve().relative_to(cwd)
            return str(rel).replace("\\\\", "/"), abs_grid
        except ValueError:
            mirror_dir = cwd / "anonymization_pages" / session_id
            mirror_dir.mkdir(parents=True, exist_ok=True)
            mirror_dest = mirror_dir / grid_path.name
            shutil.copy2(grid_path, mirror_dest)
            rel_mirror = mirror_dest.resolve().relative_to(cwd)
            return str(rel_mirror).replace("\\\\", "/"), abs_grid
    except Exception:
        return abs_grid, None


def ocr_workers() -> int:
    """How many pages to OCR at once: about half the logical cores (the rest stay free for the chat model),
    capped; LEGAL_ANON_OCR_WORKERS overrides."""
    env = os.environ.get("LEGAL_ANON_OCR_WORKERS", "").strip()
    if env.isdigit() and int(env) > 0:
        return int(env)
    return max(1, min(12, (os.cpu_count() or 2) // 2))


def _ocr_pages_parallel(visual_redactor: Any, working_file: Path, page_nums: List[int], session_id: str) -> None:
    workers = min(ocr_workers(), len(page_nums))
    if workers <= 1:
        return
    from concurrent.futures import ThreadPoolExecutor, as_completed

    visual_redactor.TESS_SINGLE_THREAD = True
    t0 = time.time()
    done = 0
    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(visual_redactor.extract_ocr_layout_for_page, working_file, page_number=p, session_id=session_id,
                              dpi=200) for p in page_nums]
            for f in as_completed(futs):
                done += 1
                try:
                    f.result()
                except Exception as exc:  # the sequential pass retries this page
                    print(f"[ocr] page failed in parallel, retrying later: {exc}", file=sys.stderr, flush=True)
                if done % max(1, len(page_nums) // 10) == 0 or done == len(page_nums):
                    print(f"[ocr] {working_file.name}: {done}/{len(page_nums)} pages ({time.time() - t0:.0f} s)",
                          file=sys.stderr, flush=True)
    finally:
        visual_redactor.TESS_SINGLE_THREAD = False


def page_needs_vision(lay: Dict[str, Any]) -> Tuple[bool, str]:
    """Does a scanned page need to be looked at, or does its OCR text (already in the chunks) say everything?
    Looking costs up to ~1,000 image tokens plus the model's thinking per page, so only pages where something can't be
    read as text are sent to the eyes: photos/faces, QR codes, ID-card-like sparse layouts, rotated or poor scans."""
    if "ocr_mean_conf" not in lay:
        return True, "no OCR confidence recorded"
    if lay.get("face_boxes_1000"):
        return True, "has a photo"
    if lay.get("qr_boxes_1000"):
        return True, "has a QR code"
    n_lines = len(lay.get("lines") or [])
    if n_lines < 12:
        return True, "sparse layout (ID card, receipt or form)"
    share = lay.get("ocr_low_conf_share")
    if float(lay.get("ocr_mean_conf") or 0) < 80 or (1.0 if share is None else float(share)) > 0.15:
        return True, f"OCR is unsure (mean confidence {lay.get('ocr_mean_conf')})"
    return False, f"clean typed text ({n_lines} lines, mean OCR confidence {lay.get('ocr_mean_conf')})"


def _prepare_scanned_pages_screenshots_for_chunk(
    working_file: Path,
    original_file: Path,
    session_id: str,
    session_data: Dict[str, Any],
    pages_dir: Path,
) -> List[Dict[str, Any]]:
    """
    Screenshot-First Scanned Page Inspector (v6.2):
    - Generates ONLY `<stem>.page_XXXX.grid.jpg` (or `<stem>.pages_0001_0002.grid.jpg` for 2-page sparse IDs/slips)
      pre-scaled to native 1,024-token resolution (`~80–180 KB` JPEG, zero `.view.png` duplicates!).
    - Automatically mirrors `.grid.jpg` into `<cwd>/anonymization_pages/<session_id>/` when `<pasta>` is
      outside `os.getcwd()` (`LocalChat Workspace`) so `show_file` succeeds without `xcopy`.
    - Filters out boilerplate blue `#ID` badges and lists `candidate_blue_badges` in the JSON output.
    """
    ext = working_file.suffix.lower()
    if ext not in IMAGE_EXTENSIONS and ext != ".pdf":
        return []

    scanned_page_nums: List[int] = []
    if ext in IMAGE_EXTENSIONS:
        scanned_page_nums = [1]
    elif ext == ".pdf":
        fitz = _import_fitz()
        if fitz is not None:
            try:
                doc = fitz.open(str(working_file))
                for idx, page in enumerate(doc):
                    ptxt = page.get_text("text") or ""
                    non_cam = re.sub(r"digitalizadocomcamscanner|\s+", "", ptxt, flags=re.IGNORECASE)
                    if len(non_cam) < 40 or _fitz_page_has_large_embedded_images(page):
                        scanned_page_nums.append(idx + 1)
                doc.close()
            except Exception:
                pass
        else:
            try:
                import pdfplumber

                with pdfplumber.open(str(working_file)) as pdf:
                    for idx, page in enumerate(pdf.pages):
                        ptxt = page.extract_text() or ""
                        if len(re.sub(r"\s+", "", ptxt)) < 25:
                            scanned_page_nums.append(idx + 1)
            except Exception:
                pass

    if not scanned_page_nums:
        return []

    out_items: List[Dict[str, Any]] = []
    try:
        script_dir = Path(__file__).resolve().parent
        if str(script_dir) not in sys.path:
            sys.path.insert(0, str(script_dir))
        import visual_redactor

        clean_stem = safe_file_stem(working_file)
        pages_dir.mkdir(parents=True, exist_ok=True)

        # Remove any stale .view.png or .grid.png from older runs so wildcard copies never pick up duplicates
        for old_p in pages_dir.glob(f"{clean_stem}.page*.*"):
            if old_p.suffix.lower() == ".png":
                old_p.unlink(missing_ok=True)

        # OCR every scanned page in parallel first (results land in the per-page cache), one single-threaded
        # Tesseract per page; the loop below then reads the cache. A 12-page scan went from 129 s to a fraction.
        _ocr_pages_parallel(visual_redactor, working_file, scanned_page_nums, session_id)

        page_bundles = []
        for p_num in scanned_page_nums:
            img, _, _ = visual_redactor.render_page_to_pil_image(working_file, page_number=p_num, dpi=200)
            lay = visual_redactor.extract_ocr_layout_for_page(working_file, page_number=p_num, session_id=session_id, dpi=200)
            rot_cw = int(lay.get("rotation_detected_cw", 0))
            auto_boxes = visual_redactor.match_session_entities_to_ocr_boxes(lay, session_data, img=img)
            cand_badges = visual_redactor.get_unmatched_candidate_badges(lay, auto_boxes)
            page_bundles.append((p_num, img, lay, rot_cw, auto_boxes, cand_badges))

        # Smart 2-Up Cropped Vertical Stack: if this single PDF has exactly 2 scanned pages AND both pages
        # have sparse vertical ink occupancy (e.g., front & back of an RG card in `documentos pessoais`),
        # combine them into a single high-legibility stacked `.pages_0001_0002.grid.jpg` with globally unique #IDs!
        if len(page_bundles) == 2 and visual_redactor.can_smart_stack_two_pages(page_bundles[0][2], page_bundles[1][2]):
            p1, img1, lay1, rot1, ab1, cb1 = page_bundles[0]
            p2, img2, lay2, rot2, ab2, cb2 = page_bundles[1]
            grid_jpg = pages_dir / f"{clean_stem}.pages_{p1:04d}_{p2:04d}.grid.jpg"
            visual_redactor.render_smart_2up_stacked_grid_image(
                working_file, session_id, img1, lay1, ab1, img2, lay2, ab2, grid_jpg
            )
            ws_grid_path, abs_work_grid = _mirror_grid_to_active_workspace_if_outside(grid_jpg, session_id)
            merged_cb = {**cb1, **cb2}
            out_items.append(
                {
                    "source_file": original_file.name,
                    "working_copy": str(working_file.resolve()),
                    "pages_combined": [p1, p2],
                    "layout_mode": "smart_2up_vertical_cropped",
                    "grid_image": ws_grid_path,
                    "work_dir_grid_image": abs_work_grid,
                    "auto_matched_boxes_count": len(ab1) + len(ab2),
                    "candidate_blue_badges": merged_cb,
                    "vision_instruction": (
                        f"Pages {p1} and {p2} of '{original_file.name}' are stacked in a single image (`grid_image`: '{ws_grid_path}'). "
                        f"Top half is Page {p1} (`#1..#99`), bottom half is Page {p2} (`#101..#199`). "
                        f"View `grid_image` directly with `show_file` (maximum 4 images per turn!), add any unmasked names/IDs to "
                        f"`entities_staging_file`, and if any blue `#ID` badge needs redaction, list its integer ID under "
                        f"\"VISUAL_REDACTIONS\": {{\"{original_file.name}\": {{\"line_ids\": [...]}}}}."
                    ),
                }
            )
            return out_items

        for p_num, img, lay, rot_cw, auto_boxes, cand_badges in page_bundles:
            grid_jpg = pages_dir / f"{clean_stem}.page_{p_num:04d}.grid.jpg"
            visual_redactor.render_annotated_grid_image(img, lay, auto_boxes, grid_jpg)
            ws_grid_path, abs_work_grid = _mirror_grid_to_active_workspace_if_outside(grid_jpg, session_id)

            needs, why = page_needs_vision(lay)
            if needs:
                instr = (
                    f"Page {p_num} of '{original_file.name}' needs a look ({why}): view `grid_image` ('{ws_grid_path}') with "
                    f"`show_file` (maximum 4 images per turn!), add any visible names/addresses/accounts to "
                    f"`entities_staging_file`, and if any blue `#ID` badge needs redaction, list its integer ID under "
                    f"\"VISUAL_REDACTIONS\": {{\"{original_file.name}\": {{\"line_ids\": [...]}}}}."
                )
            else:
                instr = (
                    f"Page {p_num} of '{original_file.name}' was read cleanly by OCR ({why}); its text is in the chunks, so "
                    f"review it there — no need to view the image. Open `grid_image` ('{ws_grid_path}') only if the text "
                    f"suggests handwriting, stamps, signatures or a photo, or to pick `#ID` badges."
                )
            out_items.append(
                {
                    "source_file": original_file.name,
                    "working_copy": str(working_file.resolve()),
                    "page": p_num,
                    "rotation_auto_corrected_cw": rot_cw,
                    "grid_image": ws_grid_path,
                    "work_dir_grid_image": abs_work_grid,
                    "needs_vision": needs,
                    "vision_reason": why,
                    "auto_matched_boxes_count": len(auto_boxes),
                    "candidate_blue_badges": cand_badges,
                    "vision_instruction": instr,
                }
            )
    except Exception:
        pass
    return out_items


def _cleanup_stray_source_folder_files(source_dir: Path, delivery_dir: Optional[Path]) -> None:
    """
    Ensures the user's source folder (`source_dir`) never accumulates stray
    `.anonymized.*` files when deliverables belong in `delivery_dir`.
    """
    if not delivery_dir or source_dir.resolve() == delivery_dir.resolve():
        return
    try:
        for p in source_dir.iterdir():
            if p.is_file() and ".anonymized." in p.name:
                dest = delivery_dir / p.name
                if not dest.exists():
                    delivery_dir.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(p), str(dest))
                else:
                    p.unlink(missing_ok=True)
    except Exception:
        pass


def anonymize_file_pipeline(
    input_path: Path,
    session_id: Optional[str] = None,
    entities_json_path: Optional[Path] = None,
    inline_entities_json: Optional[str] = None,
    whitelist_items: Optional[List[str]] = None,
    use_ollama: bool = False,
    ollama_model: str = "gemma4:e4b",
    llm_url: str = "http://127.0.0.1:11434",
    output_path: Optional[Path] = None,
    delivery_dir: Optional[Path] = None,
    prepend_llm_header: bool = True,
    log_mode: str = "normal",
    docx_image_mode: str = "placeholder",
) -> Dict[str, Any]:
    session_id, session_data = create_or_load_session(session_id)
    sdir = get_session_dir(session_id)
    staging_dir = sdir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    ws = resolve_anonymization_workspace(input_path, explicit_output_dir=delivery_dir)
    target_deliv_dir = ws["delivery_dir"]
    pages_work_dir = ws["pages_dir"]
    session_work_dir = ws["session_work_dir"]
    working_input = stage_working_copy(input_path, ws["originals_copy_dir"])
    clean_stem = safe_file_stem(working_input)

    if whitelist_items:
        existing_wl = set(session_data.get("whitelist", []))
        for w in whitelist_items:
            if w.strip():
                existing_wl.add(w.strip())
        session_data["whitelist"] = sorted(existing_wl)

    external_entities: Dict[str, Any] = {}
    if entities_json_path and entities_json_path.exists():
        external_entities.update(json.loads(entities_json_path.read_text(encoding="utf-8")))
    if inline_entities_json:
        external_entities.update(json.loads(inline_entities_json))

    raw_text = extract_text_from_file(working_input, session_id=session_id)

    # Pass 1: Deterministic Brazilian Legal Regexes + Modulo-11 Checksums + Jurisprudence Guard
    scan_deterministic_regexes(raw_text, session_data)

    # Pass 2A: Register external entities & JURISPRUDENCIA_CITADA overrides from Local LLM
    if external_entities:
        apply_external_entities_payload(session_data, external_entities)

    # Pass 2B: Optional direct local Ollama / OpenAI-compatible server scan
    if use_ollama:
        pre_masked = apply_longest_first_replacements(raw_text, session_data)
        chunks = split_into_overlapping_chunks(pre_masked, max_chars=24000, overlap_chars=800)
        for ch in chunks:
            try:
                found = query_local_ollama_ner(ch["text"], model=ollama_model, ollama_url=llm_url, timeout=300)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                raise SystemExit(json.dumps({"status": "error", "error": f"local LLM at {llm_url} failed: {exc}"}))
            if found:
                apply_external_entities_payload(session_data, found)

    # Pass 3: Propagate surname, first-name, initials, fuzzy-typos, honorific, role, corporate, and address variants
    propagate_name_variants(raw_text, session_data)

    # Pass 4: Write formatted output directly into `target_deliv_dir` (NEVER cluttering `input_path.parent`)
    ext = input_path.suffix.lower()
    pdf_redacted: Optional[Path] = None
    image_redacted: Optional[Path] = None
    scanned_redacted_pages: List[int] = []
    scanned_unredacted_pages: List[int] = []

    docx_image_report: Optional[Dict[str, int]] = None
    if ext == ".docx":
        out_file = output_path or (target_deliv_dir / f"{clean_stem}.anonymized.docx")
        image_updates, docx_image_report = anonymize_docx_embedded_images(
            working_input, session_id=session_id, session_data=session_data, image_mode=docx_image_mode
        )
        rewrite_docx_package_atomic(
            source_docx=working_input,
            dest_docx=out_file,
            transform_fn=lambda txt: apply_longest_first_replacements(txt, session_data),
            image_updates=image_updates,
            is_restore=False,
        )
        embed_docx_session_metadata(out_file, session_id, scrub_author=True)

        txt_companion = out_file.with_suffix(".txt")
        anon_text = apply_longest_first_replacements(raw_text, session_data)
        if prepend_llm_header:
            anon_text = f"{CLOUD_LLM_HEADER_PT}\n{anon_text}"
        txt_companion.write_text(anon_text, encoding="utf-8")
    elif ext in IMAGE_EXTENSIONS:
        out_file = target_deliv_dir / f"{clean_stem}.anonymized.txt"
        anon_text = apply_longest_first_replacements(raw_text, session_data)
        if prepend_llm_header:
            anon_text = f"{CLOUD_LLM_HEADER_PT}\n{anon_text}"
        out_file.write_text(anon_text, encoding="utf-8")
        try:
            script_dir = Path(__file__).resolve().parent
            if str(script_dir) not in sys.path:
                sys.path.insert(0, str(script_dir))
            import visual_redactor

            img_out_target = output_path or (target_deliv_dir / f"{clean_stem}.anonymized{ext}")
            file_vr_payload = _get_visual_redactions_for_file(working_input, session_data)
            res_img = visual_redactor.apply_visual_redactions(
                file_path=working_input,
                session_id=session_id,
                redactions_payload=file_vr_payload,
                output_path=img_out_target,
                delivery_dir=target_deliv_dir,
            )
            if res_img.get("redacted_visual_file"):
                image_redacted = Path(res_img["redacted_visual_file"])
            if res_img.get("redacted_preview_images"):
                for p_img_str in res_img["redacted_preview_images"]:
                    p_img = Path(p_img_str)
                    if p_img.exists():
                        dest_prev = pages_work_dir / p_img.name
                        if p_img.resolve() != dest_prev.resolve():
                            shutil.copy2(p_img, dest_prev)
            if res_img.get("total_boxes_redacted", 0) > 0:
                scanned_redacted_pages = [1]
        except Exception:
            pass
    else:
        out_file = (
            output_path
            if (output_path and output_path.suffix.lower() != ".pdf")
            else (target_deliv_dir / f"{clean_stem}.anonymized.txt")
        )
        anon_text = apply_longest_first_replacements(raw_text, session_data)
        if prepend_llm_header:
            anon_text = f"{CLOUD_LLM_HEADER_PT}\n{anon_text}"
        out_file.write_text(anon_text, encoding="utf-8")
        pdf_preview_images: List[str] = []
        if ext == ".pdf":
            pdf_out_target = (
                output_path
                if (output_path and output_path.suffix.lower() == ".pdf")
                else (target_deliv_dir / f"{clean_stem}.anonymized.pdf")
            )
            pdf_redacted, scanned_redacted_pages, scanned_unredacted_pages, pdf_preview_images = redact_pdf(
                working_input,
                session_data,
                session_id=session_id,
                output_pdf_path=pdf_out_target,
                pages_work_dir=pages_work_dir,
            )
            # Re-apply text replacements after redact_pdf in case VISUAL_REDACTIONS line_ids registered new entities
            propagate_name_variants(raw_text, session_data)
            anon_text = apply_longest_first_replacements(raw_text, session_data)
            if prepend_llm_header:
                anon_text = f"{CLOUD_LLM_HEADER_PT}\n{anon_text}"
            out_file.write_text(anon_text, encoding="utf-8")

    _cleanup_stray_source_folder_files(input_path.parent, target_deliv_dir)

    session_data["stats"]["files_processed"].append(str(input_path.resolve()))
    map_path = save_session(session_id, session_data)
    try:
        _safe_json_write(session_work_dir / "mapping.json", session_data)
    except Exception:
        pass

    category_counts: Dict[str, int] = {}
    for tok in session_data["token_to_original"]:
        cat = tok.strip("<>").rsplit("_", 1)[0]
        category_counts[cat] = category_counts.get(cat, 0) + 1

    check_text = (
        txt_companion.read_text(encoding="utf-8")
        if ext == ".docx"
        else out_file.read_text(encoding="utf-8", errors="replace")
    )
    leaks = find_leaks(
        check_text,
        session_data,
        scanned_unredacted_pages=scanned_unredacted_pages,
        pdf_redacted_path=pdf_redacted,
    )

    delivered_files: List[str] = []
    candidates = (
        [out_file, txt_companion]
        if ext == ".docx"
        else ([out_file, image_redacted] if ext in IMAGE_EXTENSIONS else [out_file, pdf_redacted])
    )
    for cand in candidates:
        if cand and cand.exists():
            dest = target_deliv_dir / cand.name
            if cand.resolve() != dest.resolve():
                shutil.copy2(cand, dest)
            delivered_files.append(str(dest.resolve()))

    result: Dict[str, Any] = {
        "status": "ok" if not leaks else "needs_attention",
        "session_id": session_id,
        "input_file": str(input_path.resolve()),
        "output_file": str(out_file.resolve()),
        "mapping_file": str(map_path.resolve()),
        "total_unique_placeholders": len(session_data["token_to_original"]),
        "counts_by_category": category_counts,
        "whitelisted_jurisprudence_count": len(session_data.get("whitelist", [])),
        "rule_hits": session_data["stats"]["rule_hits"],
        "ignored_false_positives_count": len(session_data["stats"]["ignored_false_positives"]),
        "leak_check": {"ok": not leaks, "remaining": leaks[:20]},
    }
    if ext == ".docx":
        result["companion_text_file"] = str(txt_companion.resolve())
        if docx_image_report is not None:
            result["docx_image_report"] = docx_image_report
    if ext in IMAGE_EXTENSIONS:
        result["redacted_image"] = str(image_redacted.resolve()) if image_redacted else None
        img_prev = pages_work_dir / f"{clean_stem}.page_0001.redacted_preview.png"
        if img_prev.exists():
            result["redacted_preview_images"] = [str(img_prev.resolve())]
    result["working_copy"] = str(working_input.resolve())
    if ext == ".pdf":
        result["redacted_pdf"] = str(pdf_redacted.resolve()) if pdf_redacted else None
        if scanned_redacted_pages:
            result["scanned_pages_redacted_visually"] = scanned_redacted_pages
        if pdf_preview_images:
            result["redacted_preview_images"] = pdf_preview_images
        if scanned_unredacted_pages:
            result["scanned_pages_without_text"] = scanned_unredacted_pages
            result["scanned_pages_warning"] = (
                f"Pages {scanned_unredacted_pages} are scanned images that still need visual redaction. "
                f"Run `visual_redactor.py prepare --file \"{input_path}\" --session \"{session_id}\"` and `visual_redactor.py apply`."
            )
    if delivered_files:
        result["delivered_to_cloud_ready_dir"] = delivered_files
    if log_mode == "ultra":
        result["ignored_false_positives_detail"] = session_data["stats"]["ignored_false_positives"]
    return result


def restore_file_pipeline(
    input_path: Path,
    session_id: Optional[str] = None,
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    ext = input_path.suffix.lower()
    if ext == ".docx" and not session_id:
        session_id = extract_docx_session_id(input_path)
    if not session_id:
        raise ValueError("A session_id is required to restore plaintext files (or when .docx metadata is absent).")

    _, session_data = create_or_load_session(session_id)
    if not session_data.get("token_to_original"):
        raise ValueError(f"No mapping entries found for session_id='{session_id}'.")

    unresolved_all: List[str] = []

    images_restored_count = 0
    if ext == ".docx":
        out_file = output_path or input_path.with_name(
            re.sub(r"\.anonymized$", "", safe_file_stem(input_path)) + ".restored.docx"
        )
        total_restored = 0

        def _restore_fn(txt: str) -> str:
            nonlocal total_restored
            res, cnt, unres = tolerant_restore_text(txt, session_data)
            total_restored += cnt
            for u in unres:
                if u not in unresolved_all:
                    unresolved_all.append(u)
            return res

        restored_images = get_docx_restored_images(input_path, session_data)
        images_restored_count = len(restored_images)
        rewrite_docx_package_atomic(
            source_docx=input_path,
            dest_docx=out_file,
            transform_fn=_restore_fn,
            image_updates=restored_images,
            is_restore=True,
        )
    else:
        out_file = output_path or input_path.with_name(
            re.sub(r"\.anonymized$", "", safe_file_stem(input_path)) + ".restored.txt"
        )
        raw_text = extract_text_from_file(input_path)
        raw_text = raw_text.replace(CLOUD_LLM_HEADER_PT + "\n", "").replace(CLOUD_LLM_HEADER_PT, "")
        restored_text, total_restored, unresolved_all = tolerant_restore_text(raw_text, session_data)
        out_file.write_text(restored_text, encoding="utf-8")

    return {
        "status": "ok",
        "session_id": session_id,
        "input_file": str(input_path.resolve()),
        "restored_file": str(out_file.resolve()),
        "placeholders_restored": total_restored,
        "images_restored": images_restored_count,
        "unresolved_placeholders": unresolved_all,
    }


# ============================================================================
# 12. CLI INTERFACE OPTIMIZED FOR QWEN 3.6 35B (256K CONTEXT)
# ============================================================================

def _chunk_single_file(
    fpath: Path,
    session_id: str,
    session_data: Dict[str, Any],
    max_chars: int,
    overlap: int,
    ws: Optional[Dict[str, Path]] = None,
) -> Tuple[Dict[str, Any], str, List[Dict[str, Any]]]:
    if ws is None:
        ws = resolve_anonymization_workspace(fpath)
    working_fpath = stage_working_copy(fpath, ws["originals_copy_dir"])

    raw_text = extract_text_from_file(working_fpath, session_id=session_id)
    scan_deterministic_regexes(raw_text, session_data)
    pre_masked = apply_longest_first_replacements(raw_text, session_data)
    save_session(session_id, session_data)

    # Render screenshot + #ID grid immediately if this file is an image or has scanned PDF pages!
    scanned_vision_pages = _prepare_scanned_pages_screenshots_for_chunk(
        working_file=working_fpath,
        original_file=fpath,
        session_id=session_id,
        session_data=session_data,
        pages_dir=ws["pages_dir"],
    )

    chunks = split_into_overlapping_chunks(pre_masked, max_chars=max_chars, overlap_chars=overlap)
    sdir = get_session_dir(session_id)
    chunks_dir = sdir / "chunks" / safe_file_stem(working_fpath)
    chunks_dir.mkdir(parents=True, exist_ok=True)
    chunk_files = []
    for ch in chunks:
        cf = chunks_dir / f"chunk_{ch['chunk_index']:04d}.txt"
        cf.write_text(ch["text"], encoding="utf-8")
        chunk_files.append(str(cf.resolve()))

    manifest: Dict[str, Any] = {
        "source_file": str(fpath),
        "working_copy": str(working_fpath.resolve()),
        "total_chars": len(raw_text),
        "chunk_count": len(chunk_files),
        "chunk_files": chunk_files,
    }
    if scanned_vision_pages:
        manifest["scanned_pages_screenshots"] = scanned_vision_pages
        to_view = [p for p in scanned_vision_pages if p.get("needs_vision", True)]
        manifest["vision_summary"] = (
            f"{len(to_view)} of {len(scanned_vision_pages)} scanned page images need a look (photos, IDs, QR codes, "
            f"unsure OCR); the others were read cleanly and are reviewed from the chunk text.")
    return manifest, pre_masked, scanned_vision_pages


def _write_discovered_entities_template_if_absent(staging_path: Path) -> None:
    if staging_path.exists():
        return
    template = {
        "PESSOA": [],
        "APELIDO": [],
        "EMPRESA": [],
        "ENDERECO": [],
        "PROCESSO_PRIVADO": [],
        "JURISPRUDENCIA_CITADA": [],
        "CONTA_BANCARIA": [],
        "VISUAL_REDACTIONS": {},
    }
    _safe_json_write(staging_path, template)


# ----------------------------------------------------------------------------
# CLI helpers: one workspace per session, progress you can watch, no repeated work
# ----------------------------------------------------------------------------
_T0 = time.time()


def _progress(msg: str) -> None:
    """One line per step on stderr, flushed at once: a caller watching a background job sees where it is."""
    try:
        sys.stderr.write(f"[{time.time() - _T0:6.1f}s] {msg}\n")
        sys.stderr.flush()
    except Exception:
        pass


def _session_workspace(src: Path, session_id: Optional[str], explicit_output_dir: Optional[str]) -> Dict[str, Path]:
    """The workspace `chunk` used for this folder is the one `anonymize` must use: the session remembers it, so a
    later call without --output-dir still reads the entities file the model edited."""
    base = (src if src.is_dir() else src.parent).resolve()
    remembered = None
    if session_id and not explicit_output_dir:
        try:
            _, sd_ = create_or_load_session(session_id)
            remembered = (sd_.get("workspaces") or {}).get(str(base))
        except Exception:
            remembered = None
    ws = resolve_anonymization_workspace(src, explicit_output_dir=explicit_output_dir or remembered)
    if session_id:
        try:
            _, sd_ = create_or_load_session(session_id)
            if (sd_.get("workspaces") or {}).get(str(base)) != str(ws["delivery_dir"]):
                sd_.setdefault("workspaces", {})[str(base)] = str(ws["delivery_dir"])
                save_session(session_id, sd_)
        except Exception:
            pass
    return ws


def _entities_files_for(ws: Dict[str, Path], session_id: Optional[str]) -> List[Path]:
    """Every entities file that belongs to this session and folder, newest first: the workspace's staging file,
    the vault's copy, and the staging files of other workspaces this session used for the same folder."""
    cands: List[Path] = [ws["session_work_dir"] / "discovered_entities.json"]
    if session_id:
        cands.append(get_session_dir(session_id) / "discovered_entities.json")
        try:
            _, sd_ = create_or_load_session(session_id)
            for d in (sd_.get("workspaces") or {}).values():
                cands.append(Path(d) / "_work" / "session" / "discovered_entities.json")
        except Exception:
            pass
    seen: Set[str] = set()
    out: List[Path] = []
    for c in cands:
        k = str(c.resolve()) if c.exists() else ""
        if k and k not in seen:
            seen.add(k)
            out.append(c)
    return sorted(out, key=lambda x: x.stat().st_mtime, reverse=True)


def _file_fingerprint(path: Path, session_data: Dict[str, Any]) -> str:
    import hashlib
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    h.update(json.dumps(sorted((session_data.get("token_to_original") or {}).items()), ensure_ascii=False).encode("utf-8"))
    h.update(json.dumps(sorted(session_data.get("whitelist") or []), ensure_ascii=False).encode("utf-8"))
    h.update(json.dumps(session_data.get("visual_redactions") or session_data.get("VISUAL_REDACTIONS") or {}, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8"))
    try:
        h.update(str(Path(__file__).stat().st_mtime).encode())
    except Exception:
        pass
    return h.hexdigest()



# ----------------------------------------------------------------------------
# `verify`: read the delivered files back and list what is still readable
# ----------------------------------------------------------------------------
_VERIFY_REGEX_CATEGORIES = {"CPF", "CNPJ", "CEP", "TELEFONE", "EMAIL", "RG", "CNH", "OAB", "PIS", "CTPS", "CONTA_BANCARIA",
                            "CONSELHO_PROFISSIONAL", "PLACA", "PROCESSO", "PROCESSO_PRIVADO", "MATRICULA_IMOVEL"}


def _verify_pages(path: Path, verify_cache_id: str) -> List[Tuple[int, str, str]]:
    """[(page, text, how)] for a delivered file; scanned or flattened PDF pages are OCR'd again."""
    suf = path.suffix.lower()
    if suf == ".pdf":
        fitz = _import_fitz()
        out: List[Tuple[int, str, str]] = []
        doc = fitz.open(str(path))
        try:
            for i, pg in enumerate(doc):
                txt = pg.get_text("text")
                # what a reader sees on an image page is the pixels: OCR them (the drawn placeholder labels are the
                # only text such a page carries)
                body = re.sub(r"<[A-Z0-9_]+_\d+[a-z0-9]*>|\s+", "", txt)
                if pg.get_images() and len(body) < 40:
                    try:
                        import visual_redactor as vr_
                        txt = vr_.ocr_single_pdf_page_text(path, page_number=i + 1, session_id=verify_cache_id)
                        out.append((i + 1, txt, "ocr"))
                        continue
                    except Exception as exc:
                        out.append((i + 1, "", f"ocr failed: {type(exc).__name__}"))
                        continue
                out.append((i + 1, txt, "text"))
        finally:
            doc.close()
        return out
    if suf in (".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".bmp"):
        try:
            import visual_redactor as vr_
            return [(1, vr_.ocr_single_pdf_page_text(path, page_number=1, session_id=verify_cache_id), "ocr")]
        except Exception as exc:
            return [(1, "", f"ocr failed: {type(exc).__name__}")]
    return [(1, extract_text_from_file(path), "text")]


def _mask_context(line: str, s: int, e: int, label: str) -> str:
    a = max(0, s - 50)
    b = min(len(line), e + 50)
    left = re.sub(r"\s+", " ", line[a:s])
    right = re.sub(r"\s+", " ", line[e:b])
    return f"…{left}[{label}, {e - s} chars]{right}…"


def verify_delivery(session_id: str, delivery_dir: Path, only: Optional[List[str]] = None) -> Dict[str, Any]:
    _, sd = create_or_load_session(session_id)
    pairs = [(o, t) for o, t in build_longest_first_replacement_pairs(sd) if len(o.strip()) >= 4]
    compiled = [(re.compile(build_entity_boundary_pattern(o), re.IGNORECASE), o, t) for o, t in pairs]
    name_parts: List[Tuple[Any, str]] = []
    for gid, g in (sd.get("canonical_groups") or {}).items():
        if g.get("category") in ("PESSOA", "PERSON"):
            for part in str(g.get("canonical", "")).split():
                cp = re.sub(r"[^\wÀ-ÿ]", "", part)
                if len(cp) >= 4 and cp.casefold() not in PORTUGUESE_COMMON_WORD_STOPWORDS and normalize_key_fold(cp) not in PORTUGUESE_COMMON_WORD_STOPWORDS:
                    name_parts.append((re.compile(r"\b" + re.escape(strip_accents(cp)) + r"\b", re.IGNORECASE), f"<{gid}>"))
    files = sorted(p for p in delivery_dir.iterdir()
                   if p.is_file() and ".anonymized." in p.name and p.suffix.lower() != ".json")
    if only:
        files = [p for p in files if any(w.casefold() in p.name.casefold() for w in only)]
    report: List[Dict[str, Any]] = []
    total = 0
    cache_id = f"verify_{session_id}"
    for f_i, f in enumerate(files, start=1):
        _progress(f"verify {f_i}/{len(files)}: {f.suffix.lower()} file")
        hits: List[Dict[str, Any]] = []
        for page, txt, how in _verify_pages(f, cache_id):
            if how.startswith("ocr failed"):
                hits.append({"page": page, "kind": "unchecked", "why": how})
                continue
            body = txt.replace(CLOUD_LLM_HEADER_PT, "")
            folded = strip_accents(body)
            wl = compute_whitelist_spans(body, sd.get("whitelist", []))
            seen_spans: List[Tuple[int, int]] = []
            def add(s_: int, e_: int, kind: str, token: str, cat: str) -> None:
                if is_span_whitelisted(s_, e_, wl) or any(s_ < b and e_ > a for a, b in seen_spans):
                    return
                if re.fullmatch(r"<[A-Z0-9_]+_\d+[a-z0-9]*>", body[s_:e_].strip()):
                    return
                seen_spans.append((s_, e_))
                ls = body.rfind("\n", 0, s_) + 1
                le_ = body.find("\n", e_)
                le_ = len(body) if le_ < 0 else le_
                hits.append({"page": page, "kind": kind, "token": token, "category": cat, "read_by": how,
                             "context": _mask_context(body[ls:le_], s_ - ls, e_ - ls, token or cat)})
            for rx, orig, tok in compiled:
                for m in rx.finditer(body):
                    add(m.start(), m.end(), "vault value still readable", tok, tok.strip("<>").rsplit("_", 1)[0])
                if folded != body:
                    for m in rx.finditer(folded):
                        add(m.start(), m.end(), "vault value still readable", tok, tok.strip("<>").rsplit("_", 1)[0])
            for rx, tok in name_parts:
                for m in rx.finditer(folded):
                    add(m.start(), m.end(), "part of a registered name still readable", tok, "PESSOA")
            probe = {"token_to_original": {}, "surface_to_token": {}, "counters": {}, "canonical_groups": {},
                     "whitelist": list(sd.get("whitelist", [])), "stats": {"files_processed": [], "rule_hits": {}, "ignored_false_positives": []}}
            try:
                scan_deterministic_regexes(body, probe)
            except Exception:
                probe = {"token_to_original": {}}
            for tok, orig in (probe.get("token_to_original") or {}).items():
                cat = tok.strip("<>").rsplit("_", 1)[0]
                if cat not in _VERIFY_REGEX_CATEGORIES or not orig or len(orig.strip()) < 4:
                    continue
                for m in re.finditer(re.escape(orig), body):
                    known = (sd.get("surface_to_token") or {}).get(normalize_key(orig))
                    add(m.start(), m.end(), "new identifier the vault doesn't have" if not known else "vault value still readable",
                        known or "", cat)
        total += len(hits)
        sd.setdefault("verified", {})[str(f.resolve())] = {"leaks": len(hits), "at": time.strftime("%Y-%m-%d %H:%M"),
                                                           "mtime": f.stat().st_mtime}
        report.append({"file": str(f), "pages_checked": len({h["page"] for h in hits}) if hits else None,
                       "leaks": hits[:60], "leak_count": len(hits)})
    try:
        _, sd_save = create_or_load_session(session_id)
        sd_save["verified"] = {**(sd_save.get("verified") or {}), **sd.get("verified", {})}
        save_session(session_id, sd_save)
    except Exception:
        pass
    return {"status": "ok" if total == 0 else "leaks_found", "session_id": session_id, "delivery_dir": str(delivery_dir),
            "files_checked": len(files), "leaks_total": total, "files": report,
            "next_step": ("Nothing readable is left: the files are ready." if total == 0 else
                          "For each leak: a 'vault value' or 'part of a registered name' was missed by the redactor on that page — "
                          "add the page's box under VISUAL_REDACTIONS (line_ids from the page's .grid image, or boxes) or the exact "
                          "surface form under its category in the entities file; a 'new identifier' goes under its category. Then run "
                          "anonymize again with the same --session (only changed files are redone) and verify again. Never paste "
                          "the values anywhere else.")}



HOW_IT_BEHAVES = [
    "chunk: run once per folder. It picks the workspace (default <folder>/anonymization, or --output-dir) and the session "
    "remembers it; every later command with the same --session uses it, with or without --output-dir.",
    "Entities: edit the entities_staging_file chunk printed (<workspace>/_work/session/discovered_entities.json). anonymize "
    "reads it, the vault's copy and the staging files of the session's other workspaces for that folder, and merges them.",
    "anonymize --dir redoes only files whose content, vault entries, whitelist or visual redactions changed since their "
    "last run, or whose outputs are missing; the rest are kept ('unchanged_since_last_run'). Adding or editing an entity "
    "redoes every file (the vault changed). --only <part of a name> limits it to some files; --force redoes all.",
    "Never delete outputs, _work or caches to force a rerun: change the entities and rerun, or use --force.",
    "OCR results are cached per file version (size + time) in the session; they are reused, never stale.",
    "Scanned pages and pages without a text layer (letters drawn as curves) are OCR'd, matched against the vault and "
    "covered with black boxes on the page image; text pages are redacted in the PDF text.",
    "verify reads the outputs back (OCR for image pages) and lists what is still readable per file and page, values masked. "
    "A file is done only when verify says ok.",
    "Progress goes to stderr one line per file; the JSON result goes to stdout. Don't wrap commands in Out-File.",
    "Cited case law (court, case number, relator, dates, DJe) is never anonymized.",
]


def session_status(session_id: str, src: Path, ws: Dict[str, Path]) -> Dict[str, Any]:
    _, sd = create_or_load_session(session_id)
    base = src if src.is_dir() else src.parent
    files = sorted(p for p in base.iterdir() if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS
                   and ".anonymized." not in p.name and ".restored." not in p.name and p.name != "discovered_entities.json") \
        if base.is_dir() else []
    done_map = sd.get("delivered") or {}
    verified = sd.get("verified") or {}
    rows: List[Dict[str, Any]] = []
    for f in files:
        prev = done_map.get(str(f.resolve())) or {}
        outs = (prev.get("result") or {}).get("delivered_to_cloud_ready_dir") or []
        if not prev:
            state = "not anonymized yet"
        elif any(not Path(o).exists() for o in outs):
            state = "outputs missing: the next anonymize redoes it"
        elif prev.get("fingerprint") != _file_fingerprint(f, sd):
            state = "changed since (file or vault): the next anonymize redoes it"
        else:
            state = "up to date: the next anonymize keeps it"
        v = [verified.get(str(Path(o).resolve())) for o in outs if Path(o).exists()]
        v = [x for x in v if x]
        rows.append({"file": f.name, "type": f.suffix.lower(), "state": state,
                     "last_result": (prev.get("result") or {}).get("status"),
                     "outputs": [Path(o).name for o in outs],
                     "verify": ("never run" if not v else
                                f"{sum(x['leaks'] for x in v)} leak(s) at {max(x['at'] for x in v)}")})
    pending = [r for r in rows if not r["state"].startswith("up to date")]
    leaky = [r for r in rows if r["verify"].split()[0].isdigit() and r["verify"].split()[0] != "0"]
    unverified = [r for r in rows if r["verify"] == "never run" and r["outputs"]]
    if pending:
        nxt = f"Run anonymize --dir \"{base}\" --session {session_id} ({len(pending)} file(s) will be redone), then verify."
    elif leaky:
        nxt = ("verify found leaks: run verify for the details, fix the entities / VISUAL_REDACTIONS for those pages, "
               "then anonymize (only what changed is redone) and verify again.")
    elif unverified:
        nxt = f"Run verify --dir \"{base}\" --session {session_id}."
    else:
        nxt = "Every file is anonymized and verified clean."
    return {"status": "ok", "session_id": session_id, "source_dir": str(base),
            "workspace": str(ws["delivery_dir"]), "entities_file_to_edit": str(ws["session_work_dir"] / "discovered_entities.json"),
            "entities_files_read": [str(x) for x in _entities_files_for(ws, session_id)],
            "vault_entries": len(sd.get("token_to_original") or {}), "files": rows, "next_step": nxt,
            "how_it_behaves": HOW_IT_BEHAVES}


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="legal_anonymizer.py",
        description="100% Local, Working-Copy Isolated, Screenshot-First Legal Document Anonymizer (.docx, .pdf, .txt, images)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # 1. `chunk`: Copies originals to `<dir>/anonymization/_work/originals_copy/`, pre-masks regexes,
    #    renders `.view.png` & `.grid.png` screenshots for scanned PDFs/images, and emits chunks
    p_chunk = sub.add_parser(
        "chunk",
        help="Stage working copies in <dir>/anonymization/_work/, run Pass-1 regexes, render screenshots for scanned pages, and emit chunks.",
    )
    p_chunk.add_argument("--file", default=None, help="Path to input .pdf, .docx, .txt, .md, or image file")
    p_chunk.add_argument("--dir", default=None, help="Path to directory of case files to chunk under one session")
    p_chunk.add_argument("--session", default=None, help="Existing session_id (omit to create a new case session)")
    p_chunk.add_argument(
        "--output-dir",
        default=None,
        help="Optional custom anonymization workspace directory (default: <dir>/anonymization)",
    )
    p_chunk.add_argument(
        "--max-chars",
        type=int,
        default=45000,
        help="Max characters per chunk (default: 45000, optimized for Qwen3.6 35B 256k context)",
    )
    p_chunk.add_argument("--overlap", type=int, default=1200, help="Overlap characters between chunks (default: 1200)")
    p_chunk.add_argument("--whitelist", nargs="*", default=[], help="Strings that must never be anonymized")

    # 2. `register`: Register contextual entities spotted by the Local LLM into the session vault
    p_reg = sub.add_parser(
        "register",
        help="Register contextual PII entities (PESSOA, APELIDO, EMPRESA, ENDERECO, PROCESSO_PRIVADO, VISUAL_REDACTIONS, etc.) into the vault.",
    )
    p_reg.add_argument("--session", required=True, help="Target session_id")
    p_reg.add_argument("--entities-json", default=None, help="Inline JSON string of entities")
    p_reg.add_argument("--entities-file", default=None, help="Path to JSON file of entities")

    # 3. `anonymize`: Execute full longest-to-shortest replacement on a file (or directory of files)
    p_anon = sub.add_parser(
        "anonymize",
        help="Anonymize a single file (.pdf, .docx, .txt, .md, .jpg, .png) or an entire directory into <dir>/anonymization/.",
    )
    p_anon.add_argument("--file", default=None, help="Path to a single input file")
    p_anon.add_argument("--dir", default=None, help="Path to a directory of case files to batch-anonymize under one session")
    p_anon.add_argument("--session", default=None, help="Session ID (shared across all files in the same lawsuit)")
    p_anon.add_argument("--entities-file", default=None, help="Optional JSON file with Local LLM discovered entities")
    p_anon.add_argument("--entities-json", default=None, help="Optional inline JSON string with Local LLM discovered entities")
    p_anon.add_argument("--whitelist", nargs="*", default=[], help="Strings to exclude from anonymization")
    p_anon.add_argument("--use-ollama", action="store_true", help="Automatically query local LLM per chunk for NER")
    p_anon.add_argument("--ollama-model", default="gemma4:e4b", help="Local model name (default: gemma4:e4b)")
    p_anon.add_argument(
        "--llm-url",
        default=os.environ.get("LLM_URL", "http://127.0.0.1:11434"),
        help="Ollama URL or OpenAI-compatible /v1 endpoint (llama-server, LocalChat, LM Studio)",
    )
    p_anon.add_argument("--output", default=None, help="Explicit output file path (single-file mode)")
    p_anon.add_argument(
        "--output-dir",
        default=None,
        help="Clean output directory for Cloud-ready anonymized files (defaults to <dir>/anonymization)",
    )
    p_anon.add_argument("--no-header", action="store_true", help="Omit the Cloud LLM tag-preservation instruction header")
    p_anon.add_argument(
        "--docx-image-mode",
        choices=["placeholder", "redact", "keep"],
        default="placeholder",
        help="How to handle embedded images in .docx files: 'placeholder' (opaque IMAGEM REMOVIDA box, default), 'redact' (visual OCR black-box), or 'keep'",
    )
    p_anon.add_argument("--log-mode", choices=["normal", "ultra"], default="normal", help="Audit detail level")
    p_anon.add_argument("--only", nargs="*", default=[], help="With --dir: only files whose name contains one of these")
    p_anon.add_argument("--force", action="store_true", help="Redo files that have not changed since the last run")

    # 4. `restore`: De-anonymize a text or .docx file back to original client values
    p_rest = sub.add_parser(
        "restore",
        help="Restore placeholders (<PESSOA_1>, <CPF_1>, etc.) and embedded .docx images in a Cloud LLM response or edited .docx file.",
    )
    p_rest.add_argument("--file", required=True, help="Path to anonymized/edited .docx, .txt, or .md file")
    p_rest.add_argument("--session", default=None, help="Session ID (auto-detected for .docx files if embedded)")
    p_rest.add_argument("--output", default=None, help="Explicit output path for restored file")

    # 5. `inspect-session`: View placeholder counts and keys (or full mapping with --reveal)
    p_insp = sub.add_parser("inspect-session", help="Inspect a session's placeholder statistics and keys.")
    p_insp.add_argument("--session", required=True, help="Session ID")
    p_insp.add_argument("--reveal", action="store_true", help="Include original cleartext values in output")

    p_ver = sub.add_parser("verify", help="Read the delivered files back (OCR for image pages) and list every PII still readable, by file and page, without printing it.")
    p_ver.add_argument("--session", required=True, help="Session ID")
    p_ver.add_argument("--dir", default=None, help="The case folder (its session workspace is found automatically)")
    p_ver.add_argument("--file", default=None, help="A case file (its folder's workspace is used)")
    p_ver.add_argument("--output-dir", default=None, help="The delivery folder, if it isn't the remembered one")
    p_ver.add_argument("--only", nargs="*", default=[], help="Only delivered files whose name contains one of these")

    p_st = sub.add_parser("status", help="Where a session stands: its workspace, which entities files it reads, what the next anonymize will redo, verify results, the next step, and how the script behaves.")
    p_st.add_argument("--session", required=True, help="Session ID")
    p_st.add_argument("--dir", default=None, help="The case folder")
    p_st.add_argument("--file", default=None, help="A case file (its folder is used)")
    p_st.add_argument("--output-dir", default=None, help="The workspace, if it isn't the remembered one")

    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if args.command == "chunk":
        if not args.file and not args.dir:
            parser.error("Provide either --file or --dir.")
        session_id, session_data = create_or_load_session(args.session)
        if args.whitelist:
            session_data["whitelist"] = sorted(set(session_data.get("whitelist", []) + args.whitelist))
        sdir = get_session_dir(session_id)

        if args.file:
            fpath = Path(args.file).expanduser().resolve()
            ws = _session_workspace(fpath, session_id, args.output_dir)
            session_data.setdefault("workspaces", {})[str(ws["source_dir"])] = str(ws["delivery_dir"])
            staging_path = ws["session_work_dir"] / "discovered_entities.json"
            _write_discovered_entities_template_if_absent(staging_path)
            _write_discovered_entities_template_if_absent(sdir / "discovered_entities.json")
            staging_json = str(staging_path.resolve())

            info, pre_masked, scanned_vision = _chunk_single_file(
                fpath, session_id, session_data, args.max_chars, args.overlap, ws=ws
            )
            _safe_json_write(ws["session_work_dir"] / "mapping.json", session_data)
            out_payload: Dict[str, Any] = {
                "status": "ok",
                "session_id": session_id,
                "anonymization_workspace": str(ws["delivery_dir"]),
                "originals_copy_dir": str(ws["originals_copy_dir"]),
                "pages_screenshots_dir": str(ws["pages_dir"]),
                "entities_staging_file": staging_json,
                **info,
                "scanned_pages_to_inspect_with_vision": scanned_vision,
                "pass1_regex_placeholders": len(session_data["token_to_original"]),
            }
            if len(pre_masked) <= 36000:
                out_payload["inline_pre_masked_text_ready"] = True
                out_payload["note"] = (
                    "Full pre-masked text is included below in `inline_pre_masked_text`. "
                    "If `scanned_pages_to_inspect_with_vision` is non-empty, view each `grid_image` (or `screenshot_image`) "
                    "with your vision tool first! Then write all discovered entities (and any extra `#ID` `line_ids` under "
                    "`VISUAL_REDACTIONS`) to `entities_staging_file`."
                )
                out_payload["inline_pre_masked_text"] = pre_masked
            print(json.dumps(out_payload, ensure_ascii=False, indent=2))
        else:
            dpath = Path(args.dir).expanduser().resolve()
            ws = _session_workspace(dpath, session_id, args.output_dir)
            session_data.setdefault("workspaces", {})[str(ws["source_dir"])] = str(ws["delivery_dir"])
            staging_path = ws["session_work_dir"] / "discovered_entities.json"
            _write_discovered_entities_template_if_absent(staging_path)
            _write_discovered_entities_template_if_absent(sdir / "discovered_entities.json")
            staging_json = str(staging_path.resolve())

            files = sorted(
                [
                    p
                    for p in dpath.iterdir()
                    if p.is_file()
                    and p.suffix.lower() in SUPPORTED_EXTENSIONS
                    and ".anonymized." not in p.name
                    and ".restored." not in p.name
                    and p.name != "discovered_entities.json"
                ]
            )
            # Pre-extract and propagate deterministic entities across all files in the folder first
            # so every `.grid.jpg` and `inline_pre_masked_text` reflects cross-document coreference!
            pre_corpus_parts = []
            for f in files:
                try:
                    wf_pre = stage_working_copy(f, ws["originals_copy_dir"])
                    t_pre = extract_text_from_file(wf_pre, session_id=session_id)
                    scan_deterministic_regexes(t_pre, session_data)
                    pre_corpus_parts.append(t_pre)
                except Exception:
                    pass
            if pre_corpus_parts:
                full_pre_corpus = "\n\n".join(pre_corpus_parts)
                scan_deterministic_regexes(full_pre_corpus, session_data)
                propagate_name_variants(full_pre_corpus, session_data)
                save_session(session_id, session_data)

            file_manifests = []
            all_chunks = []
            combined_blocks = []
            all_scanned_vision: List[Dict[str, Any]] = []
            for f_i, f in enumerate(files, start=1):
                _progress(f"chunk {f_i}/{len(files)}: {f.suffix.lower()} file ({f.stat().st_size // 1024} KB)")
                info, pre_masked, scanned_vision = _chunk_single_file(
                    f, session_id, session_data, args.max_chars, args.overlap, ws=ws
                )
                file_manifests.append(info)
                all_chunks.extend(info["chunk_files"])
                all_scanned_vision.extend(scanned_vision)
                combined_blocks.append(f"=== [ARQUIVO: {f.name}] ===\n{pre_masked}")

            _safe_json_write(ws["session_work_dir"] / "mapping.json", session_data)
            full_combined_pre_masked = "\n\n".join(combined_blocks)
            combined_chunks = split_into_overlapping_chunks(
                full_combined_pre_masked, max_chars=args.max_chars, overlap_chars=args.overlap
            )
            comb_dir = sdir / "combined_chunks"
            comb_dir.mkdir(parents=True, exist_ok=True)
            combined_chunk_files = []
            for ch in combined_chunks:
                ccf = comb_dir / f"combined_chunk_{ch['chunk_index']:04d}.txt"
                ccf.write_text(ch["text"], encoding="utf-8")
                combined_chunk_files.append(str(ccf.resolve()))

            # only the pages that need eyes (photos, IDs, QR codes, unsure OCR); clean typed pages are reviewed from
            # the chunk text, which already holds their OCR
            grid_paths_all = [item["grid_image"] for item in all_scanned_vision
                              if item.get("grid_image") and item.get("needs_vision", True)]
            ocr_only = [item["grid_image"] for item in all_scanned_vision if item.get("grid_image") and not item.get("needs_vision", True)]
            vision_batches_max_4 = [grid_paths_all[i : i + 4] for i in range(0, len(grid_paths_all), 4)]
            out_payload = {
                "status": "ok",
                "session_id": session_id,
                "anonymization_workspace": str(ws["delivery_dir"]),
                "originals_copy_dir": str(ws["originals_copy_dir"]),
                "pages_screenshots_dir": str(ws["pages_dir"]),
                "entities_staging_file": staging_json,
                "files_chunked_count": len(file_manifests),
                "total_combined_chars": len(full_combined_pre_masked),
                "vision_batches_max_4_per_turn": vision_batches_max_4,
                "vision_summary": (f"{len(grid_paths_all)} page image(s) need a look; {len(ocr_only)} clean typed page(s) "
                                   "were read by OCR and are reviewed from the chunk text (open one only if its text "
                                   "suggests handwriting, stamps or a photo)."),
                "scanned_pages_to_inspect_with_vision": all_scanned_vision,
                "combined_chunk_files": combined_chunk_files,
                "all_chunk_files": all_chunks,
                "files": file_manifests,
                "pass1_regex_placeholders": len(session_data["token_to_original"]),
            }
            if len(full_combined_pre_masked) <= 36000:
                out_payload["inline_pre_masked_text_ready"] = True
                out_payload["note"] = (
                    "All files fit within 36,000 chars and are included below in `inline_pre_masked_text`. "
                    "1) Do NOT call read_file on individual chunk files and do NOT run xcopy (all `grid_image` paths are already staged inside your workspace!). "
                    "2) HARD LIMIT: View at most 4 `grid_image` files per turn by stepping through `vision_batches_max_4_per_turn` (1 batch of <=4 images per turn). "
                    "3) Write all discovered entities (and any extra `#ID` `line_ids` under `VISUAL_REDACTIONS`) to `entities_staging_file` and run `anonymize`."
                )
                out_payload["inline_pre_masked_text"] = full_combined_pre_masked
            print(json.dumps(out_payload, ensure_ascii=False, indent=2))

    elif args.command == "register":
        session_id, session_data = create_or_load_session(args.session)
        payload: Dict[str, Any] = {}
        if args.entities_file:
            payload.update(json.loads(Path(args.entities_file).expanduser().read_text(encoding="utf-8")))
        if args.entities_json:
            payload.update(json.loads(args.entities_json))
        added_count = apply_external_entities_payload(session_data, payload)
        save_session(session_id, session_data)
        print(
            json.dumps(
                {
                    "status": "ok",
                    "session_id": session_id,
                    "registered_count": added_count,
                    "total_session_placeholders": len(session_data["token_to_original"]),
                    "whitelisted_jurisprudence_count": len(session_data.get("whitelist", [])),
                },
                ensure_ascii=False,
                indent=2,
            )
        )

    elif args.command == "anonymize":
        if not args.file and not args.dir:
            parser.error("Provide either --file or --dir.")
        ef_path = Path(args.entities_file).expanduser().resolve() if args.entities_file else None
        out_path = Path(args.output).expanduser().resolve() if args.output else None

        if args.file:
            fpath = Path(args.file).expanduser().resolve()
            ws = _session_workspace(fpath, args.session, args.output_dir)
            deliv_dir = ws["delivery_dir"]
            if ef_path is None:
                efs = _entities_files_for(ws, args.session)
                if efs:
                    ef_path = efs[0]
                    if args.session and len(efs) > 1:
                        _, sd_m = create_or_load_session(args.session)
                        for extra in efs[1:]:
                            try:
                                apply_external_entities_payload(sd_m, json.loads(extra.read_text(encoding="utf-8")))
                            except Exception:
                                pass
                        save_session(args.session, sd_m)
            res = anonymize_file_pipeline(
                input_path=fpath,
                session_id=args.session,
                entities_json_path=ef_path,
                inline_entities_json=args.entities_json,
                whitelist_items=args.whitelist,
                use_ollama=args.use_ollama,
                ollama_model=args.ollama_model,
                llm_url=args.llm_url,
                output_path=out_path,
                delivery_dir=deliv_dir,
                prepend_llm_header=not args.no_header,
                log_mode=args.log_mode,
                docx_image_mode=args.docx_image_mode,
            )
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            dpath = Path(args.dir).expanduser().resolve()
            ws = _session_workspace(dpath, args.session, args.output_dir)
            deliv_dir = ws["delivery_dir"]
            entity_files = [ef_path] if ef_path else _entities_files_for(ws, args.session)

            files = sorted(
                [
                    p
                    for p in dpath.iterdir()
                    if p.is_file()
                    and p.suffix.lower() in SUPPORTED_EXTENSIONS
                    and ".anonymized." not in p.name
                    and ".restored." not in p.name
                    and p.name != "discovered_entities.json"
                ]
            )
            if args.only:
                wanted = [w.casefold() for w in args.only]
                files = [p for p in files if any(w in p.name.casefold() for w in wanted)]
            session_id, session_data = create_or_load_session(args.session)
            for ef_ in entity_files:
                try:
                    apply_external_entities_payload(session_data, json.loads(ef_.read_text(encoding="utf-8")))
                except Exception as exc:
                    _progress(f"could not read an entities file ({type(exc).__name__}): fix its JSON")
            _progress(f"anonymize: {len(files)} file(s), {len(session_data.get('token_to_original', {}))} vault entries, "
                      f"entities from {len(entity_files)} file(s); output in {deliv_dir}")
            if args.entities_json:
                apply_external_entities_payload(session_data, json.loads(args.entities_json))

            combined_texts = []
            working_files = []
            for f_i, f in enumerate(files, start=1):
                _progress(f"reading {f_i}/{len(files)}: {f.suffix.lower()} file ({f.stat().st_size // 1024} KB)")
                wf = stage_working_copy(f, ws["originals_copy_dir"])
                working_files.append((f, wf))
                ftxt = extract_text_from_file(wf, session_id=session_id)
                scan_deterministic_regexes(ftxt, session_data)
                combined_texts.append(ftxt)
            full_corpus_text = "\n\n".join(combined_texts)
            propagate_name_variants(full_corpus_text, session_data)
            save_session(session_id, session_data)

            batch_results = []
            ready_files: List[str] = []
            blocked_files: List[str] = []
            all_preview_images: List[str] = []
            done_map = session_data.setdefault("delivered", {})
            for f_i, (orig_f, _) in enumerate(working_files, start=1):
                fkey = str(orig_f.resolve())
                fp = _file_fingerprint(orig_f, session_data)
                prev = done_map.get(fkey) or {}
                if (not args.force and prev.get("fingerprint") == fp and prev.get("result")
                        and all(Path(x).exists() for x in prev["result"].get("delivered_to_cloud_ready_dir") or [])):
                    _progress(f"redacting {f_i}/{len(working_files)}: unchanged since the last run, kept")
                    res = dict(prev["result"], unchanged_since_last_run=True)
                    batch_results.append(res)
                    ready_files.extend(res.get("delivered_to_cloud_ready_dir") or [])
                    all_preview_images.extend(res.get("redacted_preview_images") or [])
                    if res.get("status") != "ok":
                        blocked_files.append(fkey)
                    continue
                t_f = time.time()
                _progress(f"redacting {f_i}/{len(working_files)}: {orig_f.suffix.lower()} file")
                res = anonymize_file_pipeline(
                    input_path=orig_f,
                    session_id=session_id,
                    entities_json_path=None,
                    inline_entities_json=None,
                    whitelist_items=args.whitelist,
                    use_ollama=args.use_ollama,
                    ollama_model=args.ollama_model,
                    llm_url=args.llm_url,
                    output_path=None,
                    delivery_dir=deliv_dir,
                    prepend_llm_header=not args.no_header,
                    log_mode=args.log_mode,
                    docx_image_mode=args.docx_image_mode,
                )
                _progress(f"redacting {f_i}/{len(working_files)}: {res.get('status')} in {time.time() - t_f:.1f}s")
                _, sd_now = create_or_load_session(session_id)
                sd_now.setdefault("delivered", {})[fkey] = {"fingerprint": _file_fingerprint(orig_f, sd_now), "result": res}
                save_session(session_id, sd_now)
                batch_results.append(res)
                if res.get("delivered_to_cloud_ready_dir"):
                    ready_files.extend(res["delivered_to_cloud_ready_dir"])
                if res.get("redacted_preview_images"):
                    all_preview_images.extend(res["redacted_preview_images"])
                if res.get("status") != "ok":
                    blocked_files.append(str(orig_f.resolve()))

            _cleanup_stray_source_folder_files(dpath, deliv_dir)

            overall_ok = all(r["status"] == "ok" for r in batch_results)
            print(
                json.dumps(
                    {
                        "status": "ok" if overall_ok else "needs_attention",
                        "session_id": session_id,
                        "files_processed_count": len(batch_results),
                        "cloud_ready_delivery": {
                            "delivery_dir": str(deliv_dir),
                            "work_dir": str(ws["work_dir"]),
                            "originals_copy_dir": str(ws["originals_copy_dir"]),
                            "pages_screenshots_dir": str(ws["pages_dir"]),
                            "redacted_preview_images": all_preview_images,
                            "all_leak_checks_passed": overall_ok,
                            "files_ready_for_cloud": ready_files,
                            "files_needing_review": blocked_files,
                        },
                        "results": batch_results,
                        "kept_unchanged": sum(1 for r in batch_results if r.get("unchanged_since_last_run")),
                        "next_step": ("Run verify --dir \"" + str(dpath) + "\" --session " + session_id + " before saying any file is done. "
                                      "Reruns redo only what changed: never delete outputs or _work. Run status to see where the session stands."),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )

    elif args.command == "status":
        src = Path(args.dir or args.file or ".").expanduser().resolve()
        ws = _session_workspace(src, args.session, args.output_dir)
        print(json.dumps(session_status(args.session, src, ws), ensure_ascii=False, indent=2))

    elif args.command == "verify":
        src = Path(args.dir or args.file or ".").expanduser().resolve()
        ws = _session_workspace(src, args.session, args.output_dir)
        print(json.dumps(verify_delivery(args.session, ws["delivery_dir"], args.only), ensure_ascii=False, indent=2))

    elif args.command == "restore":
        fpath = Path(args.file).expanduser().resolve()
        out_p = Path(args.output).expanduser().resolve() if args.output else None
        res = restore_file_pipeline(input_path=fpath, session_id=args.session, output_path=out_p)
        print(json.dumps(res, ensure_ascii=False, indent=2))

    elif args.command == "inspect-session":
        _, session_data = create_or_load_session(args.session)
        summary: Dict[str, Any] = {
            "session_id": session_data["session_id"],
            "created_at": session_data["created_at"],
            "updated_at": session_data["updated_at"],
            "counters": session_data["counters"],
            "total_placeholders": len(session_data["token_to_original"]),
            "whitelisted_jurisprudence": session_data.get("whitelist", []),
            "placeholders": list(session_data["token_to_original"].keys()),
            "stats": session_data.get("stats", {}),
        }
        if args.reveal:
            summary["token_to_original"] = session_data["token_to_original"]
            summary["canonical_groups"] = session_data.get("canonical_groups", {})
        print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
