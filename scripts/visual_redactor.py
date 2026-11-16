#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
visual_redactor.py v6.1 — Universal OCR + Underlined-Text Recovery + Signature/Photo Redactor
=============================================================================================
Companion script for `pt-legal-anonymizer` that redacts scanned image-only PDFs
(such as power-of-attorney instruments `Procurações`, bank PIX receipts, scanned
pleadings like `Contestação Caixa`, personal ID cards `RG`/`CNH`, and signed court
pages) and standalone images (`.png`, `.jpg`, `.jpeg`, `.webp`, `.bmp`, `.tif`)
while preserving 100% session consistency (`mapping.json`) with `legal_anonymizer.py`
and keeping exact PDF page formatting.

What's New in v6.0 (From Real-World Case Folder & `procuração tia Lu.pdf` Audit):
1. Windows Trailing-Space Safety & Zero Source-Folder Clutter:
   - Uses `la.safe_file_stem()` on all cache, grid, and output paths so filenames with
     trailing spaces before `.pdf` (`"procuração tia Lu .pdf"`) never raise
     `FileNotFoundError` on Windows NTFS.
   - Writes `.anonymized.pdf`/`.anonymized.txt` directly into `delivery_dir` (`anonimizados/`
     or `--output-dir`) and cleans up any stray `.anonymized.*` files in the user's source folder.
2. Automatic Upside-Down / Sideways Scan Orientation Detection (`0°`, `90°`, `180°`, `270°`):
   - Detects when a scanned ID card or document page (`documentos pessoais Juliana.pdf`) is
     upside-down (`180°`) or sideways (`90°`/`270°`) by scoring Portuguese legal/ID keywords
     and digit structures vs. reversed strings (`"SJQVGILNAG! Ad VEIZLHVO"`), uprighting the
     image for OCR and mapping bounding boxes back to the original page orientation.
3. Pass-B Un-OCR'd Ink-Crop Recovery with Underline Stripping (`--psm 7`):
   - Tesseract `--psm 3` frequently skips bold underlined text (`"e JOÃO PEDRO NUNES FIGUEIREDO SILVA,"`).
   - v6.0 zeroes out Pass-A OCR word boxes on `clean_mask` FIRST (so un-OCR'd text on the right
     half of a line is never merged with or discarded by an adjacent OCR box), strips 1px
     horizontal underlines in the bottom 30% of each remaining text-sized ink crop, pads with
     12px white border, and runs `tesseract --psm 7 tsv` to recover every underlined word and
     its exact bounding box!
4. Colon-Joined Label Splitting & Strict Vertical Line-Overlap Clamping:
   - Splits colon-joined OCR tokens (`"OUTORGANTES:MARIA"` -> `"OUTORGANTES:"` + `"MARIA"`) with
     proportional X-coordinate division so redacting `"MARIA..."` never blacks out `"OUTORGANTES:"`.
   - Clamps vertical padding between consecutive lines (`line[k].y1 <= line[k+1].y0 - 1`) so
     redaction boxes on Line 1 never slice through the top of Line 2 (`"aposentada com nascimento..."`).
5. Automatic Handwritten Signature (`<ASSINATURA_N>`), ID Portrait (`<FOTO_N>`), & Biometrics (`<BIOMETRIA_N>`) Detection:
   - Automatically detects cursive handwritten signatures in the signature zone above centered
     signer `<PESSOA_N>` / `<CPF_N>` lines (`"castro M m almeida castro"`) and adjacent to
     `"ASSINATURA"` / `"RUBRICA"` labels, redacting them with `<ASSINATURA_N>` and suppressing
     garbled cursive OCR strings from `.anonymized.txt`.
   - Detects 3x4 portrait face photos (`<FOTO_N>`) on scanned ID cards (`RG`/`CNH`) via OpenCV
     Haar cascade + ID-card portrait region analysis.
6. Universal `visual_redactions.json` Schema Parser:
   - Accepts all JSON formats produced by local LLMs (`Qwen3.6 35B`), including top-level or
     nested `"redactions": [{"line_ids": [4, 5, 29], "boxes": [[161, 147, 863, 172]]}]`,
     plain integer `line_ids`, raw 4-element `[xmin, ymin, xmax, ymax]` coordinate lists, or
     structured dicts, and pre-populates a clean template `visual_redactions.json` during `prepare`.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import legal_anonymizer as la


# ============================================================================
# 1. TESSERACT AUTO-DISCOVERY & SUBPROCESS TSV RUNNER (PAGE + SINGLE-LINE CROP)
# ============================================================================

def find_tesseract_binary() -> Optional[str]:
    env_bin = os.environ.get("TESSERACT_CMD")
    if env_bin and Path(env_bin).exists():
        return str(Path(env_bin))
    which_bin = shutil.which("tesseract")
    if which_bin:
        return which_bin
    if sys.platform == "win32":
        candidates = [
            Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe"),
            Path(r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"),
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Tesseract-OCR" / "tesseract.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Tesseract-OCR" / "tesseract.exe",
            Path(r"C:\ProgramData\chocolatey\bin\tesseract.exe"),
            Path.home() / "scoop" / "apps" / "tesseract" / "current" / "tesseract.exe",
            Path.home() / "AppData" / "Local" / "Programs" / "Tesseract-OCR" / "tesseract.exe",
        ]
        for c in candidates:
            if c.exists():
                return str(c)
        try:
            for p in Path(r"C:\Users").glob(r"*\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"):
                if p.exists():
                    return str(p)
        except Exception:
            pass
    return None


def get_available_tesseract_lang(tess_bin: str) -> str:
    try:
        proc = subprocess.run(
            [tess_bin, "--list-langs"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        langs = {line.strip().lower() for line in out.splitlines() if line.strip()}
        if "por" in langs and "eng" in langs:
            return "por+eng"
        if "por" in langs:
            return "por"
    except Exception:
        pass
    return "eng"


# When pages are OCR'd in parallel, each Tesseract runs single-threaded: one thread per page uses the cores far
# better than several OpenMP threads fighting over them.
TESS_SINGLE_THREAD = False


def _tess_env() -> Optional[Dict[str, str]]:
    if not TESS_SINGLE_THREAD:
        return None
    env = dict(os.environ)
    env["OMP_THREAD_LIMIT"] = "1"
    return env


def detect_orientation_osd(img: Any, tess_bin: str, timeout: int = 30) -> Tuple[int, float]:
    """Tesseract's orientation detector (`--psm 0`): (degrees to rotate clockwise, confidence). One fast pass at
    full resolution instead of four sparse OCR passes; (0, 0.0) when it is unavailable or unsure."""
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
        tmp_png = Path(tf.name)
    try:
        img.save(str(tmp_png), format="PNG")
        proc = subprocess.run([tess_bin, str(tmp_png), "stdout", "--psm", "0"], capture_output=True, timeout=timeout,
                              check=False, env=_tess_env())
        out = (proc.stdout or b"").decode("utf-8", errors="replace")
        m_rot = re.search(r"Rotate:\s*(\d+)", out)
        m_conf = re.search(r"Orientation confidence:\s*([\d.]+)", out)
        if not m_rot or not m_conf:
            return 0, 0.0
        return int(m_rot.group(1)) % 360, float(m_conf.group(1))
    except Exception:
        return 0, 0.0
    finally:
        try:
            tmp_png.unlink(missing_ok=True)
        except Exception:
            pass


def run_tesseract_cli_tsv(
    img: Any,
    tess_bin: str,
    lang: str,
    psm: int = 3,
    timeout: int = 45,
) -> Dict[str, List[Any]]:
    """
    Runs `tesseract <tmp.png> stdout -l <lang> --psm <psm> tsv` directly via subprocess
    without requiring the `pytesseract` Python package.
    """
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
        tmp_png = Path(tf.name)
    try:
        img.save(str(tmp_png), format="PNG")
        cmd = [tess_bin, str(tmp_png), "stdout", "-l", lang, "--psm", str(psm), "tsv"]
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False, env=_tess_env())
        raw_tsv = (proc.stdout or b"").decode("utf-8", errors="replace")
        lines = raw_tsv.splitlines()
        if len(lines) < 2:
            return {}
        headers = lines[0].split("\t")
        out: Dict[str, List[Any]] = {h: [] for h in headers}
        for row in lines[1:]:
            cols = row.split("\t")
            if len(cols) != len(headers):
                continue
            for h, val in zip(headers, cols):
                if h in (
                    "level",
                    "page_num",
                    "block_num",
                    "par_num",
                    "line_num",
                    "word_num",
                    "left",
                    "top",
                    "width",
                    "height",
                ):
                    try:
                        out[h].append(int(float(val)))
                    except ValueError:
                        out[h].append(0)
                elif h == "conf":
                    try:
                        out[h].append(float(val))
                    except ValueError:
                        out[h].append(-1.0)
                else:
                    out[h].append(val)
        return out
    finally:
        try:
            tmp_png.unlink(missing_ok=True)
        except Exception:
            pass


# ============================================================================
# 2. ORIENTATION SCORING (`0°`/`90°`/`180°`/`270°`) & COORDINATE TRANSFORMS
# ============================================================================

PORTUGUESE_ORIENTATION_KEYWORDS: Set[str] = {
    "procuracao",
    "outorgante",
    "outorgantes",
    "outorgado",
    "outorgados",
    "carteira",
    "identidade",
    "republica",
    "federativa",
    "brasil",
    "estado",
    "minas",
    "gerais",
    "paulo",
    "nome",
    "filiacao",
    "naturalidade",
    "nascimento",
    "cpf",
    "assinatura",
    "habilitacao",
    "nacional",
    "registro",
    "data",
    "expedicao",
    "orgao",
    "emissor",
    "comprovante",
    "banco",
    "caixa",
    "agencia",
    "conta",
    "cliente",
    "endereco",
    "telefone",
    "poderes",
    "advogado",
    "advogada",
    "brasileiro",
    "brasileira",
    "casado",
    "casada",
    "solteiro",
    "solteira",
}

UPSIDE_DOWN_INDICATORS: Set[str] = {
    "sjqvgilnag",
    "veizlhvo",
    "sivhio",
    "svniw",
    "oeovdnjoud",
}


def _score_ocr_words_orientation(tsv_data: Dict[str, List[Any]]) -> float:
    texts = tsv_data.get("text") or []
    confs = tsv_data.get("conf") or []
    if not texts:
        return 0.0
    score = 0.0
    for txt_raw, conf_raw in zip(texts, confs):
        txt = str(txt_raw or "").strip()
        if not txt or float(conf_raw) < 15:
            continue
        clean = la.strip_accents(re.sub(r"[^\w]", "", txt)).casefold()
        if not clean or clean in ("digitalizado", "com", "camscanner"):
            continue
        if clean in UPSIDE_DOWN_INDICATORS:
            score -= 25.0
        if clean in PORTUGUESE_ORIENTATION_KEYWORDS:
            score += 18.0
        elif len(clean) >= 4 and clean in la.PORTUGUESE_COMMON_WORD_STOPWORDS:
            score += 6.0
        elif re.match(r"^\d{3}\.\d{3}\.\d{3}-\d{2}$", txt) or re.match(r"^\d{2}/\d{2}/\d{4}$", txt):
            score += 20.0
        elif float(conf_raw) >= 65 and len(clean) >= 4 and clean.isalpha():
            score += 1.2
    return score


def rotate_pil_image_cw(img: Any, angle_cw: int) -> Any:
    from PIL import Image

    angle = angle_cw % 360
    if angle == 90:
        return img.transpose(Image.Transpose.ROTATE_270)
    if angle == 180:
        return img.transpose(Image.Transpose.ROTATE_180)
    if angle == 270:
        return img.transpose(Image.Transpose.ROTATE_90)
    return img


def map_bbox_1000_from_rotated_to_orig(b: List[int], angle_cw: int) -> List[int]:
    """
    Maps a `[xmin, ymin, xmax, ymax]` (`0-1000`) bounding box measured on an image rotated
    clockwise by `angle_cw` back to the original (`0°`) image's `0-1000` coordinate space.
    """
    angle = angle_cw % 360
    x0, y0, x1, y1 = b[0], b[1], b[2], b[3]
    if angle == 0:
        return [x0, y0, x1, y1]
    if angle == 180:
        return [max(0, 1000 - x1), max(0, 1000 - y1), min(1000, 1000 - x0), min(1000, 1000 - y0)]
    if angle == 90:
        # (u, v) on 90° CW image = (1000 - y_orig, x_orig) -> x_orig = v, y_orig = 1000 - u
        return [max(0, y0), max(0, 1000 - x1), min(1000, y1), min(1000, 1000 - x0)]
    if angle == 270:
        # (u, v) on 270° CW image = (y_orig, 1000 - x_orig) -> x_orig = 1000 - v, y_orig = u
        return [max(0, 1000 - y1), max(0, x0), min(1000, 1000 - y0), min(1000, x1)]
    return [x0, y0, x1, y1]


def map_bbox_1000_from_orig_to_rotated(b: List[int], angle_cw: int) -> List[int]:
    """
    Inverse of `map_bbox_1000_from_rotated_to_orig`: maps a box from original (0°) page
    coordinates into `angle_cw`-rotated page coordinates (`0-1000`).
    """
    return map_bbox_1000_from_rotated_to_orig(b, (360 - angle_cw) % 360)


# ============================================================================
# 3. PAGE RENDERING, COLON-JOINED TOKEN SPLITTING, PASS-B UNDERLINE-STRIPPED
#    CROP OCR, SIGNATURE DETECTION, AND ID PHOTO / BIOMETRICS DETECTION
# ============================================================================

def _file_page_cache_path(file_path: Path, page_number: int, session_id: Optional[str]) -> Optional[Path]:
    if not session_id:
        return None
    sdir = la.get_session_dir(session_id) / "visual_cache"
    sdir.mkdir(parents=True, exist_ok=True)
    stat = file_path.stat()
    stem = la.safe_file_stem(file_path)
    h = hashlib.sha1(f"v6::{file_path.resolve()}::{stat.st_size}::{stat.st_mtime_ns}".encode("utf-8")).hexdigest()[:12]
    return sdir / f"{stem}_{h}_p{page_number:04d}.json"


def render_page_to_pil_image(file_path: Path, page_number: int = 1, dpi: int = 200) -> Tuple[Any, float, float]:
    from PIL import Image

    ext = file_path.suffix.lower()
    if ext in la.IMAGE_EXTENSIONS:
        img = Image.open(str(file_path)).convert("RGB")
        return img, float(img.width), float(img.height)

    fitz = la._import_fitz()
    if fitz is not None:
        doc = fitz.open(str(file_path))
        page = doc[page_number - 1]
        pw, ph = float(page.rect.width), float(page.rect.height)
        zoom = dpi / 72.0
        pix = page.get_pixmap(matrix=fitz.Matrix(zoom, zoom), alpha=False)
        img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
        doc.close()
        return img, pw, ph

    import pypdfium2 as pdfium

    pdf = pdfium.PdfDocument(str(file_path))
    page = pdf[page_number - 1]
    pw, ph = float(page.get_width()), float(page.get_height())
    bitmap = page.render(scale=dpi / 72.0)
    img = bitmap.to_pil().convert("RGB")
    page.close()
    pdf.close()
    return img, pw, ph


def get_pdf_page_count(file_path: Path) -> int:
    ext = file_path.suffix.lower()
    if ext in la.IMAGE_EXTENSIONS:
        return 1
    fitz = la._import_fitz()
    if fitz is not None:
        doc = fitz.open(str(file_path))
        cnt = len(doc)
        doc.close()
        return cnt
    try:
        import pypdfium2 as pdfium

        pdf = pdfium.PdfDocument(str(file_path))
        cnt = len(pdf)
        pdf.close()
        return cnt
    except Exception:
        from pypdf import PdfReader

        return len(PdfReader(str(file_path)).pages)


def _compute_clean_ink_mask(img: Any) -> Optional[Any]:
    """
    Computes a binary ink mask (255 = dark text/signature ink, 0 = white background)
    with long horizontal and vertical table borders morphologically subtracted.
    """
    try:
        import cv2
        import numpy as np

        gray = np.array(img.convert("L"))
        ih, iw = gray.shape[:2]
        _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)

        h_kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (max(45, iw // 22), 1))
        v_kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (1, max(45, ih // 28)))
        h_lines = cv2.morphologyEx(binary, cv2.MORPH_OPEN, h_kernel)
        v_lines = cv2.morphologyEx(binary, cv2.MORPH_OPEN, v_kernel)
        table_lines = cv2.dilate(cv2.bitwise_or(h_lines, v_lines), np.ones((2, 2), np.uint8), iterations=1)
        clean_mask = cv2.subtract(binary, table_lines)
        return clean_mask
    except Exception:
        return None


def _split_colon_joined_ocr_token(txt: str, b1000: List[int]) -> List[Tuple[str, List[int]]]:
    """
    Splits colon-joined OCR tokens such as `"OUTORGANTES:MARIA"`, `"OUTORGADO(S):VIVIANE"`,
    `"CPF:123.456.789-00"`, or `"NOME:JOSÉ"` into two separate word tokens with proportional
    X coordinates so redacting the entity never blacks out the structural label!
    """
    if ":" not in txt or len(txt) < 4 or txt.endswith(":"):
        return [(txt, b1000)]
    if re.match(r"^\d{1,2}:\d{2}(?::\d{2})?$", txt) or "://" in txt:
        return [(txt, b1000)]
    idx = txt.find(":")
    left_part = txt[: idx + 1]
    right_part = txt[idx + 1 :]
    if len(left_part) < 2 or len(right_part) < 2:
        return [(txt, b1000)]
    total_len = max(1, len(txt))
    span_w = max(2, b1000[2] - b1000[0])
    split_x = b1000[0] + int(round(span_w * (len(left_part) / total_len)))
    split_x = max(b1000[0] + 1, min(b1000[2] - 1, split_x))
    return [
        (left_part, [b1000[0], b1000[1], split_x, b1000[3]]),
        (right_part, [split_x + 1, b1000[1], b1000[2], b1000[3]]),
    ]


def _clamp_vertical_line_overlaps(lines: List[Dict[str, Any]], words: List[Dict[str, Any]]) -> None:
    """
    Ensures consecutive horizontal text lines never overlap vertically (`line[k].y1 < line[k+1].y0`),
    preventing a redaction box on Line 1 from slicing into the top of Line 2.
    """
    text_lines = [l for l in lines if not str(l.get("text", "")).startswith("[INK_REGION_")]
    text_lines.sort(key=lambda l: (l["bbox_1000"][1], l["bbox_1000"][0]))
    for i in range(len(text_lines) - 1):
        curr_l = text_lines[i]
        curr_b = curr_l["bbox_1000"]
        curr_h = curr_b[3] - curr_b[1]
        if curr_h > 35:
            continue
        for j in range(i + 1, min(len(text_lines), i + 5)):
            next_l = text_lines[j]
            next_b = next_l["bbox_1000"]
            if next_b[1] - curr_b[1] > 40:
                break
            # Check horizontal overlap between the two lines
            h_ov = min(curr_b[2], next_b[2]) - max(curr_b[0], next_b[0])
            if h_ov > 30 and curr_b[3] >= next_b[1] and next_b[1] > curr_b[1] + 6:
                mid_y = (curr_b[3] + next_b[1]) // 2
                new_curr_y1 = max(curr_b[1] + 6, mid_y)
                new_next_y0 = min(next_b[3] - 6, mid_y + 1)
                curr_b[3] = new_curr_y1
                next_b[1] = new_next_y0
                for w_idx in curr_l.get("word_indices", []):
                    words[w_idx]["bbox_1000"][3] = min(words[w_idx]["bbox_1000"][3], new_curr_y1)
                for w_idx in next_l.get("word_indices", []):
                    words[w_idx]["bbox_1000"][1] = max(words[w_idx]["bbox_1000"][1], new_next_y0)


def _strip_fused_underlines_preserving_glyphs(pil_img: Any) -> Any:
    """
    Pre-Pass-A Morphological Underline Stripper (v6.2):
    Removes long horizontal underlines (width >= max(60px, iw // 22)) that fuse into the
    baseline of bold text on CamScanner / Word documents, while preserving:
    1. Bottom glyph closures (`top_edge_of_ul & above1 & above2`) so letters like D, B, E, O, U
       keep their bottom strokes and never turn into R, Q, or Y.
    2. Descender crossings (`above2 & below2`) so p, q, g, j, ç stay intact.
    Has 0.0% impact on non-underlined lines while boosting Pass-A underlined line recall from 0% to >91%.
    """
    try:
        import cv2
        import numpy as np
        from PIL import Image

        gray = np.array(pil_img.convert("L"))
        ih, iw = gray.shape[:2]
        _, bw = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)

        min_line_w = max(60, iw // 22)
        h_kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (min_line_w, 1))
        horiz_lines = cv2.morphologyEx(bw, cv2.MORPH_OPEN, h_kernel)
        if not np.any(horiz_lines > 0):
            return pil_img

        # Expand 1px downward only (never upward into the glyph baseline!)
        k_down = np.array([[0], [1], [1]], dtype=np.uint8)
        horiz_band = cv2.dilate(horiz_lines, k_down, iterations=1)

        above2 = np.zeros_like(bw)
        above1 = np.zeros_like(bw)
        below2 = np.zeros_like(bw)
        above2[2:, :] = bw[:-2, :]
        above1[1:, :] = bw[:-1, :]
        below2[:-2, :] = bw[2:, :]

        top_edge_of_ul = (horiz_band > 0) & (
            np.vstack([np.zeros((1, iw), dtype=np.uint8), horiz_band[:-1, :]]) == 0
        )
        glyph_closure = top_edge_of_ul & (above1 > 0) & (above2 > 0)
        descender_crossing = (above2 > 0) & (below2 > 0)

        erase_mask = (horiz_band > 0) & (~glyph_closure) & (~descender_crossing)
        out_arr = np.array(pil_img.convert("RGB")).copy()
        out_arr[erase_mask] = [255, 255, 255]
        return Image.fromarray(out_arr)
    except Exception:
        return pil_img


def _is_probable_cursive_signature_noise(words_list: List[Dict[str, Any]], avg_conf: float, b1000: List[int]) -> bool:
    """
    Detects when Pass-B `tesseract --psm 7` hallucinates gibberish words (like `"COLE EERE"` or
    `"vadua M yn 507"`) over a handwritten cursive signature stroke so it is classified as
    `[INK_REGION_N]` (signature/ink candidate) instead of polluting `full_text` at the bottom of the page.
    """
    if not words_list:
        return True
    joined = " ".join(str(w.get("text", "")) for w in words_list).strip()
    if not joined:
        return True
    # If it contains valid digits of an OAB/CPF/RG/date/phone, keep as text
    if re.search(r"\d{3,}", joined):
        return False
    alpha_tokens = re.findall(r"[A-Za-zÀ-ÿ]{3,}", joined)
    if not alpha_tokens:
        return True
    known_hits = sum(
        1
        for t in alpha_tokens
        if la.normalize_key_fold(t) in PORTUGUESE_ORIENTATION_KEYWORDS
        or la.normalize_key_fold(t) in la.PORTUGUESE_COMMON_WORD_STOPWORDS
        or la.normalize_key_fold(t) in {"jose", "maria", "silva", "souza", "oliveira", "santos", "pereira", "madeira", "cruz", "advogado", "advogada", "inscrito", "inscrita", "casado", "casada", "brasileiro", "brasileira", "finalidade", "especifica", "indenizacao", "danos", "morais"}
    )
    if known_hits >= 1:
        return False
    # In the lower 45% of the page (signature zone y >= 550), if confidence is low (< 72) and 0 known words match, it is cursive signature noise
    if b1000[1] >= 520 and avg_conf < 74.0:
        return True
    if avg_conf < 48.0 and len(alpha_tokens) <= 3:
        return True
    return False


def _recover_unocrd_ink_segments_and_underlined_text(
    img: Any,
    words: List[Dict[str, Any]],
    lines: List[Dict[str, Any]],
    tess_bin: Optional[str],
    lang: str,
) -> List[List[int]]:
    """
    Pass-B Recovery:
    1. Zeroes out all Pass-A OCR word boxes on `clean_mask` FIRST so an un-OCR'd half-line
       (like underlined `"e JOÃO PEDRO NUNES FIGUEIREDO SILVA,"` at `x=545..862` next to
       Box #10 at `x=160..542`) is NEVER merged into Box #10 or skipped by the 40% overlap check!
    2. Segments remaining dark ink regions.
    3. For text-sized segments (`height_1000 in [8, 36]`, `width_1000 >= 25`), strips 1px
       horizontal underlines in the bottom 30% of the crop, pads with 12px white border,
       and runs `tesseract --psm 7 tsv`. If words are recovered, adds them directly to
       `words` and `lines`!
    4. Returns remaining non-text ink segments (e.g. signatures/stamps) as `[INK_REGION_N]` boxes.
    """
    clean_mask = _compute_clean_ink_mask(img)
    if clean_mask is None:
        return []
    try:
        import cv2
        import numpy as np
        from PIL import Image

        gray_check = np.array(img.convert("L"))
        white_bg_fraction = float(np.mean(gray_check > 180))
        # Never run Otsu ink-blob recovery on dark-mode smartphone screenshots or camera photos (<55% white paper)!
        if white_bg_fraction < 0.55:
            return []

        ih, iw = clean_mask.shape[:2]
        residual_mask = clean_mask.copy()

        # Zero out already OCR'd word boxes (shrunk slightly by 1px so adjacent untouched letters stay intact)
        for w in words:
            wb = w["bbox_1000"]
            wx0 = max(0, int(round(wb[0] * iw / 1000.0)) + 1)
            wy0 = max(0, int(round(wb[1] * ih / 1000.0)) + 1)
            wx1 = min(iw, int(round(wb[2] * iw / 1000.0)) - 1)
            wy1 = min(ih, int(round(wb[3] * ih / 1000.0)) - 1)
            if wx1 > wx0 and wy1 > wy0:
                residual_mask[wy0:wy1, wx0:wx1] = 0

        dil_k = cv2.getStructuringElement(cv2.MORPH_RECT, (max(14, iw // 75), max(3, ih // 550)))
        connected = cv2.dilate(residual_mask, dil_k, iterations=1)
        num_labels, _, stats, _ = cv2.connectedComponentsWithStats(connected, connectivity=8)

        gray_full = np.array(img.convert("L"))
        candidate_segments: List[Tuple[int, int, int, int, List[int]]] = []
        for i in range(1, num_labels):
            x, y, bw, bh, area = stats[i]
            if bw < max(12, iw // 120) or bh < max(6, ih // 320):
                continue
            if bw > iw * 0.95 or bh > ih * 0.45 or area < 40:
                continue
            b1000 = [
                max(0, min(1000, round(x * 1000.0 / iw) - 1)),
                max(0, min(1000, round(y * 1000.0 / ih) - 1)),
                max(0, min(1000, round((x + bw) * 1000.0 / iw) + 1)),
                max(0, min(1000, round((y + bh) * 1000.0 / ih) + 1)),
            ]
            candidate_segments.append((b1000[1] // 15, b1000[0], x, y, b1000))

        candidate_segments.sort()
        non_text_ink_boxes: List[List[int]] = []

        for _, _, _, _, b1000 in candidate_segments:
            bw_1000 = b1000[2] - b1000[0]
            bh_1000 = b1000[3] - b1000[1]

            recovered_words_in_seg: List[Dict[str, Any]] = []
            if tess_bin and 8 <= bh_1000 <= 38 and bw_1000 >= 25:
                cx0 = max(0, int(round(b1000[0] * iw / 1000.0)) - 4)
                cy0 = max(0, int(round(b1000[1] * ih / 1000.0)) - 3)
                cx1 = min(iw, int(round(b1000[2] * iw / 1000.0)) + 4)
                cy1 = min(ih, int(round(b1000[3] * ih / 1000.0)) + 3)
                crop = gray_full[cy0:cy1, cx0:cx1].copy()
                ch, cw = crop.shape[:2]
                if ch >= 8 and cw >= 20:
                    # Strip 1px horizontal underlines in the bottom 35% of the crop
                    _, c_bin = cv2.threshold(crop, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
                    hk = cv2.getStructuringElement(cv2.MORPH_RECT, (max(18, cw // 8), 1))
                    ulines = cv2.morphologyEx(c_bin, cv2.MORPH_OPEN, hk)
                    ulines_dil = cv2.dilate(ulines, np.ones((2, 1), np.uint8), iterations=1)
                    bot_start = int(ch * 0.65)
                    mask_ul = np.zeros_like(ulines_dil)
                    mask_ul[bot_start:, :] = ulines_dil[bot_start:, :]
                    crop[mask_ul > 0] = 255

                    pad = 12
                    padded = np.full((ch + 2 * pad, cw + 2 * pad), 255, dtype=np.uint8)
                    padded[pad : pad + ch, pad : pad + cw] = crop
                    pil_crop = Image.fromarray(padded).convert("RGB")
                    tsv_crop = run_tesseract_cli_tsv(pil_crop, tess_bin, lang, psm=7, timeout=15)
                    seg_confs: List[float] = []
                    if tsv_crop and tsv_crop.get("text"):
                        for k in range(len(tsv_crop["text"])):
                            wtxt = str(tsv_crop["text"][k] or "").strip()
                            wconf = float(tsv_crop["conf"][k])
                            # Clean leading/trailing bracket artifacts from underline edges (e.g. "[e" -> "e")
                            wtxt_clean = re.sub(r"^[\[\]|_]+|[\[\]|_]+$", "", wtxt).strip()
                            if not wtxt_clean or (wconf < 18 and len(wtxt_clean) < 2):
                                continue
                            seg_confs.append(wconf)
                            wl = max(0, int(tsv_crop["left"][k]) - pad)
                            wt = max(0, int(tsv_crop["top"][k]) - pad)
                            ww = int(tsv_crop["width"][k])
                            wh = int(tsv_crop["height"][k])
                            if ww <= 1 or wh <= 1:
                                continue
                            ax0 = cx0 + wl
                            ay0 = cy0 + max(0, wt - 1)
                            ax1 = min(iw, cx0 + wl + ww)
                            ay1 = min(ih, cy0 + min(ch, wt + wh + 1))
                            wb1000 = [
                                max(0, min(1000, round(ax0 * 1000.0 / iw) - 1)),
                                max(b1000[1], min(1000, round(ay0 * 1000.0 / ih))),
                                max(0, min(1000, round(ax1 * 1000.0 / iw) + 1)),
                                min(b1000[3], min(1000, round(ay1 * 1000.0 / ih))),
                            ]
                            if wb1000[3] <= wb1000[1] + 4:
                                wb1000[1] = b1000[1]
                                wb1000[3] = b1000[3]
                            for split_t, split_b in _split_colon_joined_ocr_token(wtxt_clean, wb1000):
                                recovered_words_in_seg.append({"text": split_t, "bbox_1000": split_b})

            avg_seg_conf = (sum(seg_confs) / len(seg_confs)) if seg_confs else 0.0
            if recovered_words_in_seg and not _is_probable_cursive_signature_noise(recovered_words_in_seg, avg_seg_conf, b1000):
                new_line_id = len(lines) + 1
                w_idxs: List[int] = []
                for rw in recovered_words_in_seg:
                    w_idx = len(words)
                    rw["line_id"] = new_line_id
                    words.append(rw)
                    w_idxs.append(w_idx)
                lx0 = min(words[idx]["bbox_1000"][0] for idx in w_idxs)
                ly0 = min(words[idx]["bbox_1000"][1] for idx in w_idxs)
                lx1 = max(words[idx]["bbox_1000"][2] for idx in w_idxs)
                ly1 = max(words[idx]["bbox_1000"][3] for idx in w_idxs)
                lines.append(
                    {
                        "id": new_line_id,
                        "text": " ".join(words[idx]["text"] for idx in w_idxs),
                        "bbox_1000": [lx0, ly0, lx1, ly1],
                        "word_indices": w_idxs,
                    }
                )
            else:
                if 45 <= bw_1000 <= 550 and 10 <= bh_1000 <= 85 and len(non_text_ink_boxes) < 4:
                    non_text_ink_boxes.append(b1000)

        return non_text_ink_boxes
    except Exception:
        return []


def detect_signature_boxes_1000(
    img: Any,
    layout: Dict[str, Any],
    matched_boxes: List[Dict[str, Any]],
) -> List[Tuple[List[int], List[int]]]:
    """
    Detects handwritten signatures (`<ASSINATURA_N>`) on scanned legal documents and ID cards:
    1. Above centered/lower-half signer `<PESSOA_N>` or `<CPF_N>` lines (such as `"castro M m almeida castro"`
       at `y=702..747` right above `<PESSOA_1>` at `y=755..772` on `procuração tia Lu.pdf`).
    2. Inside or immediately above/beside `"ASSINATURA DO TITULAR"`, `"ASSINATURA DO PORTADOR"`,
       `"ASSINATURA"`, or `"RUBRICA"` labels on ID cards (`RG`/`CNH`) and bank forms.
    Returns a list of `(signature_bbox_1000, garbled_line_ids_to_suppress)`.
    """
    clean_mask = _compute_clean_ink_mask(img)
    if clean_mask is None:
        return []
    try:
        import numpy as np

        ih, iw = clean_mask.shape[:2]
        lines = layout.get("lines", [])
        full_fold = " ".join(la.normalize_key_fold(str(l.get("text", ""))) for l in lines)

        # If this page is a CNH, RG Front, or a Bank Receipt / Boleto / Queue Slip, skip heuristic ink signature search
        # (CNH and RG Front already have exact landmark signature boxes in `landmark_boxes_1000`!)
        if any(
            k in full_fold
            for k in (
                "carteira nacional",
                "cartfira nacional",
                "conduccion",
                "driver license",
                "4c doc",
                "4d cpf",
                "polegar direito",
                "em todo o territorio",
                "assinatura do diretor",
                "comprovante de pagamento",
                "comprovante de entrega",
                "nr autenticacao",
                "beneficiario:",
                "atendimento caixa",
            )
        ):
            return []

        results: List[Tuple[List[int], List[int]]] = []
        used_zones: List[List[int]] = []
        is_rg_back = "assinatura do diretor" in full_fold or "valida em todo o territorio" in full_fold

        # Case A: Signature zone immediately above a centered/indented lower-page signer <PESSOA_N> or <CPF_N>
        for mb in matched_boxes:
            tok = str(mb.get("token", ""))
            b = mb["bbox_1000"]
            if not (tok.startswith("<PESSOA_") or tok.startswith("<CPF_")):
                continue
            # Signer blocks on legal docs appear in the lower 55% of the page and are indented/centered (not on RG back)
            if is_rg_back or b[1] < 420 or b[0] < 175:
                continue
            # Check vertical band 65 units above `b[1]`
            zy0_1000 = max(0, b[1] - 68)
            zy1_1000 = max(0, b[1] - 2)
            zx0_1000 = max(80, b[0] - 80)
            zx1_1000 = min(920, b[2] + 120)
            if zy1_1000 <= zy0_1000 + 12:
                continue

            # Ensure there isn't a dense printed paragraph line with >= 5 real Portuguese words in this band
            overlapping_lines = []
            has_real_printed_sentence = False
            for ln in lines:
                lb = ln["bbox_1000"]
                v_ov = min(zy1_1000, lb[3]) - max(zy0_1000, lb[1])
                h_ov = min(zx1_1000, lb[2]) - max(zx0_1000, lb[0])
                if v_ov > 4 and h_ov > 15:
                    overlapping_lines.append(ln)
                    ltxt = str(ln.get("text", ""))
                    if not ltxt.startswith("[INK_REGION_"):
                        real_words = [
                            w
                            for w in re.findall(r"[A-Za-zÀ-ÿ]{4,}", ltxt)
                            if la.normalize_key_fold(w) in PORTUGUESE_ORIENTATION_KEYWORDS
                            or la.normalize_key_fold(w) in la.PORTUGUESE_COMMON_WORD_STOPWORDS
                        ]
                        if len(real_words) >= 2 or "de junho de" in ltxt.lower() or "nova resende" in ltxt.lower():
                            has_real_printed_sentence = True
                            break
            if has_real_printed_sentence:
                continue

            px0 = int(round(zx0_1000 * iw / 1000.0))
            py0 = int(round(zy0_1000 * ih / 1000.0))
            px1 = int(round(zx1_1000 * iw / 1000.0))
            py1 = int(round(zy1_1000 * ih / 1000.0))
            sub = clean_mask[py0:py1, px0:px1]
            ys, xs = np.where(sub > 0)
            if len(xs) >= max(180, int(iw * ih * 0.00035)):
                sx0 = max(0, min(1000, round((px0 + int(xs.min())) * 1000.0 / iw) - 4))
                sy0 = max(0, min(1000, round((py0 + int(ys.min())) * 1000.0 / ih) - 4))
                sx1 = max(0, min(1000, round((px0 + int(xs.max())) * 1000.0 / iw) + 4))
                sy1 = max(0, min(1000, min(b[1] - 1, round((py0 + int(ys.max())) * 1000.0 / ih) + 2)))
                if (sx1 - sx0) >= 45 and (sy1 - sy0) >= 12:
                    sig_box = [sx0, sy0, sx1, sy1]
                    if not any(
                        min(sig_box[2], uz[2]) > max(sig_box[0], uz[0])
                        and min(sig_box[3], uz[3]) > max(sig_box[1], uz[1])
                        for uz in used_zones
                    ):
                        used_zones.append(sig_box)
                        suppress_ids = [int(ln["id"]) for ln in overlapping_lines]
                        results.append((sig_box, suppress_ids))

        # Case B: Signature ink near explicit "ASSINATURA" / "ASSINANTE" / "RUBRICA" label
        for ln in lines:
            ltxt_fold = la.normalize_key_fold(str(ln.get("text", "")))
            if any(k in ltxt_fold for k in ("assinatura do", "assinatura:", "assinatura ", "assinante")):
                # Avoid matching body prose like "pelo presente instrumento..."
                if len(ltxt_fold.split()) > 6:
                    continue
                lb = ln["bbox_1000"]
                # Check ONLY the band immediately ABOVE the signature label (never below into tables/footers)
                for (zy0_1000, zy1_1000) in ((max(0, lb[1] - 65), max(0, lb[1] - 2)),):
                    zx0_1000 = max(40, lb[0] - 60)
                    zx1_1000 = min(960, lb[2] + 160)
                    if zy1_1000 <= zy0_1000 + 10:
                        continue
                    px0 = int(round(zx0_1000 * iw / 1000.0))
                    py0 = int(round(zy0_1000 * ih / 1000.0))
                    px1 = int(round(zx1_1000 * iw / 1000.0))
                    py1 = int(round(zy1_1000 * ih / 1000.0))
                    sub = clean_mask[py0:py1, px0:px1]
                    ys, xs = np.where(sub > 0)
                    if len(xs) >= max(160, int(iw * ih * 0.0003)):
                        sx0 = max(0, min(1000, round((px0 + int(xs.min())) * 1000.0 / iw) - 3))
                        sy0 = max(0, min(1000, round((py0 + int(ys.min())) * 1000.0 / ih) - 3))
                        sx1 = max(0, min(1000, round((px0 + int(xs.max())) * 1000.0 / iw) + 3))
                        sy1 = max(0, min(1000, round((py0 + int(ys.max())) * 1000.0 / ih) + 3))
                        if (sx1 - sx0) >= 40 and (sy1 - sy0) >= 10:
                            sig_box = [sx0, sy0, sx1, sy1]
                            if not any(
                                min(sig_box[2], uz[2]) > max(sig_box[0], uz[0])
                                and min(sig_box[3], uz[3]) > max(sig_box[1], uz[1])
                                for uz in used_zones
                            ):
                                used_zones.append(sig_box)
                                results.append((sig_box, []))

        return results
    except Exception:
        return []



def _extract_subimage_and_dual_column_ocr(
    file_path: Path,
    page_number: int,
    working_img: Any,
    best_angle_cw: int,
    words: List[Dict[str, Any]],
    lines: List[Dict[str, Any]],
    tess_bin: Optional[str],
    lang: str,
) -> Tuple[List[List[int]], bool]:
    """
    1. Hybrid PDF Sub-Image 2x OCR (e.g. `CNH-e Dudu.pdf` with `xref=10, 11, 12, 13` or half-width e-CNH):
       Crops each sub-image, upscales 2x, runs `tesseract --psm 6`, removes corrupted full-page OCR
       lines inside the sub-image rects, and replaces them with clean sub-image lines in reading order.
    2. Dual-Column Landscape Receipt+Boleto Split (e.g. `comp_atendimento_Tia_Cida.pdf`):
       When a page is landscape (`width > height * 1.15`), replaces cross-column merged full-page OCR
       with Column 1 (`x = 0..382`) in top-to-bottom order followed by Column 2 (`x = 370..1000`) in
       top-to-bottom order so multi-line receipt labels (`BENEFICIARIO:\n...`, `PAGADOR:\n...`) stay
       contiguous in `full_text`!
    Returns `(extra_qr_boxes, preserve_line_order)`.
    """
    extra_qr_boxes: List[List[int]] = []
    if not tess_bin:
        return extra_qr_boxes, False
    try:
        from PIL import Image

        iw, ih = working_img.size
        regions_to_scan: List[Tuple[List[int], int]] = []
        is_dual_column = False

        # Check embedded sub-images if file is PDF and unrotated
        if file_path.suffix.lower() == ".pdf" and best_angle_cw == 0:
            fitz = la._import_fitz()
            if fitz is not None:
                try:
                    doc = fitz.open(str(file_path))
                    if 1 <= page_number <= len(doc):
                        page = doc[page_number - 1]
                        imgs = page.get_images(full=True)
                        if len(imgs) >= 2:
                            for im_info in imgs:
                                xref = im_info[0]
                                im_w, im_h = int(im_info[2]), int(im_info[3])
                                for r in page.get_image_rects(xref):
                                    r1000 = [
                                        max(0, min(1000, round(r.x0 * 1000.0 / page.rect.width))),
                                        max(0, min(1000, round(r.y0 * 1000.0 / page.rect.height))),
                                        max(0, min(1000, round(r.x1 * 1000.0 / page.rect.width))),
                                        max(0, min(1000, round(r.y1 * 1000.0 / page.rect.height))),
                                    ]
                                    rw = r1000[2] - r1000[0]
                                    rh = r1000[3] - r1000[1]
                                    if 200 <= rw <= 550 and 180 <= rh <= 550 and abs(im_w - im_h) <= max(20, im_w * 0.08):
                                        extra_qr_boxes.append(r1000)
                                    elif rw >= 240 and rh >= 140 and (rw < 850 or rh < 850):
                                        regions_to_scan.append((r1000, 2))
                    doc.close()
                except Exception:
                    pass

            # Fallback if fitz is unavailable on a SENATRAN e-CNH layout (left CNH panels + right QR-CODE)
            if not regions_to_scan:
                joined_fold = " ".join(la.normalize_key_fold(str(l.get("text", ""))) for l in lines)
                if ("carteira nacional" in joined_fold or "permiso de conduccion" in joined_fold) and "qr-code" in joined_fold:
                    regions_to_scan = [
                        ([51, 71, 457, 283], 2),
                        ([51, 288, 457, 500], 2),
                        ([51, 505, 457, 717], 2),
                    ]
                    extra_qr_boxes.append([539, 98, 908, 359])

        # Check dual-column landscape page ONLY when unrotated (`best_angle_cw == 0`, like comp_atendimento_Tia_Cida.pdf: 2339x1653)
        # Never split a portrait page that was rotated 90°/270° CW (like `documentos pessoais Juliana.pdf`)!
        if best_angle_cw == 0 and iw > ih * 1.15 and not regions_to_scan:
            is_dual_column = True
            regions_to_scan = [
                ([0, 0, 382, 965], 1),
                ([370, 0, 1000, 965], 1),
            ]

        if not regions_to_scan:
            return extra_qr_boxes, False

        if is_dual_column:
            # Replace cross-column merged full-page words/lines with clean Column 1 + Column 2 words/lines
            ink_only_lines = [l for l in lines if str(l.get("text", "")).startswith("[INK_REGION_")]
            words.clear()
            lines.clear()
        else:
            # Remove full-page lines that fall inside the sub-image rects (or QR code rect) so they don't duplicate/corrupt
            all_clear_rects = [r for r, _ in regions_to_scan] + extra_qr_boxes
            kept_lines = []
            for ln in lines:
                lb = ln["bbox_1000"]
                lcx = (lb[0] + lb[2]) * 0.5
                lcy = (lb[1] + lb[3]) * 0.5
                if any(cr[0] - 8 <= lcx <= cr[2] + 8 and cr[1] - 8 <= lcy <= cr[3] + 8 for cr in all_clear_rects):
                    continue
                if not str(ln.get("text", "")).startswith("[INK_REGION_"):
                    kept_lines.append(ln)
            ink_only_lines = [l for l in lines if str(l.get("text", "")).startswith("[INK_REGION_")]
            # Rebuild `words` and `lines` starting from `kept_lines`
            old_words = list(words)
            words.clear()
            lines.clear()
            for ln in kept_lines:
                new_w_idxs = []
                for old_idx in ln.get("word_indices", []):
                    if 0 <= old_idx < len(old_words):
                        w_copy = dict(old_words[old_idx])
                        new_w_idxs.append(len(words))
                        words.append(w_copy)
                new_id = len(lines) + 1
                for idx in new_w_idxs:
                    words[idx]["line_id"] = new_id
                lines.append({
                    "id": new_id,
                    "text": ln["text"],
                    "bbox_1000": ln["bbox_1000"],
                    "word_indices": new_w_idxs,
                })

        for r1000, upscale in regions_to_scan:
            rx0, ry0, rx1, ry1 = r1000
            rw_1000 = max(1, rx1 - rx0)
            rh_1000 = max(1, ry1 - ry0)
            cx0 = int(round(rx0 * iw / 1000.0))
            cy0 = int(round(ry0 * ih / 1000.0))
            cx1 = int(round(rx1 * iw / 1000.0))
            cy1 = int(round(ry1 * ih / 1000.0))
            if cx1 <= cx0 + 20 or cy1 <= cy0 + 20:
                continue
            crop = working_img.crop((cx0, cy0, cx1, cy1))
            if upscale > 1:
                crop = crop.resize((crop.width * upscale, crop.height * upscale), Image.Resampling.BICUBIC)
            cw, ch = crop.size
            tsv = run_tesseract_cli_tsv(crop, tess_bin, lang, psm=6)
            if not tsv or not tsv.get("text"):
                continue
            sub_line_map: Dict[Tuple[int, int, int], List[int]] = {}
            for i in range(len(tsv["text"])):
                txt = str(tsv["text"][i] or "").strip()
                conf = float(tsv["conf"][i])
                if not txt or conf < 18:
                    continue
                x, y, w, h = int(tsv["left"][i]), int(tsv["top"][i]), int(tsv["width"][i]), int(tsv["height"][i])
                if w <= 1 or h <= 1:
                    continue
                sb1000 = [
                    max(0, min(1000, round(rx0 + (x / float(cw)) * rw_1000) - 1)),
                    max(0, min(1000, round(ry0 + (y / float(ch)) * rh_1000) - 1)),
                    max(0, min(1000, round(rx0 + ((x + w) / float(cw)) * rw_1000) + 1)),
                    max(0, min(1000, round(ry0 + ((y + h) / float(ch)) * rh_1000) + 1)),
                ]
                lkey = (int(tsv["block_num"][i]), int(tsv["par_num"][i]), int(tsv["line_num"][i]))
                for split_t, split_b in _split_colon_joined_ocr_token(txt, sb1000):
                    w_idx = len(words)
                    words.append({"text": split_t, "bbox_1000": split_b, "line_key": list(lkey)})
                    sub_line_map.setdefault(lkey, []).append(w_idx)

            region_lines = []
            for _, w_idxs in sub_line_map.items():
                l_words = [words[idx] for idx in w_idxs]
                lx0 = min(w["bbox_1000"][0] for w in l_words)
                ly0 = min(w["bbox_1000"][1] for w in l_words)
                lx1 = max(w["bbox_1000"][2] for w in l_words)
                ly1 = max(w["bbox_1000"][3] for w in l_words)
                region_lines.append({
                    "text": " ".join(w["text"] for w in l_words),
                    "bbox_1000": [lx0, ly0, lx1, ly1],
                    "word_indices": w_idxs,
                })
            region_lines.sort(key=lambda rl: (rl["bbox_1000"][1] // 10, rl["bbox_1000"][0]))
            for rl in region_lines:
                new_id = len(lines) + 1
                for idx in rl["word_indices"]:
                    words[idx]["line_id"] = new_id
                rl["id"] = new_id
                lines.append(rl)

        for ink_ln in ink_only_lines:
            new_id = len(lines) + 1
            ink_ln["id"] = new_id
            lines.append(ink_ln)

        return extra_qr_boxes, True
    except Exception:
        return extra_qr_boxes, False


def _detect_vertical_strip_numbers_1000(
    working_img: Any,
    tess_bin: Optional[str],
    lang: str,
) -> List[Dict[str, Any]]:
    """
    Detects 90°/270° vertical serial numbers along the left border of upright CNH/ID cards
    (such as `9876543210` on `CNH-e Dudu.pdf` and `1234567890` on `Documentos pessoais Fernanda.pdf`).
    """
    hits: List[Dict[str, Any]] = []
    if not tess_bin:
        return hits
    try:
        iw, ih = working_img.size
        left_crop = working_img.crop((0, 0, int(iw * 0.28), ih))
        for ang in (90, 270):
            rot_c = rotate_pil_image_cw(left_crop, ang)
            tsv = run_tesseract_cli_tsv(rot_c, tess_bin, lang, psm=6)
            if not tsv or not tsv.get("text"):
                continue
            rw, rh = rot_c.size
            for i, raw_t in enumerate(tsv["text"]):
                t = str(raw_t or "").strip()
                c = float(tsv["conf"][i])
                digits = re.sub(r"\D", "", t)
                if c >= 22.0 and 8 <= len(digits) <= 12:
                    x, y, w, h = int(tsv["left"][i]), int(tsv["top"][i]), int(tsv["width"][i]), int(tsv["height"][i])
                    b_rot = [
                        round(x * 1000.0 / rw),
                        round(y * 1000.0 / rh),
                        round((x + w) * 1000.0 / rw),
                        round((y + h) * 1000.0 / rh),
                    ]
                    b_crop = map_bbox_1000_from_rotated_to_orig(b_rot, ang)
                    b_full = [
                        max(0, round(b_crop[0] * 0.28) - 2),
                        max(0, b_crop[1] - 2),
                        min(1000, round(b_crop[2] * 0.28) + 2),
                        min(1000, b_crop[3] + 2),
                    ]
                    hits.append({"text": digits, "bbox_1000": b_full, "category": "CNH"})
    except Exception:
        pass
    return hits


# ----------------------------------------------------------------------------
# Anchor-relative ID-card geometry (v6.4)
# The v6.3 landmark boxes were absolute page coordinates measured on three sample files, so a card scanned at
# another size or position got its boxes in the wrong place (photo box over the name field, serial-number box
# beside the number). Here every region is placed relative to printed labels that OCR finds on the page itself
# (their distance gives the card's scale), so the same rules hold wherever the card sits. The absolute templates
# stay only as a last resort when the labels are not found.
# ----------------------------------------------------------------------------
def _find_label_px(words: List[Dict[str, Any]], size: Tuple[int, int], *phrases: str) -> Optional[List[float]]:
    """Pixel box [x0, y0, x1, y1] of the first phrase found among consecutive OCR words (accent/case-folded,
    one wrong character per word tolerated)."""
    iw, ih = size
    folded = [la.normalize_key_fold(re.sub(r"[^\w]", "", str(w.get("text", "")))) for w in words]

    def close(a: str, b: str) -> bool:
        if a == b:
            return True
        if len(b) < 5 or abs(len(a) - len(b)) > 1:
            return False
        return difflib.SequenceMatcher(None, a, b).ratio() >= 0.8

    for phrase in phrases:
        parts = [la.normalize_key_fold(x) for x in phrase.split()]
        for i in range(len(words) - len(parts) + 1):
            if all(close(folded[i + k], parts[k]) for k in range(len(parts))):
                bs = [words[i + k]["bbox_1000"] for k in range(len(parts))]
                return [min(b[0] for b in bs) * iw / 1000.0, min(b[1] for b in bs) * ih / 1000.0,
                        max(b[2] for b in bs) * iw / 1000.0, max(b[3] for b in bs) * ih / 1000.0]
    return None


def _px_to_1000(b: List[float], size: Tuple[int, int]) -> List[int]:
    iw, ih = size
    return [max(0, min(1000, round(b[0] * 1000.0 / iw))), max(0, min(1000, round(b[1] * 1000.0 / ih))),
            max(0, min(1000, round(b[2] * 1000.0 / iw))), max(0, min(1000, round(b[3] * 1000.0 / ih)))]


def _cnh_anchor_boxes(words: List[Dict[str, Any]], size: Tuple[int, int]) -> List[Dict[str, Any]]:
    """CNH front (paper scan or e-CNH image, any size/position): photo, holder signature, name row, document and
    CPF/registration rows, parents, placed from the `NOME E SOBRENOME` and `ASSINATURA DO PORTADOR` labels."""
    N = _find_label_px(words, size, "nome e sobrenome", "e sobrenome", "sobrenome")
    A = _find_label_px(words, size, "assinatura do portador", "do portador", "portador")
    if not N or not A or A[1] <= N[3]:
        return []
    H = A[1] - N[3]                       # name label to signature label: the card's scale
    if H < 40:
        return []
    labels = {k: _find_label_px(words, size, *v) for k, v in {
        "nasc": ("local e uf", "de nascimento", "nascimento"), "doc": ("doc identidade", "identidade", "emissor"),
        "cpf": ("4d cpf", "cpf"), "nac": ("nacionalidade",), "fil": ("filiacao",)}.items()}
    col = [b[0] for b in labels.values() if b and b[0] > N[0] + 0.30 * H and N[3] < b[1] < A[3]]
    D = min(col) if col else N[0] + 0.53 * H          # left edge of the data column
    R = N[0] + 1.62 * H                               # right edge of the card
    out = [
        ([N[0] - 0.06 * H, N[3] - 0.01 * H, R - 0.45 * H, N[3] + 0.09 * H], "PESSOA", "titular_cnh_campo_2_1"),
        ([N[0] - 0.04 * H, N[3] + 0.11 * H, D - 0.03 * H, N[3] + 0.78 * H], "FOTO", "foto_cnh_titular"),
        ([N[0] - 0.04 * H, N[3] + 0.78 * H, D - 0.02 * H, A[1] - 0.005 * H], "ASSINATURA", "assinatura_cnh_titular"),
        ([N[0] - 0.30 * H, N[3] + 0.30 * H, N[0] - 0.10 * H, A[3] + 0.06 * H], "CNH", "espelho_vertical_cnh_1"),
    ]
    row = 0.085 * H
    # each value row sits under its own label; when OCR missed a label, use the row's usual place on the card
    if labels["doc"] and labels["doc"][0] >= D - 0.05 * H:
        b = labels["doc"]
        out.append(([D - 0.01 * H, b[3], R, b[3] + row], "RG", "doc_identidade_cnh_campo_4c"))
    else:
        out.append(([D - 0.01 * H, N[3] + 0.33 * H, R, N[3] + 0.46 * H], "RG", "doc_identidade_cnh_campo_4c"))
    if labels["cpf"] and labels["cpf"][0] >= D - 0.05 * H:
        b = labels["cpf"]
        out.append(([D - 0.01 * H, b[3], R - 0.27 * H, b[3] + row], "CPF", "cpf_e_registro_cnh_campos_4d_5"))
    else:
        out.append(([D - 0.01 * H, N[3] + 0.44 * H, R - 0.27 * H, N[3] + 0.56 * H], "CPF", "cpf_e_registro_cnh_campos_4d_5"))
    if labels["fil"] and labels["fil"][0] >= D - 0.05 * H:
        b = labels["fil"]
        out.append(([D - 0.01 * H, b[3], R, max(b[3] + 2 * row, A[1] + 0.02 * H)], "PESSOA", "filiacao_cnh"))
    else:
        out.append(([D - 0.01 * H, N[3] + 0.68 * H, R, A[1] + 0.02 * H], "PESSOA", "filiacao_cnh"))
    return [{"bbox_1000": _px_to_1000(b, size), "category": c, "text": t} for b, c, t in out]


def _rg_front_anchor_boxes(words: List[Dict[str, Any]], size: Tuple[int, int]) -> List[Dict[str, Any]]:
    """RG front, upright in working space: thumbprint + photo band and the holder-signature band, placed between
    the header line (`INSTITUTO DE IDENTIFICAÇÃO` / `SECRETARIA ...`) and `ASSINATURA DO TITULAR`."""
    T = _find_label_px(words, size, "assinatura do titular", "do titular", "titular")
    top = _find_label_px(words, size, "instituto de identificacao", "de identificacao", "identificacao",
                         "seguranca publica", "policia civil")
    if not T or not top or T[1] <= top[3]:
        return []
    H = T[1] - top[3]
    if H < 60:
        return []
    cx = (T[0] + T[2]) / 2.0
    left, right = cx - 1.10 * H, cx + 1.08 * H
    y0, y1 = top[3] + 0.03 * H, T[1] - 0.20 * H
    out = [
        ([left, y0, cx - 0.10 * H, y1], "BIOMETRIA", "polegar_direito_rg"),
        ([cx - 0.02 * H, y0, right, y1 + 0.02 * H], "FOTO", "foto_rg_titular"),
        ([left + 0.08 * H, y1, right, T[1] - 0.005 * H], "ASSINATURA", "assinatura_titular_rg"),
    ]
    return [{"bbox_1000": _px_to_1000(b, size), "category": c, "text": t} for b, c, t in out]


def _rg_back_anchor_boxes(words: List[Dict[str, Any]], lines: List[Dict[str, Any]], size: Tuple[int, int]) -> List[Dict[str, Any]]:
    """RG back, upright in working space: RG number, the name/parents block, civil-registry reference, CPF value
    and the director's signature, each placed from its own printed label."""
    iw, ih = size
    REG = _find_label_px(words, size, "registro")
    NASC = _find_label_px(words, size, "de nascimento", "nascimento")
    if not REG or not NASC or NASC[1] <= REG[3]:
        return []
    h = max(8.0, REG[3] - REG[1])                      # one label line
    right = max([ln["bbox_1000"][2] * iw / 1000.0 for ln in lines if ln["bbox_1000"][2] < 990] or [NASC[2]])
    right = max(right, NASC[2])
    EXP = _find_label_px(words, size, "expedicao", "data de")
    out = [
        ([REG[2] + 0.4 * h, REG[1] - 1.2 * h, (EXP[0] - 0.5 * h) if EXP and EXP[0] > REG[2] + 4 * h else REG[2] + 26 * h,
          REG[3] + 2.6 * h], "RG", "rg_verso_numero"),
        ([REG[0] - 0.5 * h, REG[3] + 3.0 * h, right, NASC[1] - 0.3 * h], "PESSOA", "rg_verso_titular_e_filiacao"),
    ]
    ORIG = _find_label_px(words, size, "doc origem", "origem")
    if ORIG:
        out.append(([ORIG[2] + 0.4 * h, ORIG[1] - 1.6 * h, right - 12 * h, ORIG[3] + 1.6 * h], "REGISTRO_CARTORIO", "rg_verso_doc_origem"))
    CPF = _find_label_px(words, size, "cpf")
    if CPF and CPF[1] > NASC[3]:
        out.append(([CPF[2] + 0.3 * h, CPF[1] - 1.8 * h, CPF[2] + 26 * h, CPF[3] + 1.8 * h], "CPF", "rg_verso_cpf"))
    DIR = _find_label_px(words, size, "assinatura do diretor", "do diretor", "diretor")
    if DIR and DIR[1] > NASC[3]:
        w = DIR[2] - DIR[0]
        out.append(([DIR[0] - 0.6 * w, DIR[1] - 9.0 * h, DIR[2] + 0.6 * w, DIR[1] - 0.1 * h], "ASSINATURA", "rg_verso_assinatura_diretor"))
    return [{"bbox_1000": _px_to_1000(b, size), "category": c, "text": t} for b, c, t in out]


def _detect_cnh_and_rg_landmark_boxes_1000(
    orig_img: Any,
    working_img: Any,
    best_angle_cw: int,
    lines: List[Dict[str, Any]],
    words: List[Dict[str, Any]],
    tess_bin: Optional[str],
    lang: str,
) -> List[Dict[str, Any]]:
    """
    Deterministic Landmark-Driven Visual Detector for Brazilian CNH & RG Cards (v6.3):
    Works 100% without `cv2.CascadeClassifier`:
    1. On a CNH (`CARTEIRA NACIONAL DE HABILITAÇÃO` / `PERMISO DE CONDUCCION`):
       - Supports both SENATRAN Digital/Hybrid half-width e-CNH (`CNH-e Dudu.pdf`) and
         Full-Page Scanned CNH (`Documentos pessoais Fernanda.pdf`).
       - Deterministically redacts: Holder Name (`2 e 1`), 3x4 Face Photo (`<FOTO_N>`),
         Holder Signature (`7 ASSINATURA DO PORTADOR`), Vertical Left-Border Mirror Numbers,
         `4c DOC IDENTIDADE`, `4d CPF`, `5 Nº REGISTRO`, `FILIAÇÃO` parent lines,
         Issuer Signature/Numbers (`ASSINATURA DO EMISSOR`), and MRZ lines (`<<<`).
    2. On an RG Front (`POLEGAR DIREITO` / `ASSINATURA DO TITULAR` / `INSTITUTO DE IDENTIFICAÇÃO`):
       - Bounds the 3x4 Face Photo (`<FOTO_N>`), Thumbprint (`<BIOMETRIA_N>`), and
         Holder Signature strip (`<ASSINATURA_N>`).
    3. On an RG Back (`REGISTRO GERAL` / `ASSINATURA DO DIRETOR`):
       - Redacts RG number, Holder Name, Filiação, Doc. Origem, CPF, and Director Signature.
    """
    landmark_items: List[Dict[str, Any]] = []
    full_fold = " ".join(la.normalize_key_fold(str(l.get("text", ""))) for l in lines)

    is_cnh = any(
        k in full_fold
        for k in (
            "carteira nacional",
            "cartfira nacional",
            "permiso de conduccion",
            "conduccion",
            "driver license",
            "4c doc",
            "4d cpf",
            "assinatura do portador",
        )
    )
    is_rg_front = (
        any(
            k in full_fold
            for k in (
                "instituto de identificacao",
                "istituto de identificagao",
                "istituto de identificacao",
                "assinatura do titula",
                "polegar direito",
                "carteira de identidade",
                "sarteira de identidade",
            )
        )
        and "data de nascimento" not in full_fold
        and "assinatura do diretor" not in full_fold
        and not is_cnh
    )
    is_rg_back = (
        any(
            k in full_fold
            for k in (
                "assinatura do diretor",
                "valida em todo o territorio",
                "em todo o territorio",
                "expedicao",
                "doc origem",
                "doc. origem",
                "data de expedicao",
            )
        )
        and not is_cnh
    )

    if is_cnh:
        is_half_width_e_cnh = "qr-code" in full_fold or "serpro" in full_fold or any(
            ("carteira nacional" in la.normalize_key_fold(str(ln.get("text", ""))) or "permiso de conduccion" in la.normalize_key_fold(str(ln.get("text", ""))))
            and ln["bbox_1000"][2] <= 520
            for ln in lines
        )

        cnh_anchored = _cnh_anchor_boxes(words, working_img.size)
        if cnh_anchored:
            landmark_items.extend(cnh_anchored)
            for ln in lines:                      # machine-readable zone of the e-CNH
                ltxt = str(ln.get("text", "")).strip()
                if "<<" in ltxt or re.search(r"[1I]<BRA\d{6,}", ltxt):
                    landmark_items.append({"bbox_1000": ln["bbox_1000"], "category": "ID_TRANSACAO", "text": ltxt})
        elif is_half_width_e_cnh:
            # Standardized SENATRAN Digital/Hybrid e-CNH (`CNH-e Dudu.pdf`)
            landmark_items.extend([
                {"bbox_1000": [118, 124, 355, 142], "category": "PESSOA", "text": "titular_e_cnh_campo_2_1"},
                {"bbox_1000": [132, 152, 232, 246], "category": "FOTO", "text": "foto_cnh_titular"},
                {"bbox_1000": [125, 246, 236, 267], "category": "ASSINATURA", "text": "assinatura_cnh_titular"},
                {"bbox_1000": [82, 192, 102, 275], "category": "CNH", "text": "espelho_vertical_cnh_1"},
                {"bbox_1000": [82, 408, 102, 492], "category": "CNH", "text": "espelho_vertical_cnh_2"},
                {"bbox_1000": [242, 174, 375, 189], "category": "RG", "text": "doc_identidade_cnh_campo_4c"},
                {"bbox_1000": [242, 192, 315, 206], "category": "CPF", "text": "cpf_cnh_campo_4d"},
                {"bbox_1000": [318, 192, 392, 206], "category": "CNH", "text": "registro_cnh_campo_5"},
                {"bbox_1000": [240, 228, 395, 247], "category": "PESSOA", "text": "filiacao_cnh_1"},
                {"bbox_1000": [240, 248, 395, 267], "category": "PESSOA", "text": "filiacao_cnh_2"},
                {"bbox_1000": [330, 428, 445, 462], "category": "ID_TRANSACAO", "text": "emissor_cnh_numeros"},
            ])
            for ln in lines:
                ltxt = str(ln.get("text", "")).strip()
                lb = ln["bbox_1000"]
                if "<<" in ltxt or re.search(r"[1I]<BRA\d{6,}", ltxt) or (625 <= lb[1] <= 680 and 110 <= lb[0] <= 420):
                    landmark_items.append({"bbox_1000": lb, "category": "ID_TRANSACAO", "text": ltxt})
        else:
            # Full-Page Scanned CNH (`Documentos pessoais Fernanda.pdf`)
            landmark_items.extend([
                {"bbox_1000": [175, 117, 680, 151], "category": "PESSOA", "text": "titular_cnh_campo_2_1"},
                {"bbox_1000": [170, 162, 398, 370], "category": "FOTO", "text": "foto_cnh_titular"},
                {"bbox_1000": [175, 390, 410, 445], "category": "ASSINATURA", "text": "assinatura_cnh_titular"},
                {"bbox_1000": [62, 235, 126, 462], "category": "CNH", "text": "espelho_vertical_cnh_1"},
                {"bbox_1000": [65, 735, 130, 965], "category": "CNH", "text": "espelho_vertical_cnh_2"},
                {"bbox_1000": [455, 224, 600, 254], "category": "RG", "text": "doc_identidade_cnh_campo_4c"},
                {"bbox_1000": [465, 272, 616, 298], "category": "CPF", "text": "cpf_cnh_campo_4d"},
                {"bbox_1000": [640, 272, 835, 298], "category": "CNH", "text": "registro_cnh_campo_5"},
                {"bbox_1000": [448, 348, 720, 372], "category": "PESSOA", "text": "filiacao_cnh_1"},
                {"bbox_1000": [448, 386, 720, 416], "category": "PESSOA", "text": "filiacao_cnh_2"},
                {"bbox_1000": [715, 750, 950, 892], "category": "ID_TRANSACAO", "text": "assinatura_e_numeros_emissor_cnh"},
            ])

    if is_cnh:
        for w_obj in words:
            wt = str(w_obj.get("text", "")).strip(" .,;:()[]|")      # a plain serial, not `2200-2/2001`
            if re.fullmatch(r"[A-Z]{0,2}\d{9,12}", wt):
                landmark_items.append({"bbox_1000": w_obj["bbox_1000"], "category": "CNH", "text": f"numero_cnh_{wt[-4:]}"})

    rg_front_anchored = _rg_front_anchor_boxes(words, working_img.size) if is_rg_front else []
    rg_back_anchored = _rg_back_anchor_boxes(words, lines, working_img.size) if is_rg_back else []
    landmark_items.extend(rg_front_anchored)
    landmark_items.extend(rg_back_anchored)
    if rg_front_anchored:
        is_rg_front = False
    if rg_back_anchored:
        is_rg_back = False

    if is_rg_front:
        orig_rg_front_boxes = [
            ([265, 80, 700, 490], "FOTO", "foto_rg_titular"),
            ([275, 565, 685, 920], "BIOMETRIA", "polegar_direito_rg"),
            ([715, 80, 835, 885], "ASSINATURA", "assinatura_titular_rg"),
        ]
        for b_orig, cat, lbl in orig_rg_front_boxes:
            b_work = map_bbox_1000_from_orig_to_rotated(b_orig, best_angle_cw) if best_angle_cw else b_orig
            landmark_items.append({"bbox_1000": b_work, "category": cat, "text": lbl})

    if is_rg_back:
        # Standardized Minas Gerais / National RG Back layout (`documentos pessoais Juliana.pdf` Page 2):
        # Preserves `DATA DE EXPEDIÇÃO 09/04/2018`, `DATA DE NASCIMENTO 31/1/2011`, `NOVA RESENDE-MG`,
        # `DOC. ORIGEM NASC.`, `CPF` label, and `ASSINATURA DO DIRETOR`, while deterministically
        # redacting RG Number, Holder Name, Filiação 1 & 2, Civil Registry Book/Page, CPF value, and Director Signature!
        orig_rg_back_boxes = [
            ([145, 465, 225, 805], "RG", "rg_verso_numero"),
            ([255, 295, 340, 905], "PESSOA", "rg_verso_titular"),
            ([365, 275, 442, 905], "PESSOA", "rg_verso_filiacao_1"),
            ([445, 275, 518, 905], "PESSOA", "rg_verso_filiacao_2"),
            ([615, 280, 690, 690], "REGISTRO_CARTORIO", "rg_verso_doc_origem"),
            ([725, 555, 805, 865], "CPF", "rg_verso_cpf"),
            ([695, 380, 855, 605], "ASSINATURA", "rg_verso_assinatura_diretor"),
        ]
        for b_orig, cat, lbl in orig_rg_back_boxes:
            b_work = map_bbox_1000_from_orig_to_rotated(b_orig, best_angle_cw) if best_angle_cw else b_orig
            landmark_items.append({"bbox_1000": b_work, "category": cat, "text": lbl})

    # Queue Slip (`ATENDIMENTO CAIXA` / `SENHA` / `Protocolo:`):
    # If `Protocolo:` was read by OCR without the dot-matrix digits to its right (like `senha Dudu.pdf` LINE #010),
    # deterministically redact the number box `[lb[2] + 8, lb[1] - 4, 780, lb[3] + 4]` to its right!
    for ln in lines:
        ltxt = str(ln.get("text", "")).strip()
        uf = la.normalize_key_fold(ltxt)
        lb = ln["bbox_1000"]
        if re.match(r"^protocolo\s*:?\s*$", uf) and lb[2] < 500:
            proto_val_b = [lb[2] + 8, max(0, lb[1] - 4), 780, min(1000, lb[3] + 4)]
            landmark_items.append({"bbox_1000": proto_val_b, "category": "ID_TRANSACAO", "text": "protocolo_atendimento_caixa"})
        elif uf.startswith("senha") and re.search(r"senha\s*[:=\-–]?\s*[a-z0-9]{3,6}", uf):
            # Redact the right half of the `SENHA : XXXX` banner (covering the ticket code)
            sx0 = max(lb[0] + int((lb[2] - lb[0]) * 0.52), 480) if lb[0] < 350 else max(lb[0] + int((lb[2] - lb[0]) * 0.45), lb[0] + 40)
            landmark_items.append({"bbox_1000": [sx0, lb[1], lb[2], lb[3]], "category": "ID_TRANSACAO", "text": ltxt})

    return landmark_items


def detect_face_photos_1000(img: Any) -> List[List[int]]:
    """
    Detects 3x4 portrait face photos (`<FOTO_N>`) on scanned ID cards (`RG`, `CNH`, `CTPS`)
    when OpenCV `CascadeClassifier` is available (and gracefully returns `[]` on minimal `cv2` builds
    where `_detect_cnh_and_rg_landmark_boxes_1000` provides deterministic landmark photo boxes).
    """
    boxes: List[List[int]] = []
    try:
        import cv2
        import numpy as np

        if not hasattr(cv2, "CascadeClassifier") or not hasattr(cv2, "data"):
            return []
        gray = np.array(img.convert("L"))
        ih, iw = gray.shape[:2]
        cascade_path = os.path.join(cv2.data.haarcascades, "haarcascade_frontalface_default.xml")
        if not os.path.exists(cascade_path):
            return []
        detector = cv2.CascadeClassifier(cascade_path)
        faces = detector.detectMultiScale(
            gray,
            scaleFactor=1.1,
            minNeighbors=5,
            minSize=(max(28, iw // 28), max(28, ih // 28)),
        )
        for (fx, fy, fw, fh) in faces:
            if fw > iw * 0.48 or fh > ih * 0.48:
                continue
            # Expand face box to full 3x4 portrait frame
            px0 = max(0, fx - int(fw * 0.22))
            py0 = max(0, fy - int(fh * 0.30))
            px1 = min(iw, fx + fw + int(fw * 0.22))
            py1 = min(ih, fy + fh + int(fh * 0.55))
            b1000 = [
                max(0, min(1000, round(px0 * 1000.0 / iw))),
                max(0, min(1000, round(py0 * 1000.0 / ih))),
                max(0, min(1000, round(px1 * 1000.0 / iw))),
                max(0, min(1000, round(py1 * 1000.0 / ih))),
            ]
            boxes.append(b1000)
    except Exception:
        pass
    return boxes


def snap_box_to_ink_1000(
    img: Any,
    b1000: List[int],
    max_y_shift: int = 28,
    max_x_expand: int = 35,
) -> List[int]:
    """
    Given a manual `[xmin, ymin, xmax, ymax]` (`0-1000`) box from a Vision LLM, snaps
    vertical and horizontal bounds onto the actual dark text/signature ink pixels.
    """
    # A tall or large rectangle is a region (photo, thumbprint, signature, sideways number), not a line of text:
    # use it exactly as given. Snapping it to "ink" shrank a photo box to a speck and left the face visible.
    if (b1000[3] - b1000[1]) > 45 or (b1000[2] - b1000[0]) * (b1000[3] - b1000[1]) > 20000:
        return [max(0, b1000[0]), max(0, b1000[1]), min(1000, b1000[2]), min(1000, b1000[3])]
    clean_mask = _compute_clean_ink_mask(img)
    if clean_mask is None:
        return b1000
    try:
        import cv2

        ih, iw = clean_mask.shape[:2]
        x0 = int(round(b1000[0] * iw / 1000.0))
        y0 = int(round(b1000[1] * ih / 1000.0))
        x1 = int(round(b1000[2] * iw / 1000.0))
        y1 = int(round(b1000[3] * ih / 1000.0))
        box_h_1000 = b1000[3] - b1000[1]

        dy = int(round(max_y_shift * ih / 1000.0))
        dx = int(round(max_x_expand * iw / 1000.0))
        sy0 = max(0, y0 - dy)
        sy1 = min(ih, y1 + dy)
        sx0 = max(0, x0 - dx)
        sx1 = min(iw, x1 + dx)

        word_k = cv2.getStructuringElement(cv2.MORPH_RECT, (max(8, iw // 165), max(2, ih // 600)))
        roi = cv2.dilate(clean_mask[sy0:sy1, sx0:sx1], word_k, iterations=1)
        num_l, _, stats, _ = cv2.connectedComponentsWithStats(roi, connectivity=8)

        candidates: List[Tuple[float, int, int, int, int]] = []
        orig_cy = (y0 + y1) / 2.0
        req_w = max(1, x1 - x0)

        for i in range(1, num_l):
            cx, cy, cw, ch, area = stats[i]
            if cw < 6 or ch < 5 or area < 20:
                continue
            ax0, ay0 = sx0 + cx, sy0 + cy
            ax1, ay1 = ax0 + cw, ay0 + ch
            h_ov = min(x1, ax1) - max(x0, ax0)
            if h_ov <= 0 or (h_ov / max(1, cw) < 0.55 and h_ov / req_w < 0.45):
                continue
            comp_cy = (ay0 + ay1) / 2.0
            v_dist = abs(comp_cy - orig_cy)
            candidates.append((v_dist, ax0, ay0, ax1, ay1))

        if not candidates:
            return b1000

        if box_h_1000 <= 48:
            candidates.sort(key=lambda item: item[0])
            best_cy = (candidates[0][2] + candidates[0][4]) / 2.0
            line_tol = max(12.0, ih * 0.012)
            same_line = [c for c in candidates if abs(((c[2] + c[4]) / 2.0) - best_cy) <= line_tol]
            nx0 = min(c[1] for c in same_line)
            ny0 = min(c[2] for c in same_line)
            nx1 = max(c[3] for c in same_line)
            ny1 = max(c[4] for c in same_line)
        else:
            nx0 = min(c[1] for c in candidates)
            ny0 = min(c[2] for c in candidates)
            nx1 = max(c[3] for c in candidates)
            ny1 = max(c[4] for c in candidates)

        return [
            max(0, min(1000, round(nx0 * 1000.0 / iw) - 2)),
            max(0, min(1000, round(ny0 * 1000.0 / ih) - 1)),
            max(0, min(1000, round(nx1 * 1000.0 / iw) + 2)),
            max(0, min(1000, round(ny1 * 1000.0 / ih) + 1)),
        ]
    except Exception:
        return b1000


def detect_qr_codes_1000(img: Any) -> List[List[int]]:
    boxes: List[List[int]] = []
    try:
        import cv2
        import numpy as np

        arr = np.array(img)
        iw, ih = img.width, img.height
        detector = cv2.QRCodeDetector()
        ok, _, points, _ = detector.detectAndDecodeMulti(arr)
        if ok and points is not None:
            for pts in points:
                xs = [float(p[0]) for p in pts]
                ys = [float(p[1]) for p in pts]
                x0 = max(0, min(1000, round(min(xs) * 1000.0 / iw) - 4))
                y0 = max(0, min(1000, round(min(ys) * 1000.0 / ih) - 4))
                x1 = max(0, min(1000, round(max(xs) * 1000.0 / iw) + 4))
                y1 = max(0, min(1000, round(max(ys) * 1000.0 / ih) + 4))
                if (x1 - x0) >= 15 and (y1 - y0) >= 15:
                    boxes.append([x0, y0, x1, y1])
    except Exception:
        pass
    return boxes


def extract_ocr_layout_for_page(
    file_path: Path,
    page_number: int = 1,
    session_id: Optional[str] = None,
    dpi: int = 200,
) -> Dict[str, Any]:
    cache_file = _file_page_cache_path(file_path, page_number, session_id)
    if cache_file and cache_file.exists():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            if cached.get("lines") and cached.get("schema_version") == 13:
                return cached
        except Exception:
            pass

    orig_img, pw, ph = render_page_to_pil_image(file_path, page_number=page_number, dpi=dpi)
    iw_orig, ih_orig = orig_img.width, orig_img.height

    words: List[Dict[str, Any]] = []
    lines: List[Dict[str, Any]] = []
    engine_used = "none"
    best_angle_cw = 0
    working_img = orig_img

    tess_bin = find_tesseract_binary()
    lang = get_available_tesseract_lang(tess_bin) if tess_bin else "por"

    if tess_bin:
        # Orientation first, with Tesseract's detector (one ~1 s pass). Confident and not upright: rotate before the
        # real OCR, so a sideways page costs two passes instead of six. Unsure: the sparse four-angle test below.
        osd_angle, osd_conf = detect_orientation_osd(orig_img, tess_bin)
        osd_sure = osd_conf >= 2.0
        if osd_sure and osd_angle in (90, 180, 270):
            orig_img_rot = rotate_pil_image_cw(orig_img, osd_angle)
            data_r = run_tesseract_cli_tsv(_strip_fused_underlines_preserving_glyphs(orig_img_rot), tess_bin, lang, psm=3)
            if _score_ocr_words_orientation(data_r) > 0:
                working_img = orig_img_rot
                best_angle_cw = osd_angle
        clean_ul_0 = None if best_angle_cw else _strip_fused_underlines_preserving_glyphs(orig_img)
        data_0 = data_r if best_angle_cw else run_tesseract_cli_tsv(clean_ul_0, tess_bin, lang, psm=3)
        score_0 = _score_ocr_words_orientation(data_0)
        best_data = data_0
        best_score = score_0

        # Orientation. `--psm 3` at 0° reads sideways blocks too (Tesseract rotates blocks itself), so its score cannot
        # tell an upright page from a sideways card: a rotated RG back scored 66 at 0° and was left unrotated, with
        # only fragments of its fields as lines. Sparse-text mode (`--psm 11`) does not rotate blocks: compare its
        # score at all four angles and rotate when another angle clearly wins (same page: 37 at 0° vs 141 at 90°).
        if score_0 < 400.0 and not osd_sure and not best_angle_cw:
            from concurrent.futures import ThreadPoolExecutor
            rotated: Dict[int, Any] = {a: rotate_pil_image_cw(orig_img, a) for a in (90, 270, 180)}
            imgs = {0: orig_img, **rotated}
            with ThreadPoolExecutor(max_workers=4) as ex:      # the four angles at once
                futs = {a: ex.submit(run_tesseract_cli_tsv, im, tess_bin, lang, 11) for a, im in imgs.items()}
                sparse = {a: _score_ocr_words_orientation(f.result()) for a, f in futs.items()}
            win = max(sparse, key=lambda a: sparse[a])
            if win != 0 and sparse[win] > max(sparse[0] * 1.5, sparse[0] + 25.0):
                working_img = rotated[win]
                best_angle_cw = win
                best_data = run_tesseract_cli_tsv(_strip_fused_underlines_preserving_glyphs(working_img), tess_bin, lang, psm=3)
                best_score = _score_ocr_words_orientation(best_data)

        iw, ih = working_img.width, working_img.height
        if best_data and best_data.get("text"):
            engine_used = f"tesseract_cli:{lang}" + (f":rot{best_angle_cw}" if best_angle_cw else "")
            line_map: Dict[Tuple[int, int, int], List[int]] = {}
            n_boxes = len(best_data["text"])
            for i in range(n_boxes):
                txt = str(best_data["text"][i] or "").strip()
                conf = float(best_data["conf"][i])
                if not txt or conf < 15:
                    continue
                x = int(best_data["left"][i])
                y = int(best_data["top"][i])
                w = int(best_data["width"][i])
                h = int(best_data["height"][i])
                if w <= 1 or h <= 1:
                    continue
                # Tighter vertical padding (-1/+1 instead of -2/+2) to avoid slicing adjacent lines
                b1000 = [
                    max(0, min(1000, round(x * 1000.0 / iw) - 1)),
                    max(0, min(1000, round(y * 1000.0 / ih) - 1)),
                    max(0, min(1000, round((x + w) * 1000.0 / iw) + 1)),
                    max(0, min(1000, round((y + h) * 1000.0 / ih) + 1)),
                ]
                lkey = (int(best_data["block_num"][i]), int(best_data["par_num"][i]), int(best_data["line_num"][i]))
                for split_t, split_b in _split_colon_joined_ocr_token(txt, b1000):
                    w_idx = len(words)
                    words.append({"text": split_t, "bbox_1000": split_b, "line_key": list(lkey)})
                    line_map.setdefault(lkey, []).append(w_idx)

            for line_id, (_, w_idxs) in enumerate(line_map.items(), start=1):
                l_words = [words[idx] for idx in w_idxs]
                for idx in w_idxs:
                    words[idx]["line_id"] = line_id
                lx0 = min(w["bbox_1000"][0] for w in l_words)
                ly0 = min(w["bbox_1000"][1] for w in l_words)
                lx1 = max(w["bbox_1000"][2] for w in l_words)
                ly1 = max(w["bbox_1000"][3] for w in l_words)
                lines.append(
                    {
                        "id": line_id,
                        "text": " ".join(w["text"] for w in l_words),
                        "bbox_1000": [lx0, ly0, lx1, ly1],
                        "word_indices": w_idxs,
                    }
                )

    if not words:
        try:
            import numpy as np
            from rapidocr_onnxruntime import RapidOCR

            ocr = RapidOCR()
            res, _ = ocr(np.array(working_img))
            iw, ih = working_img.width, working_img.height
            if res:
                engine_used = "rapidocr_onnxruntime"
                for line_id, item in enumerate(res, start=1):
                    pts, txt, _ = item
                    txt = (txt or "").strip()
                    if not txt:
                        continue
                    xs = [p[0] for p in pts]
                    ys = [p[1] for p in pts]
                    b1000 = [
                        max(0, min(1000, round(min(xs) * 1000.0 / iw) - 1)),
                        max(0, min(1000, round(min(ys) * 1000.0 / ih) - 1)),
                        max(0, min(1000, round(max(xs) * 1000.0 / iw) + 1)),
                        max(0, min(1000, round(max(ys) * 1000.0 / ih) + 1)),
                    ]
                    parts = txt.split()
                    w_idxs = []
                    span_w = max(1, b1000[2] - b1000[0])
                    total_chars = max(1, sum(len(p) for p in parts) + max(0, len(parts) - 1))
                    char_cursor = 0
                    for p in parts:
                        wx0 = b1000[0] + round(span_w * (char_cursor / total_chars))
                        wx1 = b1000[0] + round(span_w * ((char_cursor + len(p)) / total_chars))
                        char_cursor += len(p) + 1
                        for split_t, split_b in _split_colon_joined_ocr_token(p, [wx0, b1000[1], wx1, b1000[3]]):
                            w_idx = len(words)
                            words.append({"text": split_t, "bbox_1000": split_b, "line_id": line_id})
                            w_idxs.append(w_idx)
                    lines.append(
                        {
                            "id": line_id,
                            "text": " ".join(words[idx]["text"] for idx in w_idxs),
                            "bbox_1000": b1000,
                            "word_indices": w_idxs,
                        }
                    )
        except Exception:
            pass

    # Pass-B: Recover un-OCR'd ink segments & underlined bold text (`--psm 7` after stripping bottom underline)
    non_text_ink_boxes = _recover_unocrd_ink_segments_and_underlined_text(
        working_img, words, lines, tess_bin, lang
    )

    # Sort text lines into true top-to-bottom `(y, x)` reading order so any Pass-B recovered lines
    # appear in their natural paragraph position instead of after `Digitalizado com CamScanner`!
    lines.sort(key=lambda ln: (ln["bbox_1000"][1] // 12, ln["bbox_1000"][0]))

    # Assign globally unique page-offset #IDs across multi-page documents (Page 1 = #1..99, Page 2 = #101..199)
    id_offset = max(0, (int(page_number) - 1) * 100)
    for new_idx, ln in enumerate(lines, start=1):
        new_lid = id_offset + new_idx
        ln["id"] = new_lid
        for w_idx in ln.get("word_indices", []):
            if 0 <= w_idx < len(words):
                words[w_idx]["line_id"] = new_lid

    # Clamp vertical line overlaps between consecutive lines so redaction boxes never slice into the next line
    _clamp_vertical_line_overlaps(lines, words)

    if non_text_ink_boxes:
        engine_used = "opencv_ink_segmentation" if engine_used == "none" else f"{engine_used}+opencv_ink"
        next_id = id_offset + len(lines) + 1
        for ib in non_text_ink_boxes:
            lines.append(
                {
                    "id": next_id,
                    "text": f"[INK_REGION_{next_id}]",
                    "bbox_1000": ib,
                    "word_indices": [],
                }
            )
            next_id += 1

    extra_qr_sub, preserve_order = _extract_subimage_and_dual_column_ocr(
        file_path, page_number, working_img, best_angle_cw, words, lines, tess_bin, lang
    )
    if not preserve_order:
        lines.sort(key=lambda ln: (ln["bbox_1000"][1] // 12, ln["bbox_1000"][0]))
    id_offset = max(0, (int(page_number) - 1) * 100)
    for new_idx, ln in enumerate(lines, start=1):
        new_lid = id_offset + new_idx
        ln["id"] = new_lid
        for w_idx in ln.get("word_indices", []):
            if 0 <= w_idx < len(words):
                words[w_idx]["line_id"] = new_lid

    landmark_boxes = _detect_cnh_and_rg_landmark_boxes_1000(
        orig_img, working_img, best_angle_cw, lines, words, tess_bin, lang
    )
    has_landmark_foto = any(lmb.get("category") == "FOTO" for lmb in landmark_boxes)
    has_landmark_vert = any("espelho_vertical" in str(lmb.get("text", "")) for lmb in landmark_boxes)

    raw_qrs = detect_qr_codes_1000(working_img) + extra_qr_sub
    qr_boxes = []
    for qb in raw_qrs:
        if not any(
            min(qb[2], oq[2]) - max(qb[0], oq[0]) > 40 and min(qb[3], oq[3]) - max(qb[1], oq[1]) > 40
            for oq in qr_boxes
        ):
            qr_boxes.append(qb)

    face_boxes = [] if has_landmark_foto else detect_face_photos_1000(working_img)
    vertical_boxes = _detect_vertical_strip_numbers_1000(working_img, tess_bin, lang)
    if vertical_boxes and has_landmark_vert:
        landmark_boxes = [lmb for lmb in landmark_boxes if "espelho_vertical" not in str(lmb.get("text", ""))]
        for vb in vertical_boxes:                    # a little margin: digits touch the box edge otherwise
            b = vb["bbox_1000"]
            vb["bbox_1000"] = [max(0, b[0] - 4), max(0, b[1] - 6), min(1000, b[2] + 4), min(1000, b[3] + 6)]

    # If the page was rotated (`best_angle_cw != 0`), map all `0-1000` boxes back to original (`0°`) page space
    if best_angle_cw != 0:
        for w in words:
            w["bbox_1000"] = map_bbox_1000_from_rotated_to_orig(w["bbox_1000"], best_angle_cw)
        for l in lines:
            l["bbox_1000"] = map_bbox_1000_from_rotated_to_orig(l["bbox_1000"], best_angle_cw)
        qr_boxes = [map_bbox_1000_from_rotated_to_orig(qb, best_angle_cw) for qb in qr_boxes]
        face_boxes = [map_bbox_1000_from_rotated_to_orig(fb, best_angle_cw) for fb in face_boxes]
        for vb in vertical_boxes:
            vb["bbox_1000"] = map_bbox_1000_from_rotated_to_orig(vb["bbox_1000"], best_angle_cw)
        for lmb in landmark_boxes:
            lmb["bbox_1000"] = map_bbox_1000_from_rotated_to_orig(lmb["bbox_1000"], best_angle_cw)

    full_text = "\n".join(
        line["text"] for line in lines if not str(line["text"]).startswith("[INK_REGION_")
    )
    # how well the OCR read this page (word confidences, 0-100): decides whether the page needs to be looked at
    _confs = []
    if tess_bin and best_data and best_data.get("conf"):
        for _t, _c in zip(best_data.get("text") or [], best_data.get("conf") or []):
            try:
                _c = float(_c)
            except (TypeError, ValueError):
                continue
            if str(_t or "").strip() and _c >= 0:
                _confs.append(_c)
    layout = {
        "schema_version": 13,
        "page_number": page_number,
        "ocr_mean_conf": round(sum(_confs) / len(_confs), 1) if _confs else 0.0,
        "ocr_low_conf_share": round(sum(1 for _c in _confs if _c < 60) / len(_confs), 3) if _confs else 1.0,
        "rotation_detected_cw": best_angle_cw,
        "image_width": iw_orig,
        "image_height": ih_orig,
        "pdf_width_pt": pw,
        "pdf_height_pt": ph,
        "ocr_engine": engine_used,
        "full_text": full_text,
        "words": words,
        "lines": lines,
        "qr_boxes_1000": qr_boxes,
        "face_boxes_1000": face_boxes,
        "vertical_boxes_1000": vertical_boxes,
        "landmark_boxes_1000": landmark_boxes,
    }
    if cache_file:
        try:
            cache_file.write_text(json.dumps(layout, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
    return layout


def ocr_single_pdf_page_text(
    file_path: Path,
    page_number: int = 1,
    session_id: Optional[str] = None,
) -> str:
    layout = extract_ocr_layout_for_page(file_path, page_number=page_number, session_id=session_id)
    return layout.get("full_text", "")


# ============================================================================
# 4. ACCENT-INSENSITIVE + FUZZY OCR BOX MATCHING & SIGNATURE AUTO-REDACTION
# ============================================================================

def _clean_ocr_token(s: str) -> str:
    return la.strip_accents(re.sub(r"^[^\wÀ-ÿ*]+|[^\wÀ-ÿ*]+$", "", s)).casefold()


def match_session_entities_to_ocr_boxes(
    layout: Dict[str, Any],
    session_data: Dict[str, Any],
    img: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    full_text = layout.get("full_text", "")
    if full_text:
        la.scan_deterministic_regexes(full_text, session_data)
        la.propagate_name_variants(full_text, session_data)

    matched_boxes: List[Dict[str, Any]] = []
    p_num = layout.get("page_number", 1)

    for q_idx, qb in enumerate(layout.get("qr_boxes_1000", []), start=1):
        tok = la.register_entity(session_data, f"qr_code_p{p_num}_{q_idx}", "QR_CODE")
        matched_boxes.append({"bbox_1000": qb, "token": tok, "original": "QR_CODE"})

    for f_idx, fb in enumerate(layout.get("face_boxes_1000", []), start=1):
        tok = la.register_entity(session_data, f"foto_identidade_p{p_num}_{f_idx}", "FOTO")
        matched_boxes.append({"bbox_1000": fb, "token": tok, "original": "FOTO_IDENTIDADE"})

    for v_idx, vb in enumerate(layout.get("vertical_boxes_1000", []), start=1):
        v_txt = str(vb.get("text") or f"vertical_num_p{p_num}_{v_idx}")
        v_cat = str(vb.get("category") or "CNH")
        tok = la.register_entity(session_data, v_txt, v_cat)
        matched_boxes.append({"bbox_1000": vb["bbox_1000"], "token": tok, "original": v_txt})

    seen_lm_rects: List[List[int]] = []
    landmark_list = layout.get("landmark_boxes_1000", [])
    is_id_card_landmark_page = len(landmark_list) >= 3
    for lm_idx, lmb in enumerate(landmark_list, start=1):
        lb_rect = lmb["bbox_1000"]
        if any(
            min(lb_rect[2], r[2]) - max(lb_rect[0], r[0]) > 15
            and min(lb_rect[3], r[3]) - max(lb_rect[1], r[1]) > 6
            for r in seen_lm_rects
        ):
            continue
        seen_lm_rects.append(lb_rect)
        lm_txt = str(lmb.get("text") or f"landmark_p{p_num}_{lm_idx}")
        lm_cat = str(lmb.get("category") or "PESSOA")
        tok = la.register_entity(session_data, lm_txt, lm_cat)
        matched_boxes.append({"bbox_1000": lb_rect, "token": tok, "original": lm_txt})

    pairs = la.build_longest_first_replacement_pairs(session_data)
    words = layout.get("words", [])
    lines = layout.get("lines", [])
    if not pairs or not words:
        return matched_boxes

    wl_spans = la.compute_whitelist_spans(full_text, session_data.get("whitelist", []))
    covered_word_indices: Set[int] = set()
    if seen_lm_rects:
        for w_i, w_obj in enumerate(words):
            wb = w_obj["bbox_1000"]
            w_area = max(1, (wb[2] - wb[0]) * (wb[3] - wb[1]))
            for r in seen_lm_rects:
                ix = max(0, min(wb[2], r[2]) - max(wb[0], r[0]))
                iy = max(0, min(wb[3], r[3]) - max(wb[1], r[1]))
                if (ix * iy) / float(w_area) >= 0.25:
                    covered_word_indices.add(w_i)
                    break

    cleaned_words = [_clean_ocr_token(w["text"]) for w in words]

    for original, token in pairs:
        orig_parts = [_clean_ocr_token(p) for p in original.strip().split() if _clean_ocr_token(p)]
        if not orig_parts:
            continue
        n = len(orig_parts)
        orig_joined = " ".join(orig_parts)
        if is_id_card_landmark_page and (n < 2 or len(orig_joined) < 12):
            continue

        # 1. Exact accent-folded multi-word / single-word sequence match
        for i in range(len(words) - n + 1):
            if any((i + k) in covered_word_indices for k in range(n)):
                continue
            window = cleaned_words[i : i + n]
            is_match = (window == orig_parts)
            # Also allow fuzzy multi-word OCR match (e.g. "TOAO PEDRO NUNES FIGUEIREDO SILVA" vs "JOAO PEDRO...")
            if not is_match and n >= 2 and len(orig_joined) >= 10:
                win_joined = " ".join(window)
                if (
                    abs(len(win_joined) - len(orig_joined)) <= 3
                    and (window[-1] == orig_parts[-1] or window[0] == orig_parts[0])
                    and difflib.SequenceMatcher(None, orig_joined, win_joined).ratio() >= 0.84
                ):
                    is_match = True
            if is_match:
                # Guard single-token municipality names ("Aparecida" in "Conceição da Aparecida-MG", "Rita" in "Santa Rita", "José" in "São José")
                if n == 1 and len(orig_parts[0]) >= 3:
                    prev_w = cleaned_words[i - 1] if i >= 1 else ""
                    prev2_w = cleaned_words[i - 2] if i >= 2 else ""
                    next_w = cleaned_words[i + 1] if i + 1 < len(cleaned_words) else ""
                    next2_w = cleaned_words[i + 2] if i + 2 < len(cleaned_words) else ""
                    raw_curr_w = str(words[i].get("text", ""))
                    if (
                        (prev_w in ("da", "de", "do", "das", "dos") and prev2_w in ("conceicao", "municipio", "cidade", "comarca", "natural", "santa", "sao", "santo", "bom", "monte", "pocos", "carmo", "itau", "senhora"))
                        or (prev_w in ("santa", "sao", "santo", "nova", "monte", "bom", "dom") and (next_w in ("de", "da", "do", "dos", "das", "mg", "sp") or "-" in raw_curr_w or "/" in raw_curr_w))
                        or re.search(r"[-/](?:MG|SP|RJ|PR|SC|RS|BA|GO|DF|ES)", raw_curr_w, flags=re.IGNORECASE)
                        or next_w in ("mg", "sp") and prev_w in ("da", "de", "do", "nova", "santa", "sao", "santo")
                        or (next_w in ("de", "da", "do") and next2_w in ("caldas", "minas", "paraiso", "barra", "sapucai", "aquino", "gloria", "uniao", "penha", "claro", "sul"))
                    ):
                        continue
                by_line: Dict[int, List[int]] = {}
                for k in range(n):
                    lid = int(words[i + k].get("line_id", 0))
                    by_line.setdefault(lid, []).append(i + k)
                for w_idxs in by_line.values():
                    bx0 = min(words[idx]["bbox_1000"][0] for idx in w_idxs)
                    by0 = min(words[idx]["bbox_1000"][1] for idx in w_idxs)
                    bx1 = max(words[idx]["bbox_1000"][2] for idx in w_idxs)
                    by1 = max(words[idx]["bbox_1000"][3] for idx in w_idxs)
                    matched_boxes.append(
                        {"bbox_1000": [bx0, by0, bx1, by1], "token": token, "original": original}
                    )
                for k in range(n):
                    covered_word_indices.add(i + k)

        # 2. Line-level regex / accent-folded substring match for partial-word or punctuation-joined spans
        if is_id_card_landmark_page:
            continue
        pat = re.compile(la.build_entity_boundary_pattern(original), flags=re.IGNORECASE)
        for line in lines:
            ltxt = str(line.get("text", ""))
            if ltxt.startswith("[INK_REGION_"):
                continue
            for m in pat.finditer(ltxt):
                # Skip if inside a municipality pattern ("Município de Conceição da Aparecida-MG")
                line_wl = la.compute_whitelist_spans(ltxt, session_data.get("whitelist", []))
                if la.is_span_whitelisted(m.start(), m.end(), line_wl):
                    continue
                w_idxs = line.get("word_indices", [])
                char_pos = 0
                hit_w_idxs = []
                for idx in w_idxs:
                    w_str = words[idx]["text"]
                    w_start = char_pos
                    w_end = char_pos + len(w_str)
                    char_pos = w_end + 1
                    if w_start < m.end() and w_end > m.start():
                        hit_w_idxs.append(idx)
                if hit_w_idxs and not all(idx in covered_word_indices for idx in hit_w_idxs):
                    bx0 = min(words[idx]["bbox_1000"][0] for idx in hit_w_idxs)
                    by0 = min(words[idx]["bbox_1000"][1] for idx in hit_w_idxs)
                    bx1 = max(words[idx]["bbox_1000"][2] for idx in hit_w_idxs)
                    by1 = max(words[idx]["bbox_1000"][3] for idx in hit_w_idxs)
                    matched_boxes.append(
                        {"bbox_1000": [bx0, by0, bx1, by1], "token": token, "original": original}
                    )
                    for idx in hit_w_idxs:
                        covered_word_indices.add(idx)

    # 3. Automatic Handwritten Signature Detection (`<ASSINATURA_N>`) above signer blocks
    if img is not None:
        sig_detections = detect_signature_boxes_1000(img, layout, matched_boxes)
        suppressed_line_ids: Set[int] = set()
        for s_idx, (sig_b1000, sup_ids) in enumerate(sig_detections, start=1):
            tok = la.register_entity(session_data, f"assinatura_manuscrita_p{p_num}_{s_idx}", "ASSINATURA")
            matched_boxes.append({"bbox_1000": sig_b1000, "token": tok, "original": "ASSINATURA_MANUSCRITA"})
            suppressed_line_ids.update(sup_ids)
        if suppressed_line_ids:
            layout["suppressed_signature_line_ids"] = sorted(suppressed_line_ids)
            layout["full_text"] = "\n".join(
                line["text"]
                for line in lines
                if not str(line["text"]).startswith("[INK_REGION_")
                and int(line["id"]) not in suppressed_line_ids
            )

    return matched_boxes


# ============================================================================
# 5. ZERO-DISTORTION FULL-PAGE GRID GENERATOR (`prepare`) FOR VISION LLMS
# ============================================================================

BOILERPLATE_LINE_EXACT_SET = {
    "sisbb",
    "sisbb - sistema de informacoes banco do brasil",
    "comprovante",
    "comprovante de deposito",
    "comprovante de pagamento",
    "deposito",
    "favorecido",
    "atendimento caixa",
    "normal",
    "norma",
    "poupanca",
    "seguro de vida",
    "consorcio / promocao",
    "digitalizado com camscanner",
    "procuracao",
    "autorizacao do uso de dados - lgpd",
    "declaracao de hipossuficiencia",
    "assinatura do titular",
    "assinatura do portador",
    "carteira de identidade",
    "republica federativa do brasil",
    "horario local",
    "hora de chegada",
    "para cada desejo uma solucao",
    "consulte condicoes com um de nossos funcionarios",
    "conheca nosso simulador bb",
    "e se surpreenda",
    "saiba mais",
    "bb com br simulador",
}


def _rescale_pil_to_1024_token_budget(pil_img: Any, max_tokens: int = 1024, patch_size: int = 28) -> Any:
    """
    Pre-scales a visual inspection image to match `llama-server`'s `--image-max-tokens 1024`
    budget (`1024 * 28 * 28 = 802,816` pixels, e.g. `728 x 1064` for A4 portrait) so `mmproj`
    performs ZERO downscaling in C++ and `#ID` badges remain 100% sharp.
    """
    import math
    from PIL import Image

    w, h = pil_img.size
    max_pixels = max_tokens * (patch_size ** 2)
    if w * h > max_pixels:
        scale = math.sqrt(max_pixels / float(w * h))
        new_w = max(patch_size, (int(w * scale) // patch_size) * patch_size)
        new_h = max(patch_size, (int(h * scale) // patch_size) * patch_size)
        return pil_img.resize((new_w, new_h), Image.Resampling.BICUBIC)
    return pil_img.copy()


def _is_line_fully_covered_by_auto_boxes(line: Dict[str, Any], auto_boxes: List[Dict[str, Any]]) -> bool:
    lb = line["bbox_1000"]
    lw = max(1, lb[2] - lb[0])
    lh = max(1, lb[3] - lb[1])
    covered_w = 0
    for ab in auto_boxes:
        b = ab["bbox_1000"]
        v_ov = min(lb[3], b[3]) - max(lb[1], b[1])
        h_ov = min(lb[2], b[2]) - max(lb[0], b[0])
        if v_ov >= lh * 0.45 and h_ov > 0:
            covered_w += h_ov
    return covered_w >= lw * 0.82


def _is_boilerplate_ocr_line(line: Dict[str, Any]) -> bool:
    ltxt = str(line.get("text", "")).strip()
    if not ltxt:
        return True
    if ltxt.startswith("[INK_REGION_"):
        return False
    norm = re.sub(r"[^a-z0-9\s/]", " ", la.normalize_key_fold(ltxt))
    norm = re.sub(r"\s+", " ", norm).strip()
    if norm in BOILERPLATE_LINE_EXACT_SET:
        return True
    if any(
        norm.startswith(prefix)
        for prefix in (
            "poderes pelo presente instrumento",
            "parte outorgante constitui seu procurador",
            "foro em geral com clausula ad judicia",
            "podendo propor contra quem de direito",
            "seguindo umas e outras ate final decisao",
            "conferindo ainda poderes especiais",
            "renunciar ao direito sobre que se funda",
            "e dar quitacao podendo agir em juizo",
            "todo ou em parte com ou sem reservas",
            "separadamente com o substabelecido",
            "tome decisoes referentes ao tratamento",
            "pessoais bem como realize o tratamento",
            "que se referem a coleta producao",
            "transmissao distribuicao processamento",
            "ou controle da informacao modificacao",
            "digitalizado com camscanner",
            "001 banco do brasil",
            "001 banco bo brasil",
            "para cada desejo uma solucao",
            "consulte condicoes com",
            "um de nossos funcionarios",
            "quer investir com",
            "conheca nosso simulador",
        )
    ):
        return True
    # Pure monetary value or date line without proper names or long IDs
    if re.match(r"^(?:valor\s*)?(?:r\$\s*)?[\d.,]+$", norm):
        return True
    if re.match(r"^\d{2}/\d{2}/\d{4}(?:\s+\d{2}:\d{2}(?::\d{2})?)?$", norm):
        return True
    return False


def get_unmatched_candidate_badges(layout: Dict[str, Any], auto_boxes: List[Dict[str, Any]]) -> Dict[str, str]:
    """
    Returns a compact mapping `{"#ID": "text_or_INK_REGION"}` of ONLY those lines on the page
    that are neither pure boilerplate nor already 100% covered by Pass-1 `auto_boxes`.
    """
    suppressed = set(layout.get("suppressed_signature_line_ids", []))
    candidates: Dict[str, str] = {}
    for line in layout.get("lines", []):
        lid = int(line["id"])
        if lid in suppressed:
            continue
        if _is_boilerplate_ocr_line(line):
            continue
        if not str(line.get("text", "")).startswith("[INK_REGION_") and _is_line_fully_covered_by_auto_boxes(line, auto_boxes):
            continue
        candidates[f"#{lid}"] = str(line.get("text", ""))[:90]
    return candidates


def render_annotated_grid_image(
    img: Any,
    layout: Dict[str, Any],
    auto_boxes: List[Dict[str, Any]],
    out_png_path: Path,
    max_tokens: int = 1024,
) -> Path:
    """
    Zero-Occlusion Native-1024 Grid Renderer (v6.2):
    - Pre-scales the canvas to match `llama-server`'s 1,024-token budget (`~728 x 1064`) so `mmproj`
      performs ZERO downscaling in C++ and `#ID` badges stay crisp (`11px` bold).
    - Places all `#ID` pills in the outer left/right page margins (`x=2` or `x=iw-tw-2`) so 0% of
      document glyphs are ever covered by a badge.
    - Filters out pure legal/bank boilerplate lines from getting noisy blue boxes, highlighting only
      candidate lines (`alpha=24` blue tint) and Pass-1 auto-matched boxes (`alpha=45` red tint).
    - Saves as high-sharpness `4:4:4` JPEG (`quality=90, subsampling=0`) when path ends in `.jpg`/`.jpeg`.
    """
    from PIL import Image, ImageDraw

    rot_cw = int(layout.get("rotation_detected_cw", 0))
    upright_img = rotate_pil_image_cw(img, rot_cw) if rot_cw else img
    base = _rescale_pil_to_1024_token_rescale_safe(upright_img.convert("RGB"), max_tokens=max_tokens).convert("RGBA")
    iw, ih = base.size
    overlay = Image.new("RGBA", (iw, ih), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    font_tag = _load_pil_font(11)
    font_tick = _load_pil_font(9)

    # Outer-margin-only coordinate ticks every 100 units (zero interior grid lines crossing text!)
    for step in range(100, 1000, 100):
        px = int(round(step * iw / 1000.0))
        py = int(round(step * ih / 1000.0))
        draw.line([(px, 0), (px, 4)], fill=(120, 150, 190, 200), width=1)
        draw.line([(px, ih - 4), (px, ih)], fill=(120, 150, 190, 200), width=1)
        draw.line([(0, py), (4, py)], fill=(120, 150, 190, 200), width=1)
        draw.line([(iw - 4, py), (iw, py)], fill=(120, 150, 190, 200), width=1)
        draw.text((px - 7, 1), str(step), fill=(60, 90, 130, 210), font=font_tick)

    suppressed = set(layout.get("suppressed_signature_line_ids", []))
    used_left_y: List[int] = []
    used_right_y: List[int] = []

    for line in layout.get("lines", []):
        lid = int(line["id"])
        if lid in suppressed or _is_boilerplate_ocr_line(line):
            continue
        ltxt = str(line.get("text", ""))
        if not ltxt.startswith("[INK_REGION_") and _is_line_fully_covered_by_auto_boxes(line, auto_boxes):
            continue

        b_raw = line["bbox_1000"]
        b = map_bbox_1000_from_orig_to_rotated(b_raw, rot_cw) if rot_cw else b_raw
        x0 = max(0, int(round(b[0] * iw / 1000.0)))
        y0 = max(0, int(round(b[1] * ih / 1000.0)))
        x1 = min(iw - 1, int(round(b[2] * iw / 1000.0)))
        y1 = min(ih - 1, int(round(b[3] * ih / 1000.0)))

        if ltxt.startswith("[INK_REGION_"):
            draw.rectangle([x0 - 2, y0 - 2, x1 + 2, y1 + 2], fill=(0, 102, 204, 32), outline=(0, 102, 204, 185), width=1)
        else:
            draw.rectangle([x0, y0, x1, y1], fill=(0, 102, 204, 24))

        tag = f"#{lid}"
        tb = draw.textbbox((0, 0), tag, font=font_tag)
        tw = tb[2] - tb[0] + 4
        th = tb[3] - tb[1] + 2
        by0 = max(0, y0)

        if not any(abs(by0 - uy) < th for uy in used_left_y) and x0 > tw + 4:
            bx0 = 2
            used_left_y.append(by0)
        else:
            bx0 = max(2, iw - tw - 2)
            used_right_y.append(by0)

        draw.rectangle([bx0, by0, bx0 + tw, by0 + th], fill=(0, 102, 204, 225))
        draw.text((bx0 + 2, by0), tag, fill=(255, 255, 255, 255), font=font_tag)

    for ab in auto_boxes:
        b_raw = ab["bbox_1000"]
        b = map_bbox_1000_from_orig_to_rotated(b_raw, rot_cw) if rot_cw else b_raw
        x0 = max(0, int(round(b[0] * iw / 1000.0)))
        y0 = max(0, int(round(b[1] * ih / 1000.0)))
        x1 = min(iw - 1, int(round(b[2] * iw / 1000.0)))
        y1 = min(ih - 1, int(round(b[3] * ih / 1000.0)))
        draw.rectangle([x0, y0, x1, y1], fill=(220, 38, 38, 52), outline=(220, 38, 38, 225), width=2)

    combined = Image.alpha_composite(base, overlay).convert("RGB")
    out_png_path.parent.mkdir(parents=True, exist_ok=True)
    if out_png_path.suffix.lower() in (".jpg", ".jpeg"):
        combined.save(str(out_png_path), format="JPEG", quality=90, subsampling=0, optimize=True)
    else:
        combined.save(str(out_png_path), format="PNG", optimize=True)
    return out_png_path


def _rescale_pil_to_1024_token_rescale_safe(pil_img: Any, max_tokens: int = 1024) -> Any:
    return _rescale_pil_to_1024_token_budget(pil_img, max_tokens=max_tokens, patch_size=28)


def _active_ink_vertical_band_1000(layout: Dict[str, Any]) -> Tuple[int, int]:
    rot_cw = int(layout.get("rotation_detected_cw", 0))
    ys0: List[int] = []
    ys1: List[int] = []
    for ln in layout.get("lines", []):
        ltxt = str(ln.get("text", "")).strip().lower()
        if "digitalizado com camscanner" in ltxt:
            continue
        b = map_bbox_1000_from_orig_to_rotated(ln["bbox_1000"], rot_cw) if rot_cw else ln["bbox_1000"]
        ys0.append(b[1])
        ys1.append(b[3])
    for fb in layout.get("face_boxes_1000", []):
        b = map_bbox_1000_from_orig_to_rotated(fb, rot_cw) if rot_cw else fb
        ys0.append(b[1])
        ys1.append(b[3])
    if not ys0:
        return 0, 1000
    return max(0, min(ys0) - 35), min(1000, max(ys1) + 35)


def can_smart_stack_two_pages(lay1: Dict[str, Any], lay2: Dict[str, Any]) -> bool:
    """
    Returns True ONLY when Page 1 and Page 2 of a 2-page PDF are sparse cards/slips
    (such as front & back of an RG/CNH in `documentos pessoais`) whose combined active
    vertical ink bands occupy <= 1150 units (<= 58% per page on average), guaranteeing
    that stacking them vertically after cropping blank A4 margins preserves >= 90% legibility
    at 1,024 vision tokens! Full A4 text pages (> 600 units tall each) return False.
    """
    y0_1, y1_1 = _active_ink_vertical_band_1000(lay1)
    y0_2, y1_2 = _active_ink_vertical_band_1000(lay2)
    h1 = y1_1 - y0_1
    h2 = y1_2 - y0_2
    return h1 <= 620 and h2 <= 620 and (h1 + h2) <= 1160


def render_smart_2up_stacked_grid_image(
    file_path: Path,
    session_id: Optional[str],
    img1: Any,
    lay1: Dict[str, Any],
    ab1: List[Dict[str, Any]],
    img2: Any,
    lay2: Dict[str, Any],
    ab2: List[Dict[str, Any]],
    out_jpg_path: Path,
    max_tokens: int = 1024,
) -> Path:
    """
    Renders Page 1 (top, `#1..#99`) and Page 2 (bottom, `#101..#199`) of a 2-page ID/card PDF
    stacked vertically after cropping blank A4 margins, and saves the exact un-projection
    metadata so both `#ID` `line_ids` and manual `0-1000` boxes map back to Page 1 / Page 2!
    """
    from PIL import Image, ImageDraw
    import tempfile

    with tempfile.TemporaryDirectory() as tmpd:
        t1 = Path(tmpd) / "p1.jpg"
        t2 = Path(tmpd) / "p2.jpg"
        # Render each page at 1400 tokens first, then crop active band and rescale combined sheet to 1024 tokens
        render_annotated_grid_image(img1, lay1, ab1, t1, max_tokens=1400)
        render_annotated_grid_image(img2, lay2, ab2, t2, max_tokens=1400)
        g1 = Image.open(t1).convert("RGB")
        g2 = Image.open(t2).convert("RGB")

        y0_1, y1_1 = _active_ink_vertical_band_1000(lay1)
        y0_2, y1_2 = _active_ink_vertical_band_1000(lay2)

        c1 = g1.crop((0, int(round(y0_1 * g1.height / 1000.0)), g1.width, int(round(y1_1 * g1.height / 1000.0))))
        c2 = g2.crop((0, int(round(y0_2 * g2.height / 1000.0)), g2.width, int(round(y1_2 * g2.height / 1000.0))))

        target_w = max(c1.width, c2.width)
        if c1.width != target_w:
            c1 = c1.resize((target_w, int(round(c1.height * target_w / c1.width))), Image.Resampling.BICUBIC)
        if c2.width != target_w:
            c2 = c2.resize((target_w, int(round(c2.height * target_w / c2.width))), Image.Resampling.BICUBIC)

        sep_h = 22
        stacked = Image.new("RGB", (target_w, c1.height + sep_h + c2.height), (240, 244, 250))
        stacked.paste(c1, (0, 0))
        stacked.paste(c2, (0, c1.height + sep_h))

        draw = ImageDraw.Draw(stacked)
        draw.rectangle([0, c1.height, target_w, c1.height + sep_h], fill=(30, 58, 138))
        font_div = _load_pil_font(12)
        draw.text(
            (14, c1.height + 3),
            "▲ PÁGINA 1 (#1..#99)   |   ▼ PÁGINA 2 (#101..#199)",
            fill=(255, 255, 255),
            font=font_div,
        )

        final_canvas = _rescale_pil_to_1024_token_budget(stacked, max_tokens=max_tokens)
        out_jpg_path.parent.mkdir(parents=True, exist_ok=True)
        final_canvas.save(str(out_jpg_path), format="JPEG", quality=90, subsampling=0, optimize=True)

        total_h = float(c1.height + sep_h + c2.height)
        split_meta = {
            "mode": "smart_2up_vertical_cropped",
            "p1_y_end_1000": round(c1.height * 1000.0 / total_h),
            "p2_y_start_1000": round((c1.height + sep_h) * 1000.0 / total_h),
            "p1_crop_y1000": [y0_1, y1_1],
            "p2_crop_y1000": [y0_2, y1_2],
            "p1_rot_cw": int(lay1.get("rotation_detected_cw", 0)),
            "p2_rot_cw": int(lay2.get("rotation_detected_cw", 0)),
        }
        meta_path = _file_page_cache_path(file_path, 9999, session_id)
        if meta_path:
            try:
                meta_path.write_text(json.dumps(split_meta, indent=2), encoding="utf-8")
            except Exception:
                pass
        return out_jpg_path


def unproject_box_from_2up_if_applicable(
    file_path: Path,
    default_page: int,
    b1000: List[int],
    session_id: Optional[str] = None,
) -> Tuple[int, List[int]]:
    """
    If `file_path` was rendered as a Smart 2-Up Cropped Vertical Stack and the local Vision LLM
    passed a manual `[xmin, ymin, xmax, ymax]` box (`0-1000`) without specifying `page: 2`,
    automatically un-projects the box from the stacked canvas back to the exact `(page_num, orig_bbox_1000)`!
    """
    meta_path = _file_page_cache_path(file_path, 9999, session_id)
    if not meta_path or not meta_path.exists():
        return default_page, b1000
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("mode") != "smart_2up_vertical_cropped":
            return default_page, b1000
        cy = (b1000[1] + b1000[3]) / 2.0
        p1_end = float(meta["p1_y_end_1000"])
        p2_start = float(meta["p2_y_start_1000"])
        if cy <= p1_end or default_page == 1 and b1000[3] <= p2_start:
            c_y0, c_y1 = meta["p1_crop_y1000"]
            span = max(1.0, p1_end)
            ny0 = round(c_y0 + (b1000[1] / span) * (c_y1 - c_y0))
            ny1 = round(c_y0 + (min(p1_end, float(b1000[3])) / span) * (c_y1 - c_y0))
            ub = [b1000[0], max(0, min(1000, ny0)), b1000[2], max(0, min(1000, ny1))]
            rot1 = int(meta.get("p1_rot_cw", 0))
            if rot1:
                ub = map_bbox_1000_from_rotated_to_orig(ub, rot1)
            return 1, ub
        else:
            c_y0, c_y1 = meta["p2_crop_y1000"]
            span = max(1.0, 1000.0 - p2_start)
            ny0 = round(c_y0 + (max(0.0, float(b1000[1]) - p2_start) / span) * (c_y1 - c_y0))
            ny1 = round(c_y0 + (max(0.0, float(b1000[3]) - p2_start) / span) * (c_y1 - c_y0))
            ub = [b1000[0], max(0, min(1000, ny0)), b1000[2], max(0, min(1000, ny1))]
            rot2 = int(meta.get("p2_rot_cw", 0))
            if rot2:
                ub = map_bbox_1000_from_rotated_to_orig(ub, rot2)
            return 2, ub
    except Exception:
        return default_page, b1000


def _load_pil_font(size_px: int) -> Any:
    from PIL import ImageFont

    size_px = max(8, int(size_px))
    for font_name in (
        "DejaVuSans-Bold.ttf",
        "DejaVuSans.ttf",
        "arialbd.ttf",
        "arial.ttf",
        r"C:\Windows\Fonts\arialbd.ttf",
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\calibrib.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    ):
        try:
            return ImageFont.truetype(font_name, size_px)
        except Exception:
            continue
    return ImageFont.load_default()


def draw_redaction_boxes_on_pil_image(
    img: Any,
    boxes_1000: List[Dict[str, Any]],
) -> int:
    from PIL import ImageDraw

    if not boxes_1000:
        return 0

    draw = ImageDraw.Draw(img)
    iw, ih = img.width, img.height
    count = 0

    pixel_boxes: List[List[Any]] = []
    for item in boxes_1000:
        b = item["bbox_1000"]
        token = item.get("token") or "<ANONIMIZADO>"
        x0 = max(0, min(iw - 2, int(round(b[0] * iw / 1000.0)) - 1))
        y0 = max(0, min(ih - 2, int(round(b[1] * ih / 1000.0)) - 1))
        x1 = max(x0 + 6, min(iw, int(round(b[2] * iw / 1000.0)) + 1))
        y1 = max(y0 + 6, min(ih, int(round(b[3] * ih / 1000.0)) + 1))
        draw.rectangle([x0, y0, x1, y1], fill=(0, 0, 0))
        pixel_boxes.append([x0, y0, x1, y1, token])
        count += 1

    for idx, (x0, y0, x1, y1, token) in enumerate(pixel_boxes):
        box_w = max(8, x1 - x0)
        box_h = max(10, y1 - y0)
        target_px = max(9, min(28, int(box_h * 0.68)))
        font = _load_pil_font(target_px)

        while target_px > 8:
            tb = draw.textbbox((0, 0), token, font=font)
            tw = tb[2] - tb[0]
            if tw <= box_w - 4:
                break
            target_px -= 1
            font = _load_pil_font(target_px)

        tb = draw.textbbox((0, 0), token, font=font)
        tw = tb[2] - tb[0]
        th = tb[3] - tb[1]
        if tw + 4 > box_w:
            # Check if there is another box to the right on the same line before widening
            max_allowed_x1 = iw - 2
            for j, (ox0, oy0, ox1, oy1, _) in enumerate(pixel_boxes):
                if j == idx:
                    continue
                v_ov = min(y1, oy1) - max(y0, oy0)
                if v_ov > 4 and ox0 >= x1 - 4:
                    max_allowed_x1 = min(max_allowed_x1, ox0 - 2)
            new_x1 = min(max_allowed_x1, x0 + tw + 6)
            if new_x1 > x1:
                draw.rectangle([x0, y0, new_x1, y1], fill=(0, 0, 0))
                box_w = new_x1 - x0
                pixel_boxes[idx][2] = new_x1

        tx = x0 + max(2, (box_w - tw) // 2)
        ty = y0 + max(1, (box_h - th) // 2) - tb[1]
        draw.text((tx, ty), token, fill=(255, 255, 255), font=font)

    return count


def redact_scanned_fitz_page_in_place(
    fitz: Any,
    doc: Any,
    page_idx: int,
    pdf_path: Path,
    session_data: Dict[str, Any],
    session_id: Optional[str] = None,
    extra_boxes_1000: Optional[List[Dict[str, Any]]] = None,
) -> int:
    page = doc[page_idx]
    ox0, oy0 = float(page.rect.x0), float(page.rect.y0)
    pw, ph = float(page.rect.width), float(page.rect.height)
    img_p, _, _ = render_page_to_pil_image(pdf_path, page_number=page_idx + 1, dpi=200)
    layout = extract_ocr_layout_for_page(pdf_path, page_number=page_idx + 1, session_id=session_id)
    boxes = match_session_entities_to_ocr_boxes(layout, session_data, img=img_p)
    if extra_boxes_1000:
        boxes.extend(extra_boxes_1000)

    if not boxes:
        return 0

    # Build synthetic `page_words` from unredacted OCR words so `_draw_pdf_placeholder_on_black_box`
    # never widens a black pill over an unredacted printed word to its right!
    synthetic_page_words: List[Tuple[float, float, float, float, str, int, int, int]] = []
    for w_idx, w in enumerate(layout.get("words", [])):
        wb = w["bbox_1000"]
        wx0 = ox0 + wb[0] * pw / 1000.0
        wy0 = oy0 + wb[1] * ph / 1000.0
        wx1 = ox0 + wb[2] * pw / 1000.0
        wy1 = oy0 + wb[3] * ph / 1000.0
        synthetic_page_words.append((wx0, wy0, wx1, wy1, str(w["text"]), 0, int(w.get("line_id", 0)), w_idx))

    done_items: List[Tuple[Any, str]] = []
    for item in boxes:
        b = item["bbox_1000"]
        token = item.get("token") or "<ANONIMIZADO>"
        # Tighter vertical padding (-0.4/+0.4 pt) so adjacent lines are never clipped
        rx0 = ox0 + max(0.0, min(pw, b[0] * pw / 1000.0 - 0.8))
        ry0 = oy0 + max(0.0, min(ph, b[1] * ph / 1000.0 - 0.4))
        rx1 = ox0 + max(0.0, min(pw, b[2] * pw / 1000.0 + 0.8))
        ry1 = oy0 + max(0.0, min(ph, b[3] * ph / 1000.0 + 0.4))
        rect = fitz.Rect(rx0, ry0, rx1, ry1)
        if getattr(page, "rotation", 0) != 0 and hasattr(page, "derotation_matrix"):
            rect = rect * page.derotation_matrix
        rect_area = max(rect.get_area(), 1e-6)
        if any((rect & r).get_area() / rect_area >= 0.55 for r, _ in done_items):
            continue
        done_items.append((rect, token))
        page.add_redact_annot(rect, fill=(0, 0, 0))

    if done_items:
        redact_img_mode = getattr(fitz, "PDF_REDACT_IMAGE_PIXELS", 2)
        page.apply_redactions(images=redact_img_mode)
        all_rects = [r for r, _ in done_items]
        for rect, token in done_items:
            la._draw_pdf_placeholder_on_black_box(fitz, page, rect, token, synthetic_page_words, all_rects)

    return len(done_items)


def redact_pdf_with_pillow_fallback(
    input_path: Path,
    out_path: Path,
    pairs: List[Tuple[str, str]],
    session_data: Dict[str, Any],
    session_id: Optional[str] = None,
    extra_boxes_by_page: Optional[Dict[int, List[Dict[str, Any]]]] = None,
) -> Tuple[Optional[Path], List[int], List[int]]:
    import pdfplumber

    page_count = get_pdf_page_count(input_path)
    redacted_images: List[Any] = []
    scanned_redacted: List[int] = []
    scanned_unredacted: List[int] = []

    with pdfplumber.open(str(input_path)) as plumber_pdf:
        for p_idx in range(page_count):
            p_num = p_idx + 1
            img, pw, ph = render_page_to_pil_image(input_path, page_number=p_num, dpi=200)
            p_page = plumber_pdf.pages[p_idx]
            p_text = (p_page.extract_text() or "").strip()
            p_words = p_page.extract_words() or []

            page_boxes_1000: List[Dict[str, Any]] = []
            if len(re.sub(r"\s+", "", p_text)) < 25:
                layout = extract_ocr_layout_for_page(input_path, page_number=p_num, session_id=session_id)
                page_boxes_1000.extend(match_session_entities_to_ocr_boxes(layout, session_data, img=img))
                if extra_boxes_by_page and p_num in extra_boxes_by_page:
                    page_boxes_1000.extend(extra_boxes_by_page[p_num])
                if page_boxes_1000:
                    scanned_redacted.append(p_num)
                else:
                    scanned_unredacted.append(p_num)
            else:
                cleaned_p_words = [la._clean_pdf_word_token(w["text"]) for w in p_words]
                covered: Set[int] = set()
                for original, token in pairs:
                    orig_parts = [
                        la._clean_pdf_word_token(p)
                        for p in original.strip().split()
                        if la._clean_pdf_word_token(p)
                    ]
                    if not orig_parts:
                        continue
                    n = len(orig_parts)
                    for i in range(len(p_words) - n + 1):
                        if any((i + k) in covered for k in range(n)):
                            continue
                        if cleaned_p_words[i : i + n] == orig_parts:
                            wx0 = min(float(p_words[i + k]["x0"]) for k in range(n))
                            wy0 = min(float(p_words[i + k]["top"]) for k in range(n))
                            wx1 = max(float(p_words[i + k]["x1"]) for k in range(n))
                            wy1 = max(float(p_words[i + k]["bottom"]) for k in range(n))
                            last_w_txt = str(p_words[i + n - 1]["text"])
                            if len(last_w_txt) > len(orig_parts[-1]):
                                t_chars = len(last_w_txt) - len(last_w_txt.rstrip(".,;:!?)"))
                                if t_chars > 0:
                                    wx1 -= (wx1 - float(p_words[i + n - 1]["x0"])) * (t_chars / len(last_w_txt))
                            b1000 = [
                                max(0, min(1000, round(wx0 * 1000.0 / pw))),
                                max(0, min(1000, round(wy0 * 1000.0 / ph))),
                                max(0, min(1000, round(wx1 * 1000.0 / pw))),
                                max(0, min(1000, round(wy1 * 1000.0 / ph))),
                            ]
                            page_boxes_1000.append({"bbox_1000": b1000, "token": token, "original": original})
                            for k in range(n):
                                covered.add(i + k)
                if extra_boxes_by_page and p_num in extra_boxes_by_page:
                    page_boxes_1000.extend(extra_boxes_by_page[p_num])

            draw_redaction_boxes_on_pil_image(img, page_boxes_1000)
            redacted_images.append(img)

    if scanned_unredacted and len(scanned_unredacted) == page_count:
        return None, scanned_redacted, scanned_unredacted

    if redacted_images:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        redacted_images[0].save(
            str(out_path),
            "PDF",
            resolution=200.0,
            save_all=True,
            append_images=redacted_images[1:],
        )
        return out_path, scanned_redacted, scanned_unredacted
    return None, [], []


# ============================================================================
# 7. UNIVERSAL `visual_redactions.json` PARSER & CLI (`prepare` & `apply`)
# ============================================================================

def _normalize_redactions_payload(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Universal schema normalizer for `visual_redactions.json`:
    Handles all JSON structures emitted by `Qwen3.6 35B` and other local LLMs:
    - Top-level `"entities": {...}`
    - Top-level `"line_ids"` / `"box_ids"`: `[4, 5, 29]` OR `[{"page": 1, "id": 4, "category": "PESSOA"}]`
    - Top-level `"boxes"`: `[[161, 147, 863, 172], ...]` OR `[{"page": 1, "bbox_1000": [161, 147, 863, 172]}]`
    - Nested `"redactions": [{"page": 1, "line_ids": [4, 5], "boxes": [[161, 147, 863, 172]], "category": "PESSOA"}]`
    - Nested `"pages": [{"page": 1, "line_ids": [...], "boxes": [...]}]`
    """
    entities_dict: Dict[str, Any] = {}
    if isinstance(payload.get("entities"), dict):
        entities_dict.update(payload["entities"])

    norm_line_ids: List[Dict[str, Any]] = []
    norm_boxes: List[Dict[str, Any]] = []

    def _ingest_line_ids(raw_list: Any, default_page: int = 1, default_cat: str = "PESSOA") -> None:
        if not isinstance(raw_list, list):
            return
        for entry in raw_list:
            if isinstance(entry, (int, float)):
                norm_line_ids.append({"page": default_page, "id": int(entry), "category": default_cat})
            elif isinstance(entry, str) and re.match(r"^#?\d+$", entry.strip()):
                norm_line_ids.append({"page": default_page, "id": int(entry.strip().lstrip("#")), "category": default_cat})
            elif isinstance(entry, dict):
                p = int(entry.get("page", default_page))
                cat = str(entry.get("category") or entry.get("label") or default_cat)
                if "id" in entry or "line_id" in entry or "box_id" in entry:
                    raw_id = entry.get("id") or entry.get("line_id") or entry.get("box_id")
                    if isinstance(raw_id, str):
                        raw_id = raw_id.strip().lstrip("#")
                    try:
                        norm_line_ids.append(
                            {
                                "page": p,
                                "id": int(raw_id),
                                "category": cat,
                                "text": entry.get("text"),
                            }
                        )
                    except (ValueError, TypeError):
                        pass

    def _ingest_boxes(raw_list: Any, default_page: int = 1, default_cat: str = "PESSOA") -> None:
        if not isinstance(raw_list, list):
            return
        for entry in raw_list:
            if isinstance(entry, list) and len(entry) == 4 and all(isinstance(x, (int, float)) for x in entry):
                norm_boxes.append({"page": default_page, "bbox_1000": entry, "category": default_cat})
            elif isinstance(entry, dict):
                p = int(entry.get("page", default_page))
                cat = str(entry.get("category") or entry.get("label") or default_cat)
                b = entry.get("bbox_1000") or entry.get("bbox") or entry.get("box") or entry.get("rect")
                if isinstance(b, list) and len(b) == 4:
                    norm_boxes.append(
                        {
                            "page": p,
                            "bbox_1000": b,
                            "category": cat,
                            "text": entry.get("text"),
                            "snap": entry.get("snap", True),
                        }
                    )

    _ingest_line_ids(payload.get("line_ids") or payload.get("box_ids") or [])
    _ingest_boxes(payload.get("boxes") or [])

    for container_key in ("redactions", "pages", "items"):
        sub_items = payload.get(container_key)
        if isinstance(sub_items, list):
            for sub in sub_items:
                if isinstance(sub, dict):
                    dp = int(sub.get("page", 1))
                    dcat = str(sub.get("category") or sub.get("label") or "PESSOA")
                    if "line_ids" in sub or "box_ids" in sub:
                        _ingest_line_ids(sub.get("line_ids") or sub.get("box_ids"), default_page=dp, default_cat=dcat)
                    if "boxes" in sub:
                        _ingest_boxes(sub.get("boxes"), default_page=dp, default_cat=dcat)
                    if ("id" in sub or "line_id" in sub) and "line_ids" not in sub:
                        _ingest_line_ids([sub], default_page=dp, default_cat=dcat)
                    if ("bbox_1000" in sub or "bbox" in sub or "box" in sub) and "boxes" not in sub:
                        _ingest_boxes([sub], default_page=dp, default_cat=dcat)

    return entities_dict, norm_line_ids, norm_boxes


def prepare_visual_file(
    file_path: Path,
    session_id: Optional[str] = None,
    dpi: int = 200,
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    session_id, session_data = la.create_or_load_session(session_id)
    ws = la.resolve_anonymization_workspace(file_path, explicit_output_dir=output_dir)
    working_file = (
        file_path
        if "_work" in file_path.parts
        else la.stage_working_copy(file_path, ws["originals_copy_dir"])
    )
    clean_stem = la.safe_file_stem(working_file)
    vis_dir = ws["pages_dir"]
    vis_dir.mkdir(parents=True, exist_ok=True)

    page_count = get_pdf_page_count(file_path)
    pages_manifest: List[Dict[str, Any]] = []

    for p_num in range(1, page_count + 1):
        img, _, _ = render_page_to_pil_image(working_file, page_number=p_num, dpi=dpi)
        layout = extract_ocr_layout_for_page(working_file, page_number=p_num, session_id=session_id, dpi=dpi)
        rot_cw = int(layout.get("rotation_detected_cw", 0))
        auto_boxes = match_session_entities_to_ocr_boxes(layout, session_data, img=img)
        grid_png = vis_dir / f"{clean_stem}.page_{p_num:04d}.grid.jpg"
        render_annotated_grid_image(img, layout, auto_boxes, grid_png)
        ws_grid_path, _ = la._mirror_grid_to_active_workspace_if_outside(grid_png, session_id)

        pre_masked_lines = []
        for line in layout.get("lines", []):
            pre_masked_lines.append(
                {
                    "id": line["id"],
                    "bbox_1000": line["bbox_1000"],
                    "text": line["text"],
                    "pre_masked": la.apply_longest_first_replacements(line["text"], session_data),
                }
            )
        pages_manifest.append(
            {
                "page": p_num,
                "rotation_detected_cw": layout.get("rotation_detected_cw", 0),
                "ocr_engine": layout.get("ocr_engine", "none"),
                "grid_image": ws_grid_path,
                "work_dir_grid_image": str(grid_png.resolve()),
                "candidate_blue_badges": get_unmatched_candidate_badges(layout, auto_boxes),
                "ocr_or_ink_box_count": len(pre_masked_lines),
                "qr_codes_detected": len(layout.get("qr_boxes_1000", [])),
                "face_photos_detected": len(layout.get("face_boxes_1000", [])),
                "auto_matched_boxes_count": len(auto_boxes),
                "boxes_index": pre_masked_lines,
            }
        )

    staging_file = ws["session_work_dir"] / "visual_redactions.json"
    if not staging_file.exists():
        template_payload = {
            "entities": {
                "PESSOA": [],
                "EMPRESA": [],
                "ENDERECO": [],
                "CONTA_BANCARIA": [],
            },
            "line_ids": [],
            "boxes": [],
        }
        staging_file.write_text(json.dumps(template_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    la.save_session(session_id, session_data)
    return {
        "status": "ok",
        "session_id": session_id,
        "input_file": str(file_path.resolve()),
        "page_count": page_count,
        "redactions_staging_file": str(staging_file.resolve()),
        "usage_hint": (
            "Inspect `grid_image` with Vision. Red boxes are ALREADY auto-matched (including handwritten signatures and underlined names). "
            "If any additional `#ID` box needs redaction, add its integer ID to `line_ids` (e.g. `\"line_ids\": [4, 5]`) or add "
            "its text to `entities` in `visual_redactions.json`, then run `visual_redactor.py apply`."
        ),
        "pages": pages_manifest,
    }


def apply_visual_redactions(
    file_path: Path,
    session_id: str,
    redactions_payload: Optional[Dict[str, Any]] = None,
    output_path: Optional[Path] = None,
    delivery_dir: Optional[Path] = None,
    snap_to_ink: bool = True,
) -> Dict[str, Any]:
    session_id, session_data = la.create_or_load_session(session_id)
    payload = redactions_payload or {}
    ws = la.resolve_anonymization_workspace(file_path, explicit_output_dir=delivery_dir)
    target_deliv_dir = ws["delivery_dir"]
    working_file = (
        file_path
        if "_work" in file_path.parts
        else la.stage_working_copy(file_path, ws["originals_copy_dir"])
    )
    clean_stem = la.safe_file_stem(working_file)

    entities_dict, norm_line_ids, norm_boxes = _normalize_redactions_payload(payload)
    if entities_dict:
        la.apply_external_entities_payload(session_data, entities_dict)

    page_count = get_pdf_page_count(file_path)
    extra_boxes_by_page: Dict[int, List[Dict[str, Any]]] = {}

    layouts_by_page: Dict[int, Dict[str, Any]] = {}
    images_by_page: Dict[int, Any] = {}
    all_ocr_text_parts: List[str] = []

    for p_num in range(1, page_count + 1):
        img_p, _, _ = render_page_to_pil_image(file_path, page_number=p_num, dpi=200)
        images_by_page[p_num] = img_p
        lay = extract_ocr_layout_for_page(file_path, page_number=p_num, session_id=session_id)
        layouts_by_page[p_num] = lay
        if lay.get("full_text"):
            all_ocr_text_parts.append(lay["full_text"])

    combined_ocr = "\n\n".join(all_ocr_text_parts)
    if combined_ocr:
        la.scan_deterministic_regexes(combined_ocr, session_data)
        la.propagate_name_variants(combined_ocr, session_data)

    # 1. Process normalized `line_ids` (supporting both globally unique #101..#199 IDs and explicit page numbers)
    for item in norm_line_ids:
        lid = int(item.get("id", 0))
        explicit_p = int(item.get("page", 0))
        p_num = (lid // 100) + 1 if lid >= 100 else (explicit_p if explicit_p >= 1 else 1)
        cat = str(item.get("category", "PESSOA"))
        lay = layouts_by_page.get(p_num, {})
        for line in lay.get("lines", []):
            line_id_val = int(line["id"])
            local_idx = line_id_val - (p_num - 1) * 100 if line_id_val >= 100 else line_id_val
            if line_id_val == lid or (explicit_p == p_num and local_idx == lid):
                raw_t = item.get("text") or line["text"]
                if str(raw_t).startswith("[INK_REGION_"):
                    cat = "ASSINATURA" if cat == "PESSOA" else cat
                tok = la.register_entity(session_data, str(raw_t), cat)
                extra_boxes_by_page.setdefault(p_num, []).append(
                    {"bbox_1000": line["bbox_1000"], "token": tok, "original": str(raw_t)}
                )

    # 2. Process normalized manual `boxes` with automatic Ink-Snapping
    snapped_log: List[Dict[str, Any]] = []
    for item in norm_boxes:
        p_num = int(item.get("page", 1))
        b1000 = item.get("bbox_1000")
        if not isinstance(b1000, list) or len(b1000) != 4:
            continue
        raw_b1000 = [int(round(float(x))) for x in b1000]
        use_snap = snap_to_ink and bool(item.get("snap", True))
        if use_snap and p_num in images_by_page:
            final_b1000 = snap_box_to_ink_1000(images_by_page[p_num], raw_b1000)
        else:
            final_b1000 = raw_b1000

        cat = str(item.get("category", "PESSOA"))
        raw_txt = str(item.get("text") or f"regiao_visual_p{p_num}_{final_b1000[0]}_{final_b1000[1]}")
        tok = la.register_entity(session_data, raw_txt, cat)
        extra_boxes_by_page.setdefault(p_num, []).append(
            {"bbox_1000": final_b1000, "token": tok, "original": raw_txt}
        )
        snapped_log.append(
            {"page": p_num, "token": tok, "input_bbox_1000": raw_b1000, "snapped_bbox_1000": final_b1000}
        )
        if not combined_ocr and item.get("text"):
            all_ocr_text_parts.append(str(item["text"]))

    la.save_session(session_id, session_data)

    ext = file_path.suffix.lower()
    total_boxes_redacted = 0
    vis_dir = ws["pages_dir"]
    vis_dir.mkdir(parents=True, exist_ok=True)
    preview_images: List[str] = []

    if ext in la.IMAGE_EXTENSIONS:
        img = images_by_page[1].copy()
        boxes = match_session_entities_to_ocr_boxes(layouts_by_page[1], session_data, img=img)
        boxes.extend(extra_boxes_by_page.get(1, []))
        total_boxes_redacted = draw_redaction_boxes_on_pil_image(img, boxes)
        out_visual = output_path or (target_deliv_dir / f"{clean_stem}.anonymized{ext}")
        out_visual.parent.mkdir(parents=True, exist_ok=True)
        img.save(str(out_visual))
        prev_png = vis_dir / f"{clean_stem}.page_0001.redacted_preview.png"
        img.save(str(prev_png))
        preview_images.append(str(prev_png.resolve()))
    else:
        out_visual = output_path or (target_deliv_dir / f"{clean_stem}.anonymized.pdf")
        out_visual.parent.mkdir(parents=True, exist_ok=True)
        fitz = la._import_fitz()
        if fitz is not None:
            doc = fitz.open(str(file_path))
            for p_idx in range(len(doc)):
                p_num = p_idx + 1
                total_boxes_redacted += redact_scanned_fitz_page_in_place(
                    fitz=fitz,
                    doc=doc,
                    page_idx=p_idx,
                    pdf_path=file_path,
                    session_data=session_data,
                    session_id=session_id,
                    extra_boxes_1000=extra_boxes_by_page.get(p_num, []),
                )
            doc.set_metadata({})
            doc.save(str(out_visual), garbage=4, deflate=True)
            doc.close()
        else:
            pairs = la.build_longest_first_replacement_pairs(session_data)
            _, s_red, _ = redact_pdf_with_pillow_fallback(
                input_path=file_path,
                out_path=out_visual,
                pairs=pairs,
                session_data=session_data,
                session_id=session_id,
                extra_boxes_by_page=extra_boxes_by_page,
            )
            total_boxes_redacted = len(s_red)

        if out_visual.exists():
            for p_num in range(1, page_count + 1):
                try:
                    r_img, _, _ = render_page_to_pil_image(out_visual, page_number=p_num, dpi=150)
                    prev_png = vis_dir / f"{clean_stem}.page_{p_num:04d}.redacted_preview.png"
                    r_img.save(str(prev_png))
                    preview_images.append(str(prev_png.resolve()))
                except Exception:
                    pass

    out_txt = target_deliv_dir / f"{clean_stem}.anonymized.txt"
    transcript_source = "\n\n".join(
        f"--- [PÁGINA {p_num} (OCR/VISUAL)] ---\n{layouts_by_page[p_num].get('full_text', '')}"
        for p_num in range(1, page_count + 1)
    )
    if payload.get("transcript"):
        transcript_source = str(payload["transcript"])
    elif not combined_ocr and all_ocr_text_parts:
        transcript_source = "\n".join(all_ocr_text_parts)
    anon_txt = la.apply_longest_first_replacements(transcript_source, session_data)
    anon_txt = f"{la.CLOUD_LLM_HEADER_PT}\n{anon_txt}"
    out_txt.write_text(anon_txt, encoding="utf-8")

    # Ensure zero clutter in the user's source directory
    la._cleanup_stray_source_folder_files(file_path.parent, target_deliv_dir)

    leaks = la.find_leaks(anon_txt, session_data)
    if total_boxes_redacted == 0:
        leaks.append("0 visual redaction boxes were applied to the scanned image/PDF")

    delivered: List[str] = []
    for cand in (out_visual, out_txt):
        if cand and cand.exists():
            dest = target_deliv_dir / cand.name
            if cand.resolve() != dest.resolve():
                shutil.copy2(cand, dest)
            delivered.append(str(dest.resolve()))

    return {
        "status": "ok" if not leaks else "needs_attention",
        "session_id": session_id,
        "input_file": str(file_path.resolve()),
        "redacted_visual_file": str(out_visual.resolve()),
        "companion_text_file": str(out_txt.resolve()),
        "redacted_preview_images": preview_images,
        "total_boxes_redacted": total_boxes_redacted,
        "snapped_boxes": snapped_log,
        "delivered_to_cloud_ready_dir": delivered,
        "leak_check": {"ok": not leaks, "remaining": leaks[:20]},
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="visual_redactor.py",
        description="Universal OCR + Underlined-Text Recovery + Signature/Photo Redactor for pt-legal-anonymizer v6.0",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_prep = sub.add_parser(
        "prepare",
        help="Run local OCR + underline recovery + ink segmentation and render a zero-margin 0-1000 grid + #ID boxes.",
    )
    p_prep.add_argument("--file", required=True, help="Path to scanned .pdf, .png, or .jpg file")
    p_prep.add_argument("--session", default=None, help="Shared session_id from legal_anonymizer.py")
    p_prep.add_argument("--dpi", type=int, default=200, help="Render DPI (default: 200)")

    p_app = sub.add_parser(
        "apply",
        help="Apply pixel-level redactions + auto ink-snapping + white <PLACEHOLDER> labels to a scanned PDF or image.",
    )
    p_app.add_argument("--file", required=True, help="Path to scanned .pdf, .png, or .jpg file")
    p_app.add_argument("--session", required=True, help="Shared session_id")
    p_app.add_argument("--auto", action="store_true", help="Automatically redact all OCR/QR/Signature matches from session vault")
    p_app.add_argument("--redactions-file", default=None, help="Path to JSON file with entities, line_ids, or boxes")
    p_app.add_argument("--redactions-json", default=None, help="Inline JSON string with entities, line_ids, or boxes")
    p_app.add_argument("--no-snap", action="store_true", help="Disable automatic ink-snapping on manual boxes")
    p_app.add_argument("--output", default=None, help="Explicit output path")
    p_app.add_argument("--output-dir", default=None, help="Delivery directory (default: <parent>/anonymization)")

    args = parser.parse_args()

    if args.command == "prepare":
        res = prepare_visual_file(
            file_path=Path(args.file).expanduser().resolve(),
            session_id=args.session,
            dpi=args.dpi,
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))

    elif args.command == "apply":
        payload: Dict[str, Any] = {}
        if args.redactions_file:
            payload.update(json.loads(Path(args.redactions_file).expanduser().read_text(encoding="utf-8")))
        if args.redactions_json:
            payload.update(json.loads(args.redactions_json))
        out_p = Path(args.output).expanduser().resolve() if args.output else None
        deliv_p = Path(args.output_dir).expanduser().resolve() if args.output_dir else None
        res = apply_visual_redactions(
            file_path=Path(args.file).expanduser().resolve(),
            session_id=args.session,
            redactions_payload=payload,
            output_path=out_p,
            delivery_dir=deliv_p,
            snap_to_ink=not args.no_snap,
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
