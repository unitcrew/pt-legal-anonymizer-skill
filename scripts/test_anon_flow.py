#!/usr/bin/env python3
"""Self-test of anon.py with SYNTHETIC data only (never put real client data in this repository).

Run: python scripts/test_anon_flow.py   (needs pymupdf, Pillow, python-docx; tesseract for the scanned page)
It builds a folder named with accents, starts the job through a misspelled path, goes page by page like the model
would (drop, add, look, done) and checks the outputs contain no hidden value.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAME, CPF, PHONE = "Joana Pereira Lima", "123.456.789-09", "(11) 98765-4321"


def run(*args: str, ok: bool = True) -> str:
    p = subprocess.run([sys.executable, str(HERE / "anon.py"), *args], capture_output=True, text=True, encoding="utf-8")
    out = p.stdout + p.stderr
    if ok and p.returncode != 0:
        raise AssertionError(f"anon.py {' '.join(args)} failed:\n{out}")
    return out


def main() -> None:
    import docx
    import pymupdf
    from PIL import Image, ImageDraw, ImageFont

    tmp = Path(tempfile.mkdtemp(prefix="anon_test_"))
    os.environ["PT_LEGAL_ANONYMIZER_HOME"] = str(tmp / "vault")
    case = tmp / "ações 2026"
    case.mkdir()
    # 1) a text PDF
    pdf = pymupdf.open()
    pg = pdf.new_page()
    pg.insert_text((72, 100), f"Autora: {NAME}, CPF {CPF}, telefone {PHONE}.", fontsize=11)
    pg.insert_text((72, 130), "Comarca de Testeville - 1a Vara Civel", fontsize=11)
    pdf.save(str(case / "a_inicial.pdf"))
    # 2) a "scanned" page (an image, no text layer)
    img = Image.new("RGB", (1240, 1754), "white")
    dr = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("DejaVuSans.ttf", 34)
    except OSError:
        font = ImageFont.load_default()
    dr.text((120, 200), "NOME COMPLETO", fill="black", font=font)
    dr.text((120, 250), NAME.upper(), fill="black", font=font)
    dr.text((120, 400), f"CPF {CPF}", fill="black", font=font)
    img.save(case / "b_scan.png")
    # 3) a docx with the name in the header
    d = docx.Document()
    d.sections[0].header.paragraphs[0].text = f"Cliente {NAME}"
    d.add_paragraph(f"{NAME}, inscrita no CPF {CPF}, residente na Rua das Flores, nº 45.")
    d.save(str(case / "c_peticao.docx"))

    out = run("start", "--dir", str(tmp / "acoes 2026"))           # misspelled on purpose
    assert "usei a pasta real" in out and "D1-P1" in out, out
    assert "ERRO" in run("done", "--note", "teste antes de olhar", ok=False)   # done before looking is refused
    pages = 0
    while True:
        out = run("page")
        if "Não há página atual" in out:
            break
        pages += 1
        assert pages < 10, "too many pages"
        extra = ["--add", NAME] if NAME.lower() not in out.lower() else []
        res = run("apply", *extra)
        assert "resultado FINAL" in res, res
        res = run("done", "--note", "nome e documentos ocultados")
        if "TODOS os documentos" in res:
            break
    outs = list((case / "anonymization").glob("*anonimizado*"))
    assert len(outs) == 3, outs
    for f in outs:
        if f.suffix == ".pdf":
            text = "\n".join(p.get_text() for p in pymupdf.open(str(f)))
        elif f.suffix == ".docx":
            dd = docx.Document(str(f))
            text = "\n".join(p.text for p in dd.paragraphs) + dd.sections[0].header.paragraphs[0].text
        else:
            text = ""
        for secret in (NAME, CPF, "98765", "Flores"):
            assert secret not in text, f"{secret} leaked in {f.name}: {text[:300]}"
        if f.suffix == ".pdf":
            assert "Testeville" in text, "the court line must stay readable"
    print(f"ok: {pages} pages, outputs: {[f.name for f in outs]}")
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
