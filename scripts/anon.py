#!/usr/bin/env python3
"""anon.py: anonymize case documents ONE PAGE AT A TIME, with the model deciding every box.

Why it is built this way (lessons from the earlier versions):
- A model shown many pages at once loses track of them; it shows ONE page (or one text section) and nothing else.
- Fixed automatic redactions the model could not undo made it fight the script. Here the script only SUGGESTS; every
  suggestion can be dropped, and the model can add text, whole lines or rectangles of its own.
- Long paths got mistyped (accents dropped or invented). The folder is given once, to `start`; after that every
  command works on the active job, pages are named by short ids (D1-P2), and a mistyped folder is matched to the real one.
- The page is finished only after the model has looked at the FINAL render (exactly what the output file will show)
  and confirmed it with a note. Then the next page comes, by itself.

Commands (python anon.py <command> ...):
  start --dir FOLDER        begin (or resume) a job for the documents in FOLDER; shows the first page
  page                      show the current page again (image with grid and numbered suggestions)
  apply [--drop S2,S5] [--keep S2] [--add "exact text"] [--add-line L12] [--add-box x0,y0,x1,y1] [--remove A1]
                            change the boxes of the current page and render the final page to look at
  done --note "..."         the final render has no readable personal data: save, then go to the next page
  goto D1-P2                reopen another page
  reset                     back to the suggestions only, on the current page
  status                    where the job is
"""
from __future__ import annotations

import argparse
import copy
import difflib
import hashlib
import json
import os
import re
import sys
import time
import unicodedata
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

try:                                     # Windows consoles: never die on an accent
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # type: ignore[attr-defined]
except Exception:  # noqa: BLE001
    pass

import legal_anonymizer as la            # noqa: E402  (session vault, regex rules, docx rewriting)

PDF_EXT = {".pdf"}
IMG_EXT = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp"}
TXT_EXT = {".txt", ".md"}
DOCX_EXT = {".docx"}
SECTION_CHARS = 2600
VIEW_WIDTH = 1100
MAX_SUGGESTIONS = 45
MAX_LINES_LISTED = 140

# words of forms and legal documents that are never a person's name (keeps headers out of the name suggestions)
_FORM_WORDS = set("""
sistema integrado seguranca publica policia militar civil federal boletim ocorrencia numero fl folha folhas pagina
unidade responsavel registro delegacia comunicacao origem dados atividade natureza fato fatos local data hora inicio
final fim tipo descricao meio utilizado objeto objetos envolvido envolvidos envolvida qualificacao vitima autor autora
autores testemunha testemunhas suspeito suspeita condutor comunicante solicitante noticiante declarante sexo masculino
feminino nacionalidade brasileira brasileiro naturalidade estado uf municipio cidade bairro logradouro rua avenida
travessa rodovia estrada praca alameda complemento cep endereco residencial comercial telefone celular email fone
documento identidade carteira cpf rg cnh cnpj orgao expedidor emissor profissao ocupacao cor pele parda branca preta
amarela indigena estado civil solteiro solteira casado casada divorciado divorciada viuvo viuva uniao estavel escolaridade
fundamental medio superior completo incompleto mae pai filiacao nome nomes apelido idade anos nascimento relacao
relacionamento sem com historico relato narrativa providencia providencias adotadas observacao observacoes anexo anexos
recibo eletronico pendente assinatura assinado assinada digitalmente secretaria secretario ministerio tribunal justica
juizo vara comarca forum processo procedimento inquerito acao autos requerente requerido requerida reu re exequente
executado executada apelante apelado agravante agravado embargante embargado impetrante impetrado advogado advogada
oab defensoria promotoria ministerio publico excelentissimo excelentissima senhor senhora doutor doutora juiz juiza
desembargador desembargadora relator relatora certidao certifico peticao inicial contestacao sentenca despacho decisao
acordao recurso apelacao agravo embargos mandado intimacao citacao audiencia conciliacao instrucao julgamento valor
causa total parcela parcelas contrato clausula clausulas banco agencia conta corrente poupanca credito debito pagamento
cobranca juros multa correcao monetaria empresa sociedade ltda eireli me epp sa companhia comercio industria servicos
representante legal procurador procuradora outorgante outorgado outorgada procuracao substabelecimento vigente
consumado consumada tentado tentada estelionato furto roubo fraude ameaca lesao corporal vantagem economica crime
criminal penal codigo artigo lei decreto resolucao portaria inciso paragrafo alinea capitulo titulo secao republica
federativa brasil governo prefeitura camara assembleia legislativa centro norte sul leste oeste zona rural urbana
residencia morador visitante proprietario proprietaria inquilino locatario locador favor contra referente referencia
protocolo matricula registro geral cartorio oficio tabelionato escritura imovel lote quadra gleba fazenda sitio
chacara apartamento bloco casa sala andar edificio condominio conjunto ordem servico nota fiscal emissao emitido
vencimento competencia periodo atendimento atendente hospital clinica medico medica paciente laudo exame pericia perito
perita quesito quesitos resposta respostas conclusao anexado juntada juntado digitalizado digitalizada camscanner
original copia autenticada pagina pag nao sim outros outras outro outra informacoes informacao geral gerais
nova novo velha velho sao porto belo bela rio monte vila jardim parque vale serra lagoa barra ponte boa bom
""".split())
_CONNECTORS = {"de", "da", "do", "das", "dos", "e", "d", "di", "del", "van", "von"}
_FUNCTION_WORDS = set("""a o os as ao aos à às no na nos nas em por pelo pela pelos pelas para com sem sob sobre se que um
uma uns umas entre ate até apos após seu sua seus suas este esta esse essa isto isso aquele aquela ja já mais menos muito
""".split())
# common Brazilian given names and surnames: an ALL-CAPS run (forms) is suggested as a name only with one of these, or
# under/after a label such as NOME, MÃE, VÍTIMA (form headers in capitals are not names)
_NAME_WORDS = set(x for x in """
ana maria jose joao antonio francisco carlos paulo pedro lucas luiz luis marcos gabriel rafael daniel marcelo bruno
eduardo felipe raimundo rodrigo manoel manuel mateus matheus andre fernando fabio leonardo gustavo guilherme leandro
tiago thiago anderson ricardo jorge alexandre roberto edson diego sergio claudio marcio vitor victor joaquim julio
cesar renato adriano wagner rogerio sebastiao geraldo vinicius henrique heitor arthur davi enzo miguel samuel benjamin
igor caio otavio murilo ruan wesley willian william alan alex jean jefferson junior neto filho sobrinho
francisca antonia adriana juliana marcia fernanda patricia aline sandra camila amanda bruna jessica leticia julia
luciana vanessa mariana gabriela vera kelly simone daniela sonia rosa rosana roseli rosangela tereza teresa lucia
helena beatriz larissa raquel cristina cristiane carla claudia debora denise eliane elaine fabiana flavia gisele
isabel isabela joana josefa luana marta michele monica natalia priscila regina renata sabrina silvana silvia solange
tatiana valeria vitoria alice laura sofia sophia valentina livia cecilia eloa lara manuela heloisa yasmin rita
conceicao aparecida fatima graca gracas lourdes luzia margarida neide neusa sueli tania ivone irene ines ines
silva santos oliveira souza sousa rodrigues ferreira alves pereira lima gomes costa ribeiro martins carvalho almeida
lopes soares fernandes vieira barbosa rocha dias nascimento andrade moreira nunes marques machado mendes freitas
cardoso ramos goncalves santana teixeira araujo cavalcanti campos moura monteiro mello melo batista barros pinto
correia azevedo castro farias faria rezende resende borges moraes morais duarte xavier medeiros miranda guimaraes
siqueira cunha prado reis pires coelho brito fonseca macedo bezerra queiroz leite vasconcelos sampaio aguiar
assis paiva matos mattos peixoto viana tavares lacerda nogueira magalhaes amaral franco vaz salles sales cruz
""".split())
_NAME_LABELS = set(x for x in """nome nomes mae pai filiacao vitima autor autora testemunha envolvido envolvida
condutor comunicante declarante noticiante requerente requerido requerida reu re advogado advogada conjuge
responsavel proprietario proprietaria outorgante outorgado assinante solicitante paciente medico medica""".split())


# ---------------------------------------------------------------------------------------------------------- helpers
def _fold(s: str) -> str:
    s = unicodedata.normalize("NFKD", str(s or ""))
    return "".join(c for c in s if not unicodedata.combining(c)).casefold()


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", _fold(s))


def _out(lines: list[str]) -> None:
    print("\n".join(lines))


def _fail(msg: str, code: int = 2) -> None:
    print("ERRO: " + msg)
    sys.exit(code)


def _vault() -> Path:
    return la.get_vault_root()


def _active_file() -> Path:
    return _vault() / "flow_active.json"


def _script_cmd() -> str:
    return f'python "{Path(__file__).resolve()}"'


def _new_session_data() -> dict[str, Any]:
    return {"session_id": "scratch", "counters": {}, "token_to_original": {}, "surface_to_token": {},
            "canonical_groups": {}, "whitelist": [],
            "stats": {"files_processed": [], "rule_hits": {}, "ignored_false_positives": []}}


def _resolve_dir(raw: str) -> tuple[Path, str]:
    """The folder as given, or the real folder it was meant to be (accents dropped or invented, case, spaces)."""
    p = Path(os.path.expandvars(os.path.expanduser(raw.strip().strip('"').strip("'"))))
    if p.is_dir():
        return p.resolve(), ""
    # walk down from the deepest existing parent, matching each missing part to a real child by its folded form
    parts = list(p.parts)
    cur = Path(parts[0]) if p.is_absolute() else Path.cwd()
    rest = parts[1:] if p.is_absolute() else parts
    fixed = []
    for part in rest:
        nxt = cur / part
        if nxt.exists():
            cur = nxt
            continue
        try:
            kids = [k for k in cur.iterdir() if k.is_dir()]
        except OSError:
            kids = []
        target = _norm(part)
        same = [k for k in kids if _norm(k.name) == target]
        if len(same) != 1:
            close = difflib.get_close_matches(target, [_norm(k.name) for k in kids], n=1, cutoff=0.75)
            same = [k for k in kids if close and _norm(k.name) == close[0]]
        if len(same) != 1:
            names = ", ".join(sorted(k.name for k in kids)[:20])
            _fail(f"a pasta '{part}' não existe em '{cur}'. Pastas que existem ali: {names or '(nenhuma)'}. "
                  "Use o nome exato de uma delas.")
        fixed.append(f"'{part}' -> '{same[0].name}'")
        cur = same[0]
    return cur.resolve(), ("A pasta digitada não existia; usei a pasta real: " + ", ".join(fixed)) if fixed else ""


# ------------------------------------------------------------------------------------------------------ job state
def _load() -> dict[str, Any]:
    af = _active_file()
    if not af.exists():
        _fail(f"nenhum trabalho ativo. Comece com: {_script_cmd()} start --dir \"PASTA\"")
    ptr = json.loads(af.read_text(encoding="utf-8"))
    sp = Path(ptr["state"])
    if not sp.exists():
        _fail(f"o trabalho ativo sumiu ({sp}). Comece de novo com: {_script_cmd()} start --dir \"PASTA\"")
    st = json.loads(sp.read_text(encoding="utf-8"))
    st["_path"] = str(sp)
    return st


def _save(st: dict[str, Any]) -> None:
    sp = Path(st["_path"])
    data = {k: v for k, v in st.items() if k != "_path"}
    tmp = sp.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, sp)


def _work(st: dict[str, Any]) -> Path:
    w = Path(st["work"])
    w.mkdir(parents=True, exist_ok=True)
    return w


def _doc(st: dict[str, Any], pid: str) -> dict[str, Any]:
    return next(d for d in st["docs"] if d["id"] == pid.split("-")[0])


def _units(st: dict[str, Any]) -> list[str]:
    return [u for d in st["docs"] for u in d["units"]]


def _unit_word(doc: dict[str, Any]) -> str:
    return "página" if doc["kind"] in ("pdf", "image") else "trecho"


def _unit_no(pid: str) -> int:
    return int(pid.split("-")[1][1:])


def _plan_marker(st: dict[str, Any]) -> str:
    docs = [{"id": d["id"], "name": d["name"], "unit": _unit_word(d), "units": d["units"],
             "done": [u for u in d["units"] if st["pages"].get(u, {}).get("status") == "done"],
             "output": d.get("output", "")} for d in st["docs"]]
    return "LOCALCHAT_PLAN " + json.dumps({"job": st["job"], "docs": docs, "current": st.get("cur") or ""}, ensure_ascii=False)


# ------------------------------------------------------------------------------------------------------------ start
def cmd_start(a: argparse.Namespace) -> None:
    folder, fixnote = _resolve_dir(a.dir)
    work_root = folder / "anonymization"
    work = work_root / "_work" / "flow"
    sp = work / "state.json"
    if sp.exists() and not a.restart:
        st = json.loads(sp.read_text(encoding="utf-8"))
        st["_path"] = str(sp)
        _active_file().write_text(json.dumps({"state": str(sp)}, ensure_ascii=False), encoding="utf-8")
        lines = ([fixnote] if fixnote else []) + [f"Retomando o trabalho já começado nesta pasta ({_progress(st)})."]
        if not st.get("cur"):
            lines.append("Todos os documentos já estão prontos. Para refazer do zero: start --dir ... --restart")
            lines.append(_plan_marker(st))
            _out(lines)
            return
        _out(lines)
        _show(st)
        return
    files = sorted(f for f in folder.iterdir() if f.is_file() and f.suffix.lower() in PDF_EXT | IMG_EXT | TXT_EXT | DOCX_EXT
                   and not f.name.startswith(("~$", ".")))
    if a.only:
        pats = [x.strip() for x in a.only.split(",") if x.strip()]
        import fnmatch
        files = [f for f in files if any(fnmatch.fnmatch(_fold(f.name), _fold(p)) for p in pats)]
    if not files:
        _fail(f"nenhum documento (.pdf, .docx, .txt, .md ou imagem) em '{folder}'.")
    work.mkdir(parents=True, exist_ok=True)
    session_id = la.create_or_load_session(None)[0]
    st: dict[str, Any] = {"job": hashlib.sha1(str(folder).encode()).hexdigest()[:8], "folder": str(folder),
                          "out": str(work_root), "work": str(work), "session": session_id, "docs": [], "pages": {},
                          "cur": "", "started": time.time(), "_path": str(sp)}
    import pymupdf
    for n, f in enumerate(files, 1):
        did = f"D{n}"
        ext = f.suffix.lower()
        d: dict[str, Any] = {"id": did, "name": f.name, "src": str(f)}
        try:
            if ext in PDF_EXT:
                with pymupdf.open(str(f)) as pdf:
                    if pdf.needs_pass:
                        d["error"] = "o PDF tem senha"
                        n_units = 0
                    else:
                        n_units = pdf.page_count
                d["kind"] = "pdf"
            elif ext in IMG_EXT:
                d["kind"], n_units = "image", 1
            else:
                d["kind"] = "docx" if ext in DOCX_EXT else "text"
                n_units = len(_sections(f, d["kind"]))
        except Exception as exc:  # noqa: BLE001
            d["kind"], n_units, d["error"] = ext.lstrip("."), 0, f"não abriu ({exc.__class__.__name__}: {exc})"
        d["units"] = [f"{did}-P{i}" for i in range(1, n_units + 1)]
        st["docs"].append(d)
    st["cur"] = next(iter(_units(st)), "")
    _save(st)
    _active_file().write_text(json.dumps({"state": str(sp)}, ensure_ascii=False), encoding="utf-8")
    lines = ([fixnote] if fixnote else []) + ["Trabalho iniciado. Documentos (um de cada vez, uma página de cada vez):"]
    for d in st["docs"]:
        lines.append(f"  {d['id']}  {d['name']}  ({len(d['units'])} {_unit_word(d)}{'s' if len(d['units']) != 1 else ''})"
                     + (f"  — PULADO: {d['error']}" if d.get("error") else ""))
    lines.append("Daqui em diante NENHUM comando precisa de caminho de pasta: todos trabalham no trabalho ativo.")
    _out(lines)
    if st["cur"]:
        _show(st)
    else:
        _out([_plan_marker(st)])


def _progress(st: dict[str, Any]) -> str:
    units = _units(st)
    done = sum(1 for u in units if st["pages"].get(u, {}).get("status") == "done")
    return f"{done} de {len(units)} páginas/trechos prontos"


# ------------------------------------------------------------------------------------------- text documents (sections)
def _doc_text_blocks(path: Path, kind: str) -> list[str]:
    if kind == "docx":
        import docx                      # python-docx
        d = docx.Document(str(path))
        blocks = [p.text for p in la.iter_all_docx_paragraphs(d)]
        for sec in d.sections:           # headers and footers carry names and addresses too
            for part in (sec.header, sec.footer):
                try:
                    blocks += [p.text for p in part.paragraphs]
                except Exception:  # noqa: BLE001
                    pass
        return blocks
    raw = path.read_bytes()
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(enc).splitlines()
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace").splitlines()


def _sections(path: Path, kind: str) -> list[str]:
    out, cur = [], ""
    for b in _doc_text_blocks(path, kind):
        if cur and len(cur) + len(b) + 1 > SECTION_CHARS:
            out.append(cur)
            cur = ""
        while len(b) > SECTION_CHARS:             # one huge paragraph: cut at a space
            cut = b.rfind(" ", 0, SECTION_CHARS)
            cut = cut if cut > SECTION_CHARS // 2 else SECTION_CHARS
            out.append(b[:cut])
            b = b[cut:].lstrip()
        cur = (cur + "\n" + b) if cur else b
    if cur.strip() or not out:
        out.append(cur)
    return out


# --------------------------------------------------------------------------------------------- page words and lines
def _page_cache(st: dict[str, Any], pid: str) -> Path:
    return _work(st) / f"{pid}.words.json"


def _page_data(st: dict[str, Any], pid: str) -> dict[str, Any]:
    """Words and lines of a page in page space (0-1000, as the page is displayed), how it is stored, and its upright
    rotation. OCR runs only for the page being worked on."""
    cp = _page_cache(st, pid)
    if cp.exists():
        return json.loads(cp.read_text(encoding="utf-8"))
    d = _doc(st, pid)
    pno = _unit_no(pid)
    if d["kind"] in ("docx", "text"):
        secs = _sections(Path(d["src"]), d["kind"])
        data = {"mode": "text", "text": secs[pno - 1] if pno <= len(secs) else ""}
    else:
        data = _pdf_page_words(st, d, pno)
    cp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return data


def _open_pdf(d: dict[str, Any]):
    import pymupdf
    if d["kind"] == "image":
        img = pymupdf.open(d["src"])
        pdf = pymupdf.open("pdf", img.convert_to_pdf())
        img.close()
        return pdf
    return pymupdf.open(d["src"])


def _pdf_page_words(st: dict[str, Any], d: dict[str, Any], pno: int) -> dict[str, Any]:
    import pymupdf
    with _open_pdf(d) as pdf:
        page = pdf[pno - 1]
        W, H = page.rect.width, page.rect.height
        raw = page.get_text("words")
        text_chars = sum(len(w[4]) for w in raw)
        images = []
        for info in page.get_image_info():
            r = pymupdf.Rect(info["bbox"]) & page.rect
            if r.is_empty:
                continue
            b = [round(r.x0 * 1000 / W), round(r.y0 * 1000 / H), round(r.x1 * 1000 / W), round(r.y1 * 1000 / H)]
            images.append(b)
        if text_chars >= 40 or d["kind"] == "text_pdf":
            mat = page.rotation_matrix
            words, lines, by_line = [], [], {}
            for w in raw:
                r = pymupdf.Rect(w[:4]) * mat
                b = [round(r.x0 * 1000 / W), round(r.y0 * 1000 / H), round(r.x1 * 1000 / W), round(r.y1 * 1000 / H)]
                key = (w[5], w[6])
                if key not in by_line:
                    by_line[key] = len(lines)
                    lines.append({"words": []})
                lines[by_line[key]]["words"].append(len(words))
                words.append({"t": w[4], "b": b})
            return {"mode": "text_pdf", "rot": 0, "words": words, "lines": _finish_lines(words, lines),
                    "images": images, "faces": [], "qr": [], "side": []}
    # a scanned page: OCR (cached by the old engine per session)
    import visual_redactor as vr
    src = Path(d["src"])
    if d["kind"] == "image":
        lay = vr.extract_ocr_layout_for_page(src, page_number=1, session_id=st["session"])
    else:
        lay = vr.extract_ocr_layout_for_page(src, page_number=pno, session_id=st["session"])
    words, lines = [], []
    for ln in lay.get("lines") or []:
        if str(ln.get("text", "")).startswith("[INK_REGION"):
            continue
        idxs = []
        for wi in ln.get("word_indices") or []:
            w = lay["words"][wi]
            t = str(w.get("text") or "").strip()
            if not t:
                continue
            idxs.append(len(words))
            words.append({"t": t, "b": [int(x) for x in w["bbox_1000"]]})
        if idxs:
            lines.append({"words": idxs})
    side = [v["bbox_1000"] for v in lay.get("vertical_boxes_1000") or [] if isinstance(v, dict)]
    return {"mode": "scan", "rot": int(lay.get("rotation_detected_cw", 0)) % 360, "words": words,
            "lines": _finish_lines(words, lines), "images": [], "faces": lay.get("face_boxes_1000") or [],
            "qr": lay.get("qr_boxes_1000") or [], "side": side, "ocr_conf": lay.get("ocr_mean_conf")}


def _finish_lines(words: list[dict[str, Any]], lines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for ln in lines:
        ws = sorted(ln["words"], key=lambda i: words[i]["b"][0])
        bs = [words[i]["b"] for i in ws]
        out.append({"words": ws, "t": " ".join(words[i]["t"] for i in ws),
                    "b": [min(b[0] for b in bs), min(b[1] for b in bs), max(b[2] for b in bs), max(b[3] for b in bs)]})
    out.sort(key=lambda l: (round(l["b"][1] / 8), l["b"][0]))
    for n, ln in enumerate(out, 1):
        ln["id"] = f"L{n}"
        for i in ln["words"]:
            words[i]["ln"] = ln["id"]
    return out


def _union(bs: list[list[int]]) -> list[int]:
    return [min(b[0] for b in bs), min(b[1] for b in bs), max(b[2] for b in bs), max(b[3] for b in bs)]


def _reading_order(data: dict[str, Any]) -> list[int]:
    """Words in reading order: rows by vertical overlap, left to right inside a row."""
    if "_order" in data:
        return data["_order"]
    ws = data["words"]
    idx = sorted(range(len(ws)), key=lambda i: (ws[i]["b"][1] + ws[i]["b"][3]) / 2)
    rows: list[list[int]] = []
    for i in idx:
        b = ws[i]["b"]
        cy = (b[1] + b[3]) / 2
        if rows:
            r = rows[-1]
            top = min(ws[j]["b"][1] for j in r)
            bot = max(ws[j]["b"][3] for j in r)
            if top - 2 <= cy <= bot + 2:
                r.append(i)
                continue
        rows.append([i])
    data["_order"] = [i for r in rows for i in sorted(r, key=lambda j: ws[j]["b"][0])]
    return data["_order"]


def _locate(text: str, data: dict[str, Any], fuzzy: bool = True, loose: bool = False) -> list[list[list[int]]]:
    """Where `text` is written on the page: a list of matches, each a list of boxes (one per line it spans).
    Case, accents, spaces and punctuation don't matter; small OCR errors are tolerated in longer texts, but only
    when the text isn't found as written."""
    hits = _locate_pass(text, data, False)
    if hits or not fuzzy:
        return hits
    hits = _locate_pass(text, data, True)
    return hits if hits or not loose else _locate_pass(text, data, True, loose=True)


def _locate_pass(text: str, data: dict[str, Any], fuzzy: bool, loose: bool = False) -> list[list[list[int]]]:
    target = _norm(text)
    if not target:
        return []
    order = _reading_order(data)
    tol, need = (max(4, len(target) // 3), 0.8) if loose else (max(2, len(target) // 8), 0.86)
    norms = [_norm(data["words"][i]["t"]) for i in order]
    found: list[list[list[int]]] = []
    used: set[int] = set()
    n = len(order)
    for s in range(n):
        if s in used or not norms[s]:
            continue
        acc, best = "", None
        for e in range(s, min(n, s + 14)):
            acc += norms[e]
            if target in acc and acc.find(target) < len(norms[s]):   # starts inside the first word
                best = e
                break
            if fuzzy and len(target) >= 6 and abs(len(acc) - len(target)) <= tol and \
                    acc[:2] == target[:2] and difflib.SequenceMatcher(None, acc, target).ratio() >= need:
                best = e
                break
            if len(acc) > len(target) + tol + 4:
                break
        if best is None:
            continue
        if fuzzy:                                # take in trailing OCR crumbs while the match keeps improving
            r0 = difflib.SequenceMatcher(None, acc, target).ratio()
            while best + 1 < n and norms[best + 1]:
                r1 = difflib.SequenceMatcher(None, acc + norms[best + 1], target).ratio()
                if r1 < r0:
                    break
                acc, r0, best = acc + norms[best + 1], r1, best + 1
        span = order[s:best + 1]
        used.update(range(s, best + 1))
        rows_: list[list[list[int]]] = []
        for i in span:                       # one box per row the text spans
            b = data["words"][i]["b"]
            if rows_ and min(rows_[-1][-1][3], b[3]) - max(rows_[-1][-1][1], b[1]) > -2:
                rows_[-1].append(b)
            else:
                rows_.append([b])
        found.append([_union(r) for r in rows_])
    return found


# ------------------------------------------------------------------------------------------------------ suggestions
def _session(st: dict[str, Any]) -> dict[str, Any]:
    return la.create_or_load_session(st["session"])[1]


def _cat_of_token(tok: str) -> str:
    m = re.match(r"<?([A-Z_]+?)_\d+", tok or "")
    return m.group(1) if m else "DADO"


def _name_runs(text_lines: list[str], label_lines: set[int] | None = None, strict: bool = False) -> list[str]:
    """Runs of 2+ capitalised words that read like a person's name. Title Case runs count by themselves; ALL-CAPS runs
    (forms, headers) only with a common given name or surname in them, or on a line next to a NOME/MÃE/VÍTIMA label."""
    out = []
    for li, line in enumerate(text_lines):
        toks = re.findall(r"[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ'\-]*", line)
        run: list[str] = []
        labelled = bool(label_lines and li in label_lines)

        def flush() -> None:
            while run and _fold(run[-1]) in _CONNECTORS:
                run.pop()
            while run and _fold(run[0]) in _CONNECTORS:
                run.pop(0)
            if run and all(w.isupper() for w in run):        # forms: an OCR crumb or a UF stuck to the ends
                while run and (len(run[0]) < 3 or _fold(run[0]) in _CONNECTORS):
                    run.pop(0)
                while run and (len(run[-1]) < 3 or _fold(run[-1]) in _CONNECTORS):
                    run.pop()
            real = [w for w in run if _fold(w) not in _CONNECTORS]
            if len(real) >= 2 and la.looks_like_person_name(" ".join(run)):
                caps = strict or all(w.isupper() for w in real)
                if not caps or (all(len(w) >= 3 for w in real) and
                                (labelled or any(_fold(w) in _NAME_WORDS for w in real))):
                    out.append(" ".join(run))
            run.clear()

        for t in toks:
            f = _fold(t)
            if f in _CONNECTORS and run:
                run.append(t)
            elif t[0].isupper() and len(t) >= 2 and f not in _FORM_WORDS and f not in _FUNCTION_WORDS \
                    and not re.fullmatch(r"(.)\1{2,}", f):
                run.append(t)
            else:
                flush()
        flush()
    seen, uniq = set(), []
    for r in out:
        k = _norm(r)
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq


def _label_lines(data: dict[str, Any]) -> set[int]:
    """Lines that are the value of a name field: the label is on the line itself, or on a line just above it."""
    lines = data["lines"]
    def is_label(t: str) -> bool:
        ws = re.findall(r"[A-Za-zÀ-ÿ]+", t)
        return 0 < len(ws) <= 6 and any(_fold(w) in _NAME_LABELS for w in ws[:3])
    has = [is_label(l["t"]) for l in lines]
    out = set()
    for i, l in enumerate(lines):
        if has[i]:
            out.add(i)
            continue
        for j, o in enumerate(lines):
            if has[j] and 0 < l["b"][1] - o["b"][1] <= 30 and min(l["b"][2], o["b"][2]) - max(l["b"][0], o["b"][0]) > -20:
                out.add(i)
                break
    return out


def _regex_hits(text: str) -> list[tuple[str, str]]:
    sd = _new_session_data()
    try:
        la.scan_deterministic_regexes(text, sd)
    except Exception:  # noqa: BLE001
        return []
    return [(orig, _cat_of_token(tok)) for tok, orig in sd.get("token_to_original", {}).items()]


def _suggest(st: dict[str, Any], pid: str, data: dict[str, Any]) -> list[dict[str, Any]]:
    sess = _session(st)
    text = data["text"] if data["mode"] == "text" else "\n".join(l["t"] for l in data["lines"])
    cands: list[tuple[str, str, str]] = []           # (text, category, why)
    for tok, orig in sess.get("token_to_original", {}).items():
        if len(_norm(orig)) >= 3:
            cands.append((orig, _cat_of_token(tok), "já ocultado antes"))
            core = re.sub(r"\D", "", orig)
            if len(core) >= 6 and core != _norm(orig):        # the same number written without its prefix or dots
                cands.append((core, _cat_of_token(tok), "já ocultado antes"))
    cands += [(o, c, "padrão") for o, c in _regex_hits(text)]
    for m in re.finditer(r"\b(?:Rua|R\.|Avenida|Av\.?|Travessa|Tv\.|Alameda|Al\.|Rodovia|Estrada|Praça|Praca|Largo|"
                         r"Servidão|Viela|Beco)\s+[^,;\n]{3,60}?(?:,?\s*(?:n[º°o.]*|número|numero)?\s*\d+[A-Za-z]?)",
                         text, re.I):
        cands.append((m.group(0).strip(), "ENDERECO", "parece endereço"))
    this_year = time.localtime().tm_year
    for m in re.finditer(r"\b(\d{1,2})[/.\-](\d{1,2})[/.\-]((?:19|20)\d{2})\b", text):
        if 1900 <= int(m.group(3)) <= this_year - 14:
            cands.append((m.group(0), "DATA_NASCIMENTO", "data antiga: nascimento?"))
    if data["mode"] == "text":
        cands += [(r, "PESSOA", "parece nome") for r in _name_runs(data["text"].splitlines())]
    else:
        cands += [(r, "PESSOA", "parece nome") for r in _name_runs([l["t"] for l in data["lines"]], _label_lines(data),
                                                                  strict=data["mode"] == "scan")]
    items: list[dict[str, Any]] = []
    if data["mode"] == "text":
        low = _fold(text)
        for t, cat, why in sorted(cands, key=lambda c: -len(c[0])):     # longest first: "CEP 12345-678" covers "12345-678"
            if _fold(t) in low and not any(_fold(t) in _fold(x["text"]) for x in items):
                items.append({"cat": cat, "text": t, "why": why})
    else:
        for t, cat, why in cands:
            for boxes in _locate(t, data, fuzzy=why != "parece nome", loose=why == "já ocultado antes" and len(_norm(t)) >= 10):
                boxes = [[x0, min(y0, (y0 + y1) // 2 - 5), x1, max(y1, (y0 + y1) // 2 + 5)] if y1 - y0 < 8 else [x0, y0, x1, y1]
                         for x0, y0, x1, y1 in boxes]       # OCR sometimes gives a word a box 3 units tall
                if any(_overlap(boxes, x.get("boxes") or []) for x in items):
                    continue
                items.append({"cat": cat, "text": t, "why": why, "boxes": boxes})
        lab = _label_lines(data)
        lab_boxes = [data["lines"][i]["b"] for i in lab]
        for it in items:                      # a name in a form field: take in OCR crumbs of it, and register all of it
            if it["why"] == "parece nome" and any(_overlap([b], [lb]) for b in it["boxes"] for lb in lab_boxes):
                it["boxes"] = [_grow_name(b, data) for b in it["boxes"]]
                inside = [w["t"] for i in _reading_order(data) for w in [data["words"][i]]
                          if any(w["b"][0] >= b[0] - 1 and w["b"][2] <= b[2] + 1 and w["b"][1] >= b[1] - 3 and w["b"][3] <= b[3] + 3
                                 for b in it["boxes"])]
                if inside and la.looks_like_person_name(" ".join(inside)):
                    it["text"] = " ".join(inside)
        for t, cat, boxes in _field_values(data):
            if not any(_overlap(boxes, x.get("boxes") or []) for x in items):
                items.append({"cat": cat, "text": t, "why": "campo do formulário", "boxes": boxes})
        for kind, cat, cap in (("faces", "FOTO", 80), ("qr", "QRCODE", 300), ("side", "TEXTO_LATERAL", 120)):
            for b in data.get(kind) or []:
                b = [int(x) for x in b]
                if (b[2] - b[0]) * (b[3] - b[1]) <= cap * 1000:
                    items.append({"cat": cat, "text": "", "why": "detectado na imagem", "boxes": [b]})
        for b in data.get("images") or []:
            area = (b[2] - b[0]) * (b[3] - b[1])
            if 3000 <= area <= 200000:
                items.append({"cat": "IMAGEM", "text": "", "why": "imagem dentro da página", "boxes": [b]})
    items = items[:MAX_SUGGESTIONS]
    for n, it in enumerate(items, 1):
        it["id"] = f"S{n}"
    return items


_CATEGORIES = {"PESSOA", "APELIDO", "EMPRESA", "CPF", "CNPJ", "RG", "CNH", "OAB", "ENDERECO", "CEP", "TELEFONE",
               "EMAIL", "PLACA", "CONTA", "PIX", "DATA_NASCIMENTO", "MATRICULA", "PROCESSO", "PROTOCOLO", "DADO",
               "FOTO", "ASSINATURA", "CARIMBO", "MANUSCRITO", "QRCODE", "IMAGEM", "TRECHO", "OCULTO"}
_FIELD_LABELS = {"nascimento": "DATA_NASCIMENTO", "cpf": "CPF", "rg": "RG", "identidade": "RG", "telefone": "TELEFONE",
                 "celular": "TELEFONE", "fone": "TELEFONE", "email": "EMAIL", "endereco": "ENDERECO",
                 "logradouro": "ENDERECO", "cep": "CEP", "placa": "PLACA", "conta": "CONTA", "agencia": "CONTA",
                 "chassi": "PLACA", "renavam": "PLACA", "pis": "PIS", "nis": "PIS", "ctps": "CTPS", "titulo": "TITULO_ELEITOR"}


def _label_cat(word: str) -> str | None:
    """The category a form label announces, tolerating one OCR slip ("EMAL", "TELEFQNE")."""
    f = _fold(re.sub(r"[^\wÀ-ÿ]", "", word))
    if f in _FIELD_LABELS:
        return _FIELD_LABELS[f]
    if len(f) >= 4:
        close = difflib.get_close_matches(f, [k for k in _FIELD_LABELS if len(k) >= 4], n=1, cutoff=0.8)
        if close:
            return _FIELD_LABELS[close[0]]
    return None


def _grow_name(b: list[int], data: dict[str, Any]) -> list[int]:
    """OCR splits a name ("JU LIA"): take in letter-only fragments right next to the box on the same line."""
    x0, y0, x1, y1 = b
    for _ in range(3):
        for w in data["words"]:
            wb = w["b"]
            if min(y1, wb[3]) - max(y0, wb[1]) < 0.5 * min(y1 - y0, wb[3] - wb[1]):
                continue
            f = _fold(w["t"])
            if re.search(r"\d", w["t"]) or f.strip(".,;:") in _FORM_WORDS or not re.search(r"[a-z]", f):
                continue
            if 0 <= x0 - wb[2] <= 18:
                x0 = min(x0, wb[0])
            elif 0 <= wb[0] - x1 <= 18:
                x1 = max(x1, wb[2])
    return [x0, y0, x1, y1]


def _field_values(data: dict[str, Any]) -> list[tuple[str, str, list[list[int]]]]:
    """Forms: the value written under (or right after) a label such as DATA NASCIMENTO, CPF, TELEFONE, CEP."""
    out = []
    words = data["words"]
    for ln in data["lines"]:
        ws = ln["words"]
        for k, wi in enumerate(ws):
            cat = _label_cat(words[wi]["t"])
            if not cat:
                continue
            lb = words[wi]["b"]
            # the label's column: from its start to the next label word far to the right (or +260)
            right = next((words[ws[j]]["b"][0] for j in range(k + 1, len(ws))
                          if words[ws[j]]["b"][0] - words[ws[j - 1]]["b"][2] > 25), min(1000, lb[0] + 260))
            below = sorted((o for o in data["lines"] if 0 < o["b"][1] - lb[1] <= 30), key=lambda o: o["b"][1])
            for o in below:
                vs = [words[i] for i in o["words"] if lb[0] - 15 <= words[i]["b"][0] < right - 4]
                if cat == "EMAIL":
                    vs = vs if any(re.search(r"@|mail|\.com|\.br", v["t"], re.I) for v in vs) else []
                elif cat != "ENDERECO":
                    vs = [v for v in vs if re.search(r"\d", v["t"])]
                if vs:
                    out.append((" ".join(v["t"] for v in vs), cat, [_union([v["b"] for v in vs])]))
                    break
    return out


def _overlap(a: list[list[int]], b: list[list[int]]) -> bool:
    for x in a:
        for y in b:
            ix = max(0, min(x[2], y[2]) - max(x[0], y[0]))
            iy = max(0, min(x[3], y[3]) - max(x[1], y[1]))
            if ix * iy > 0.5 * min((x[2] - x[0]) * (x[3] - x[1]), (y[2] - y[0]) * (y[3] - y[1])):
                return True
    return False


# -------------------------------------------------------------------------------------------- rotation (view space)
def _to_view(b: list[int], rot: int) -> list[int]:
    if not rot:
        return list(b)
    import visual_redactor as vr
    return vr.map_bbox_1000_from_rotated_to_orig(b, (360 - rot) % 360)


def _from_view(b: list[int], rot: int) -> list[int]:
    if not rot:
        return list(b)
    import visual_redactor as vr
    return vr.map_bbox_1000_from_rotated_to_orig(b, rot)


# ------------------------------------------------------------------------------------------------------ the page
def _page(st: dict[str, Any], pid: str) -> dict[str, Any]:
    pg = st["pages"].get(pid)
    if pg is None:
        data = _page_data(st, pid)
        pg = {"status": "todo", "suggest": _suggest(st, pid, data), "drop": [], "added": [], "render_sig": ""}
        st["pages"][pid] = pg
        _save(st)
    return pg


def _chosen(pg: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for s in pg["suggest"] if s["id"] not in pg["drop"]] + pg["added"]


def _sig(pg: dict[str, Any]) -> str:
    return hashlib.sha1(json.dumps(_chosen(pg), sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:12]


def _fonts(size: int):
    try:
        import visual_redactor as vr
        return vr._load_pil_font(size)
    except Exception:  # noqa: BLE001
        from PIL import ImageFont
        return ImageFont.load_default()


def _page_image(d: dict[str, Any], pno: int, width: int, pdf=None):
    """The page as displayed, `width` pixels wide (PIL image)."""
    from PIL import Image
    own = pdf is None
    pdf = pdf or _open_pdf(d)
    try:
        page = pdf[pno - 1]
        zoom = width / page.rect.width
        import pymupdf
        pix = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom), alpha=False)
        return Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    finally:
        if own:
            pdf.close()


def _upright(img, rot: int):
    if not rot:
        return img
    import visual_redactor as vr
    return vr.rotate_pil_image_cw(img, rot)


def _framed(img, draw_grid: bool):
    """Add a ruler margin (0-1000 on every side) and, for the view, a faint grid every 100. The view's side margins
    are wide: the suggestion tags go there, so they never cover the page."""
    from PIL import Image, ImageDraw
    M = 70 if draw_grid else 34
    w, h = img.size
    canvas = Image.new("RGB", (w + 2 * M, h + 2 * M), (255, 255, 255))
    canvas.paste(img, (M, M))
    over = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    dr = ImageDraw.Draw(over)
    f = _fonts(13)
    for v in range(0, 1001, 50):
        x = M + v * w / 1000
        y = M + v * h / 1000
        major = v % 100 == 0
        if draw_grid and major and 0 < v < 1000:
            dr.line([(x, M), (x, M + h)], fill=(40, 110, 255, 60), width=1)
            dr.line([(M, y), (M + w, y)], fill=(40, 110, 255, 60), width=1)
        tick = 8 if major else 4
        dr.line([(x, M - tick), (x, M)], fill=(30, 60, 140, 255), width=1)
        dr.line([(x, M + h), (x, M + h + tick)], fill=(30, 60, 140, 255), width=1)
        dr.line([(M - tick, y), (M, y)], fill=(30, 60, 140, 255), width=1)
        dr.line([(M + w, y), (M + w + tick, y)], fill=(30, 60, 140, 255), width=1)
        if major:
            lab = str(v)
            dr.text((x - 4 * len(lab), 2), lab, fill=(30, 60, 140, 255), font=f)
            dr.text((x - 4 * len(lab), M + h + 14), lab, fill=(30, 60, 140, 255), font=f)
            dr.text((1, y - 7), lab.rjust(4), fill=(30, 60, 140, 255), font=f)
            dr.text((M + w + 3, y - 7), lab, fill=(30, 60, 140, 255), font=f)
    return Image.alpha_composite(canvas.convert("RGBA"), over).convert("RGB"), M


def _draw_boxes(img, M: int, items: list[tuple[str, list[list[int]], tuple[int, int, int], bool]]):
    """Boxes on the page; each tag sits in the nearest side margin with a thin line to its box."""
    from PIL import ImageDraw
    w, h = img.size[0] - 2 * M, img.size[1] - 2 * M
    dr = ImageDraw.Draw(img)
    f = _fonts(14)
    taken: dict[str, list[float]] = {"l": [], "r": []}
    for label, boxes, color, on in items:
        for k, b in enumerate(boxes):
            x0, y0 = M + b[0] * w / 1000 - 3, M + b[1] * h / 1000 - 3
            x1, y1 = M + b[2] * w / 1000 + 3, M + b[3] * h / 1000 + 3
            if on:
                dr.rectangle([x0, y0, x1, y1], outline=color, width=3)
            else:
                for xx in range(int(x0), int(x1), 8):
                    dr.line([(xx, y0), (min(xx + 4, x1), y0)], fill=color, width=1)
                    dr.line([(xx, y1), (min(xx + 4, x1), y1)], fill=color, width=1)
            if k:
                continue
            tag = label if on else label + "x"
            side = "l" if (b[0] + b[2]) / 2 < 500 else "r"
            ty = (y0 + y1) / 2 - 8
            while any(abs(ty - t) < 18 for t in taken[side]):
                ty += 18
            taken[side].append(ty)
            tw = 9 * len(tag) + 6
            tx = 2 if side == "l" else img.size[0] - tw - 2
            dr.line([(tx + tw if side == "l" else tx, ty + 8), (x0 if side == "l" else x1, (y0 + y1) / 2)], fill=color, width=1)
            dr.rectangle([tx, ty, tx + tw, ty + 17], fill=color)
            dr.text((tx + 3, ty + 1), tag, fill=(255, 255, 255), font=f)
    return img


def _view_image(st: dict[str, Any], pid: str, pg: dict[str, Any], data: dict[str, Any]) -> Path:
    d = _doc(st, pid)
    rot = data.get("rot", 0)
    img = _upright(_page_image(d, _unit_no(pid), VIEW_WIDTH if not rot or rot == 180 else int(VIEW_WIDTH * 1.0)), rot)
    if img.size[0] > VIEW_WIDTH + 10:
        img = img.resize((VIEW_WIDTH, int(img.size[1] * VIEW_WIDTH / img.size[0])))
    img, M = _framed(img, True)
    items = []
    for s in pg["suggest"]:
        items.append((s["id"], [_to_view(b, rot) for b in s.get("boxes") or []],
                      (230, 110, 0) if s["id"] not in pg["drop"] else (150, 150, 150), s["id"] not in pg["drop"]))
    for a in pg["added"]:
        items.append((a["id"], [_to_view(b, rot) for b in a.get("boxes") or []], (0, 150, 60), True))
    _draw_boxes(img, M, items)
    out = _work(st) / f"{pid}.view.jpg"
    img.save(out, quality=88, subsampling=0)
    return out


# ------------------------------------------------------------------------------------------------- rendering output
def _tokens_for(st: dict[str, Any], items: list[dict[str, Any]], sess: dict[str, Any] | None = None) -> dict[str, str]:
    """The label each chosen item gets (the same text always gets the same token, across documents)."""
    sess = copy.deepcopy(sess if sess is not None else _session(st))
    out = {}
    for it in items:
        if it.get("text"):
            tok = la.register_entity(sess, it["text"], it["cat"])
            out[it["id"]] = tok.strip("<>") if tok and tok != it["text"] else it["cat"]
        else:
            out[it["id"]] = it["cat"]
    return out


def _redact_into(page, items: list[dict[str, Any]], labels: dict[str, str], rot_note: int = 0) -> None:
    import pymupdf
    W, H = page.rect.width, page.rect.height
    der = page.derotation_matrix
    for it in items:
        for b in it.get("boxes") or []:
            r = pymupdf.Rect((b[0] - 4) * W / 1000, (b[1] - 3) * H / 1000, (b[2] + 4) * W / 1000, (b[3] + 3) * H / 1000)
            r = (r & page.rect) * der
            if r.is_empty:
                continue
            lab = labels.get(it["id"], it["cat"])
            fs = max(4.0, min(9.0, (abs(r.y1 - r.y0)) * 0.7, abs(r.x1 - r.x0) / max(1, len(lab)) * 1.7))
            page.add_redact_annot(r, text=lab, fontsize=fs, fill=(0, 0, 0), text_color=(1, 1, 1), align=pymupdf.TEXT_ALIGN_CENTER)
    page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_PIXELS, graphics=pymupdf.PDF_REDACT_LINE_ART_REMOVE_IF_TOUCHED)


def _render_final(st: dict[str, Any], pid: str, pg: dict[str, Any], data: dict[str, Any]) -> tuple[Path | None, str]:
    """Exactly what the output will show for this page (an image), or the section's anonymized text."""
    d = _doc(st, pid)
    items = _chosen(pg)
    labels = _tokens_for(st, items)
    if data["mode"] == "text":
        sess = copy.deepcopy(_session(st))
        for it in items:
            la.register_entity(sess, it["text"], it["cat"])
        return None, la.apply_longest_first_replacements(data["text"], sess)
    import pymupdf
    with _open_pdf(d) as src:
        one = pymupdf.open()
        one.insert_pdf(src, from_page=_unit_no(pid) - 1, to_page=_unit_no(pid) - 1)
    _redact_into(one[0], items, labels)
    img = _upright(_page_image(d, 1, VIEW_WIDTH, pdf=one), data.get("rot", 0))
    one.close()
    if img.size[0] > VIEW_WIDTH + 10:
        img = img.resize((VIEW_WIDTH, int(img.size[1] * VIEW_WIDTH / img.size[0])))
    img, _m = _framed(img, False)
    out = _work(st) / f"{pid}.final.jpg"
    img.save(out, quality=88, subsampling=0)
    return out, ""


# ----------------------------------------------------------------------------------------------------- showing a page
def _show(st: dict[str, Any], pid: str | None = None) -> None:
    pid = pid or st.get("cur")
    if not pid:
        _out(["Não há página atual: todos os documentos estão prontos.", _plan_marker(st)])
        return
    d = _doc(st, pid)
    pg = _page(st, pid)
    data = _page_data(st, pid)
    units = d["units"]
    word = _unit_word(d)
    head = (f"=== {pid}: {d['name']} — {word} {_unit_no(pid)} de {len(units)} "
            f"(documento {d['id'][1:]} de {len(st['docs'])}) ===")
    lines = [head]
    if data["mode"] == "text":
        lines += ["Texto deste trecho:", "<<<", data["text"], ">>>"]
        lines.append("Sugestões (todas LIGADAS até você desligar com --drop):" if pg["suggest"] else "Nenhuma sugestão automática.")
        for s in pg["suggest"]:
            mark = "" if s["id"] not in pg["drop"] else "  [desligada]"
            lines.append(f"  {s['id']} {s['cat']}: \"{s['text']}\" ({s['why']}){mark}")
        for a in pg["added"]:
            lines.append(f"  {a['id']} {a['cat']}: \"{a['text']}\" (adicionada por você)")
        lines += ["", "Próximo passo: decida o que ocultar e rode UM comando:",
                  f"  {_script_cmd()} apply --drop S2 --add \"texto exato a ocultar\"",
                  "(--drop desliga sugestões erradas; --add oculta um texto que faltou, escrito como está no trecho; "
                  "--remove A1 desfaz uma adição.) O resultado mostra o trecho anonimizado para você conferir."]
        lines.append(_plan_marker(st))
        _out(lines)
        return
    view = _view_image(st, pid, pg, data)
    rel = os.path.relpath(view, st["folder"]) if str(view).startswith(st["folder"]) else str(view)
    lines += [f"Imagem desta página (com grade 0-1000 e as sugestões numeradas): {rel}",
              f"LOCALCHAT_SHOW {view}"]
    if data["mode"] == "scan" and data.get("ocr_conf") is not None and data["ocr_conf"] < 70:
        lines.append("Atenção: o OCR leu mal esta página; confie na imagem, não no texto das linhas.")
    lines.append("Sugestões (caixas LARANJA; todas LIGADAS até você desligar com --drop):" if pg["suggest"] else
                 "Nenhuma sugestão automática nesta página: olhe a imagem e adicione o que precisar.")
    rot = data.get("rot", 0)
    for s in pg["suggest"]:
        bx = _to_view(s["boxes"][0], rot) if s.get("boxes") else None
        mark = "" if s["id"] not in pg["drop"] else "  [desligada]"
        lines.append(f"  {s['id']} {s['cat']}" + (f" \"{s['text']}\"" if s.get("text") else "") +
                     (f" em {bx}" if bx else "") + f" ({s['why']}){mark}")
    for a in pg["added"]:
        bx = _to_view(a["boxes"][0], rot) if a.get("boxes") else None
        lines.append(f"  {a['id']} {a['cat']}" + (f" \"{a['text']}\"" if a.get("text") else "") +
                     (f" em {bx}" if bx else "") + " (caixa VERDE, adicionada por você)")
    if data["lines"]:
        lines.append("Linhas de texto lidas nesta página (para adicionar o que faltou por --add-line ou --add):")
        for ln in data["lines"][:MAX_LINES_LISTED]:
            lines.append(f"  {ln['id']} y={_to_view(ln['b'], rot)[1]}: {ln['t'][:110]}")
        if len(data["lines"]) > MAX_LINES_LISTED:
            lines.append(f"  (... mais {len(data['lines']) - MAX_LINES_LISTED} linhas)")
    lines += ["", "Próximo passo: OLHE a imagem e decida. Depois rode UM comando:",
              f"  {_script_cmd()} apply --drop S2,S5 --add \"texto exato\" --add-line L14 --add-box 120,300,480,330",
              "  --drop: desliga sugestões erradas (ex.: cabeçalho do formulário, nome de órgão público).",
              "  --add \"...\": oculta um texto escrito na página (nome, endereço, número); acho o lugar sozinho.",
              "  --add-line L14: oculta a linha inteira.  --add-box x0,y0,x1,y1: oculta um retângulo da grade (foto, "
              "assinatura, carimbo, manuscrito).",
              "Você decide tudo; as sugestões são só ajuda. O resultado mostra a página FINAL para você conferir."]
    lines.append(_plan_marker(st))
    _out(lines)


# --------------------------------------------------------------------------------------------------------- commands
def cmd_page(a: argparse.Namespace) -> None:
    st = _load()
    _show(st)


def cmd_status(a: argparse.Namespace) -> None:
    st = _load()
    lines = [f"Pasta: {st['folder']}", f"Progresso: {_progress(st)}. Página atual: {st.get('cur') or '(nenhuma: terminado)'}"]
    for d in st["docs"]:
        done = [u for u in d["units"] if st["pages"].get(u, {}).get("status") == "done"]
        lines.append(f"  {d['id']} {d['name']}: {len(done)}/{len(d['units'])} prontos" +
                     (f" -> {d['output']}" if d.get("output") else "") + (f" (PULADO: {d['error']})" if d.get("error") else ""))
    lines.append(f"Continuar: {_script_cmd()} page")
    lines.append(_plan_marker(st))
    _out(lines)


def _parse_box(raw: str) -> tuple[list[int], str]:
    cat = "OCULTO"
    if ":" in raw:
        raw, cat = raw.split(":", 1)
        cat = re.sub(r"[^A-Z_]", "", cat.upper()) or "OCULTO"
    nums = [int(round(float(x))) for x in re.findall(r"-?\d+(?:\.\d+)?", raw)]
    if len(nums) != 4:
        raise ValueError(f"--add-box precisa de 4 números x0,y0,x1,y1 (0 a 1000), recebi '{raw}'.")
    x0, y0, x1, y1 = nums
    x0, x1 = sorted((max(0, min(1000, x0)), max(0, min(1000, x1))))
    y0, y1 = sorted((max(0, min(1000, y0)), max(0, min(1000, y1))))
    if x1 - x0 < 3 or y1 - y0 < 3:
        raise ValueError(f"--add-box {nums}: pequena demais (menos de 3 unidades). Confira os números na grade.")
    if (x1 - x0) * (y1 - y0) > 400000:
        raise ValueError(f"--add-box {nums}: cobre {round((x1 - x0) * (y1 - y0) / 10000)}% da página. Use caixas justas, "
                         "só sobre o dado (várias caixas pequenas se precisar).")
    return [x0, y0, x1, y1], cat


def _split_ids(vals: list[str] | None) -> list[str]:
    out = []
    for v in vals or []:
        out += [x.strip().upper() for x in re.split(r"[,\s]+", v) if x.strip()]
    return out


def _guess_cat(text: str) -> str:
    hits = _regex_hits(text)
    if hits and _norm(hits[0][0]) == _norm(text):
        return hits[0][1]
    if re.search(r"\b(?:S\.?/?A\.?|Ltda\.?|EIRELI|ME|EPP|Banco|Cia\.?|Companhia|Comércio|Comercio|Indústria|Industria|"
                 r"Associação|Associacao|Cooperativa|Instituto|Fundação|Fundacao|Holding|Group|Grupo)\b", text, re.I):
        return "EMPRESA"
    return "PESSOA" if la.looks_like_person_name(text) else "DADO"


def cmd_apply(a: argparse.Namespace) -> None:
    st = _load()
    pid = st.get("cur")
    if not pid:
        _fail("não há página atual: todos os documentos estão prontos.")
    pg = _page(st, pid)
    data = _page_data(st, pid)
    rot = data.get("rot", 0)
    msgs, errs = [], []
    known = {s["id"] for s in pg["suggest"]}
    for sid in _split_ids(a.drop):
        if sid == "ALL":
            pg["drop"] = sorted(known)
            msgs.append("todas as sugestões desligadas")
        elif sid in known:
            if sid not in pg["drop"]:
                pg["drop"].append(sid)
        else:
            errs.append(f"--drop {sid}: não existe essa sugestão (existem {', '.join(sorted(known)) or 'nenhuma'})")
    for sid in _split_ids(a.keep):
        if sid in pg["drop"]:
            pg["drop"].remove(sid)
        elif sid not in known:
            errs.append(f"--keep {sid}: não existe essa sugestão")
    for aid in _split_ids(a.remove):
        before = len(pg["added"])
        pg["added"] = [x for x in pg["added"] if x["id"] != aid]
        if len(pg["added"]) == before:
            errs.append(f"--remove {aid}: não existe essa adição (adições: {', '.join(x['id'] for x in pg['added']) or 'nenhuma'})")

    def next_id() -> str:
        n = max([int(x["id"][1:]) for x in pg["added"]] + [0]) + 1
        return f"A{n}"

    for raw in a.add or []:
        cat = None
        m = re.match(r"^\s*([A-Z_]{2,})\s*:\s*(.+)$", raw)
        if m and m.group(1) in _CATEGORIES:
            cat, raw = m.group(1), m.group(2)
        txt = raw.strip().strip('"').strip()
        if not txt:
            continue
        cat = cat or _guess_cat(txt)
        if data["mode"] == "text":
            if _fold(txt) not in _fold(data["text"]):
                close = difflib.get_close_matches(txt, re.findall(r"\S+(?:\s+\S+){0,%d}" % max(0, len(txt.split()) - 1),
                                                                    data["text"]), n=1, cutoff=0.6)
                errs.append(f"--add \"{txt}\": esse texto não está neste trecho" + (f" (será \"{close[0]}\"?)" if close else "") +
                            ". Copie o texto exatamente como aparece.")
                continue
            pg["added"].append({"id": next_id(), "cat": cat, "text": txt, "why": "adicionado"})
            continue
        hits = _locate(txt, data, loose=True)
        if not hits:
            near = difflib.get_close_matches(_norm(txt), [_norm(l["t"]) for l in data["lines"]], n=1, cutoff=0.5)
            hint = ""
            if near:
                ln = next(l for l in data["lines"] if _norm(l["t"]) == near[0])
                hint = f" A linha mais parecida é {ln['id']}: \"{ln['t'][:80]}\" (use --add-line {ln['id']})."
            errs.append(f"--add \"{txt}\": não achei esse texto no que o OCR leu nesta página.{hint} "
                        "Se ele está na imagem mas o OCR não leu, use --add-box com as coordenadas da grade.")
            continue
        for boxes in hits:
            pg["added"].append({"id": next_id(), "cat": cat, "text": txt, "why": "adicionado", "boxes": boxes})
    for lid in _split_ids(a.add_line):
        if data["mode"] == "text":
            errs.append("--add-line só vale para páginas (PDF/imagem); em texto use --add \"...\".")
            break
        ln = next((l for l in data["lines"] if l["id"].upper() == lid), None)
        if not ln:
            errs.append(f"--add-line {lid}: não existe essa linha (vão de L1 a L{len(data['lines'])})")
            continue
        pg["added"].append({"id": next_id(), "cat": _guess_cat(ln["t"]) if len(ln["t"]) < 60 else "TRECHO",
                            "text": ln["t"], "why": "linha inteira", "boxes": [ln["b"]]})
    for raw in a.add_box or []:
        if data["mode"] == "text":
            errs.append("--add-box só vale para páginas (PDF/imagem).")
            break
        try:
            b, cat = _parse_box(raw)
        except ValueError as exc:
            errs.append(str(exc))
            continue
        pg["added"].append({"id": next_id(), "cat": cat, "text": "", "why": "retângulo", "boxes": [_from_view(b, rot)]})
    _save(st)
    if errs:
        msgs = ["Algumas instruções não foram aplicadas:"] + [f"  - {e}" for e in errs] + \
               ["O resto foi aplicado. Corrija só o que falhou."]
    img, text = _render_final(st, pid, pg, data)
    pg["render_sig"] = _sig(pg)
    _save(st)
    ch = _chosen(pg)
    lines = msgs + [f"=== {pid}: resultado FINAL ({len(ch)} item(ns) ocultado(s)) ==="]
    if img is None:
        lines += ["Trecho como vai ficar:", "<<<", text, ">>>"]
    else:
        rel = os.path.relpath(img, st["folder"]) if str(img).startswith(st["folder"]) else str(img)
        lines += [f"Imagem da página FINAL (é exatamente o que vai sair no arquivo): {rel}", f"LOCALCHAT_SHOW {img}"]
    lines += ["Agora CONFIRA com atenção: algum nome, CPF, RG, endereço, telefone, conta, placa, assinatura ou rosto "
              "ainda está legível? Algo foi coberto sem necessidade?",
              f"  - Se falta ocultar algo: {_script_cmd()} apply --add \"...\" (ou --add-line / --add-box)",
              f"  - Se algo foi coberto por engano: {_script_cmd()} apply --drop S3  (ou --remove A2)",
              f"  - Se está LIMPO: {_script_cmd()} done --note \"o que foi ocultado nesta {_unit_word(_doc(st, pid))}\""]
    _out(lines)


def cmd_done(a: argparse.Namespace) -> None:
    st = _load()
    pid = st.get("cur")
    if not pid:
        _fail("não há página atual: todos os documentos estão prontos.")
    pg = _page(st, pid)
    if pg.get("render_sig") != _sig(pg):
        _fail("você ainda não viu o resultado final desta página com as escolhas atuais. Rode "
              f"{_script_cmd()} apply (sem opções, se não quiser mudar nada) e OLHE o resultado antes do done.")
    note = (a.note or "").strip()
    if len(note) < 8:
        _fail("escreva em --note o que foi ocultado nesta página (ex.: \"2 nomes, 1 CPF, endereço; cabeçalho mantido\").")
    d = _doc(st, pid)
    # the choices become the job's memory: the same text is hidden the same way everywhere after this
    sess = _session(st)
    for it in _chosen(pg):
        if it.get("text") and len(_norm(it["text"])) >= 3:
            la.register_entity(sess, it["text"], it["cat"])
    la.save_session(st["session"], sess)
    pg.update(status="done", note=note[:400], done_at=time.time())
    lines = [f"{pid} pronta. Anotado: {note[:200]}",
             "LOCALCHAT_PAGE_DONE " + json.dumps({"page": pid, "doc": d["name"], "note": note[:400]}, ensure_ascii=False)]
    if all(st["pages"].get(u, {}).get("status") == "done" for u in d["units"]):
        try:
            outp, leaks = _write_output(st, d)
            d["output"] = outp
            lines.append(f"Documento {d['id']} ({d['name']}) terminado. Arquivo anonimizado: {outp}")
            if leaks:
                lines.append("ATENÇÃO: no texto do arquivo final ainda aparece: " + "; ".join(leaks[:8]) +
                             f". Reabra a página com {_script_cmd()} goto <ID> e oculte.")
        except Exception as exc:  # noqa: BLE001
            d["output_error"] = f"{exc.__class__.__name__}: {exc}"
            lines.append(f"ERRO ao gravar o arquivo de {d['id']}: {d['output_error']}")
    units = _units(st)
    nxt = next((u for u in units[units.index(pid) + 1:] if st["pages"].get(u, {}).get("status") != "done"), None) or \
        next((u for u in units if st["pages"].get(u, {}).get("status") != "done"), None)
    st["cur"] = nxt or ""
    _save(st)
    if not nxt:
        lines.append("TODOS os documentos estão prontos:")
        for dd in st["docs"]:
            lines.append(f"  {dd['id']} {dd['name']} -> {dd.get('output') or dd.get('output_error') or dd.get('error')}")
        lines.append(_plan_marker(st))
        _out(lines)
        return
    lines.append("Próxima página abaixo. Trabalhe só nela.")
    _out(lines)
    _show(st, nxt)


def cmd_goto(a: argparse.Namespace) -> None:
    st = _load()
    pid = a.id.strip().upper()
    if pid not in _units(st):
        _fail(f"não existe {pid}. Existem: {', '.join(_units(st))}")
    pg = _page(st, pid)
    pg["status"] = "todo"
    st["cur"] = pid
    _save(st)
    _show(st, pid)


def cmd_reset(a: argparse.Namespace) -> None:
    st = _load()
    pid = st.get("cur")
    if not pid:
        _fail("não há página atual.")
    pg = _page(st, pid)
    pg.update(drop=[], added=[], render_sig="")
    _save(st)
    _show(st, pid)


# ---------------------------------------------------------------------------------------------------- output files
def _safe_name(st: dict[str, Any], d: dict[str, Any]) -> str:
    sess = _session(st)
    stem = la.apply_longest_first_replacements(Path(d["name"]).stem, sess)
    # file names often carry just a first name or a surname ("BO Rosa"): any word of a hidden name goes too
    parts = {}
    for tok, orig in sess.get("token_to_original", {}).items():
        if _cat_of_token(tok) in ("PESSOA", "APELIDO"):
            for w in re.findall(r"[A-Za-zÀ-ÿ]{3,}", orig):
                if _fold(w) not in _CONNECTORS:
                    parts.setdefault(_fold(w), tok.strip("<>").split("_")[0] + "_" + tok.strip("<>").split("_")[1].rstrip("abcdefghijklmnopqrstuvwxyz"))
    stem = re.sub(r"[A-Za-zÀ-ÿ]{3,}", lambda m: parts.get(_fold(m.group(0)), m.group(0)), stem)
    stem = re.sub(r'[<>:"/\\|?*]+', "", stem).strip() or d["id"]
    return f"{stem} (anonimizado)"


def _write_output(st: dict[str, Any], d: dict[str, Any]) -> tuple[str, list[str]]:
    out_dir = Path(st["out"])
    out_dir.mkdir(parents=True, exist_ok=True)
    sess = _session(st)
    surfaces = [o for o in sess.get("token_to_original", {}).values() if len(_norm(o)) >= 4]
    name = _safe_name(st, d)
    if d["kind"] in ("docx", "text"):
        src = Path(d["src"])
        if d["kind"] == "docx":
            dst = out_dir / (name + ".docx")
            la.rewrite_docx_package_atomic(src, dst, lambda t: la.apply_longest_first_replacements(t, sess))
            try:
                la.embed_docx_session_metadata(dst, st["session"], scrub_author=True)
            except Exception:  # noqa: BLE001
                pass
            final_text = "\n".join(_doc_text_blocks(dst, "docx"))
        else:
            dst = out_dir / (name + src.suffix.lower())
            raw = "\n".join(_doc_text_blocks(src, "text"))
            final_text = la.apply_longest_first_replacements(raw, sess)
            dst.write_text(final_text, encoding="utf-8")
        leaks = [s for s in surfaces if _fold(s) in _fold(final_text)]
        return str(dst), leaks
    import pymupdf
    with _open_pdf(d) as src:
        out = pymupdf.open()
        out.insert_pdf(src)
    for pid in d["units"]:
        pg = st["pages"][pid]
        items = _chosen(pg)
        _redact_into(out[_unit_no(pid) - 1], items, _tokens_for(st, items, sess))
    out.set_metadata({})
    try:
        out.del_xml_metadata()
    except Exception:  # noqa: BLE001
        pass
    out.set_toc([])
    for page in out:
        for annot in list(page.annots() or []):
            page.delete_annot(annot)
    leaks = []
    full = "\n".join(p.get_text() for p in out)
    if full.strip():
        leaks = [s for s in surfaces if _fold(s) in _fold(full)]
    if d["kind"] == "image":
        dst = out_dir / (name + ".png")
        pix = out[0].get_pixmap(dpi=200, alpha=False)
        pix.save(str(dst))
    else:
        dst = out_dir / (name + ".pdf")
        out.save(str(dst), garbage=4, deflate=True, clean=True)
    out.close()
    return str(dst), leaks


# ------------------------------------------------------------------------------------------------------------- main
def main() -> None:
    p = argparse.ArgumentParser(prog="anon.py", description="Anonimiza documentos uma página por vez.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start")
    s.add_argument("--dir", required=True, help="pasta com os documentos (só aqui se digita caminho)")
    s.add_argument("--only", default="", help="só estes arquivos (padrões separados por vírgula, ex.: \"BO*,*.docx\")")
    s.add_argument("--restart", action="store_true", help="recomeça do zero, mesmo que já exista um trabalho nesta pasta")
    sub.add_parser("page")
    sub.add_parser("status")
    sub.add_parser("where")
    ap = sub.add_parser("apply")
    ap.add_argument("--drop", action="append")
    ap.add_argument("--keep", action="append")
    ap.add_argument("--add", action="append")
    ap.add_argument("--add-line", action="append")
    ap.add_argument("--add-box", action="append")
    ap.add_argument("--remove", action="append")
    dn = sub.add_parser("done")
    dn.add_argument("--note", default="")
    g = sub.add_parser("goto")
    g.add_argument("id")
    sub.add_parser("reset")
    a = p.parse_args()
    {"start": cmd_start, "page": cmd_page, "status": cmd_status, "where": cmd_status, "apply": cmd_apply,
     "done": cmd_done, "goto": cmd_goto, "reset": cmd_reset}[a.cmd](a)


if __name__ == "__main__":
    main()
