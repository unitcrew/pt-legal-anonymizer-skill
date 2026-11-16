---
name: pt-legal-anonymizer
description: Anonymize and restore Brazilian and Portuguese legal documents (.docx, .pdf, .txt, .md, .csv) and scanned image PDFs/receipts/IDs (.pdf, .png, .jpg, .jpeg) 100% locally with full formatting preservation, automatic dependency installation, working-copy isolation inside <folder>/anonymization/, native 1024-token .grid.jpg vision inspection auto-staged in workspace, smart 2-up vertical ID stacking, deterministic CNH/RG landmark & sub-image redaction, Modulo-11 CPF/CNPJ/PIS validation, longest-to-shortest replacement, true PyMuPDF vector and pixel redaction with white placeholders, embedded DOCX image placeholder/restoration, pre-Pass-A underline OCR recovery, and session consistency. Use whenever the user asks to anonymize, redact, mask, sanitize, de-identify, or restore lawsuits, petitions, procuracoes, personal IDs (RG/CNH), police reports (BO/REDS), bank receipts, contracts, or court dockets.
---

# Portuguese & Brazilian Legal Document Anonymizer (`pt-legal-anonymizer` v6.4)

This skill provides a **100% local, zero-cloud, formatting-preserving, and reversible** PII anonymization and visual redaction pipeline for Brazilian and Portuguese legal workflows (`PJe`, `eproc`, `e-SAJ`, `Projudi`, `SEEU`, `REDS`/`BO`, bank receipts, boletos, personal IDs `RG`/`CNH`, WhatsApp screenshots, and powers of attorney `Procurações`).

It is engineered for **local vision LLMs** (such as `Qwen3.6 35B-A3B` in `LocalChat`, `Ollama`, or `LM Studio` on Windows 11) operating with a **1,024-token per-image cap and a strict 4-image per-turn limit**.

---

> **v6.4**: photo, thumbprint, signature and field boxes on CNH/RG cards are now placed from the labels printed on the card itself, so they land correctly at any scan size or position (v6.3 used fixed page coordinates). Sideways cards are detected by comparing all four rotations. Vertical serial numbers are boxed where OCR actually reads them. Boleto barcodes and URLs are matched even when OCR inserts spaces.

## 0. Eight Golden Rules for the Local Agent (Read First!)

1. **Step 0 — Missing Requirements Are Installed Automatically**:
   - `legal_anonymizer.py` automatically runs `ensure_runtime_requirements(auto_install=True)` on startup to check and install any missing Python packages (`pymupdf`, `pillow`, `numpy`, `opencv-python`, `python-docx`). If any dependency or Tesseract OCR (`por+eng`) is missing, install it before proceeding.
2. **Vision-First Backup of the Deterministic Blind Script**:
   - The underlying Python blind script (`legal_anonymizer.py` + `visual_redactor.py`) deterministically handles ~95% of structured redactions before you act: Modulo-11 `CPF`/`CNPJ`/`PIS`, `RG`, `OAB`, `CNJ`, bank accounts, envelopes, barcodes, qualification clauses (`[NOME], brasileiro(a), casado(a)...`), CNH/RG 3×4 portrait photos (`<FOTO_N>`), thumbprints (`<BIOMETRIA_N>`), signatures (`<ASSINATURA_N>`), vertical CNH serial numbers (`<CNH_N>`), QR codes (`<QR_CODE_N>`), hybrid PDF sub-images, and 2-column receipt+boleto splits.
   - **Your critical job as the Vision LLM is to visually inspect the `.grid.jpg` screenshots to back up the blind script**—verifying that every sensitive field on every page is covered by a **red auto-redaction box** and catching anything the blind script could not know (such as informal first names/nicknames in WhatsApp chat bubbles like `"Juju"`, `"Tia Lu"`, `"Dudu"`, or any unmasked line marked with a **blue `#ID` badge**).
   - **Do NOT obsess over raw OCR text alone**: OCR on noisy scans or phone screenshots can miss or garble characters. Always trust what you see in the `.grid.jpg` screenshots!
3. **The User's Source Folder is 100% READ-ONLY**:
   - Never run `mv`, `cp`, `rm`, or write any file directly inside `<PASTA_DOS_DOCUMENTOS>`.
   - `chunk` creates `<PASTA_DOS_DOCUMENTOS>/anonymization/`, stages working copies in `_work/originals_copy/`, and writes all final Cloud-ready deliverables to `<PASTA_DOS_DOCUMENTOS>/anonymization/`.
4. **Single `.grid.jpg` Per Scanned Page (Zero `.view.png` Duplicates & Zero `xcopy` Needed!)**:
   - `chunk` renders a single 1,024-token `<doc>.page_0001.grid.jpg` (`~80–180 KB`) per scanned page—or a stacked `<doc>.pages_0001_0002.grid.jpg` for 2-page ID cards (`RG`/`CNH`).
   - Python **automatically mirrors every `.grid.jpg` (and post-redaction `.redacted_preview.jpg`) into `anonymization_pages/<session_id>/` inside your current `LocalChat Workspace` (`os.getcwd()`)**.
   - **NEVER run `xcopy` or `copy` to move images**, and **NEVER look for `.view.png` files**.
5. **HARD 4-IMAGE-PER-TURN LIMIT (`vision_batches_max_4_per_turn`)**:
   - `LocalChat` enforces a hard limit of **at most 4 images per turn**. Calling `show_file` on 5+ images in one turn drops vision on the 5th+ image.
   - Always step through `"vision_batches_max_4_per_turn"` one batch at a time (**at most 4 `show_file` calls per turn**). Never call `read_file` on `.jpg` or `.png` files.
6. **How to Read `.grid.jpg` Overlays (Red Boxes vs. Blue `#ID` Badges)**:
   - **Bold Red Boxes** (`fill=red, outline=red`) show regions **already caught and scheduled for redaction** by the deterministic blind script. You do **not** need to re-add red-boxed regions!
   - **Blue `#ID` Badges** in the left/right margins (`#1..#99` on Page 1, `#101..#199` on Page 2) mark non-boilerplate lines that are **not yet covered** by a red box.
   - If you see unredacted PII inside a line with a blue `#ID` badge (for example, `#2`, `#3`, `#4`, `#7` on a WhatsApp screenshot), simply list those integer IDs under `"VISUAL_REDACTIONS": {"<filename>": {"line_ids": [2, 3, 4, 7]}}` or add the exact text to `"PESSOA"` / `"APELIDO"`. Only use `"boxes": [[xmin, ymin, xmax, ymax]]` (in `0–1000` outer-margin tick coordinates) if a visual region has neither a red box nor a blue `#ID` badge.
7. **NEVER write inline `python -c` scripts using `fitz`, `cv2`, or `PIL` to draw boxes**:
   - Always use `legal_anonymizer.py`. It handles orientation correction, sub-image OCR, dual-column splitting, ink-snapping, and non-overlapping white `<CATEGORIA_ID>` labels automatically.
8. **Register only clean entity names and street cores (preserve municipalities)**:
   - Register `"Sítio Boa Vista"` or `"Praça Coronel Antônio Bento, nº 33"` (without leading `"logradouro"`).
   - Never register municipalities, states, or court jurisdictions (`"Nova Resende/MG"`, `"Conceição da Aparecida-MG"`, `"Alpinópolis-MG"`, `"Poços de Caldas/MG"`, `"Curitiba, PR"`, `"Belo Horizonte, MG"`).

---

## 1. Standard 3-Step Workflow (Folder or Single File)

Locate `<SKILL_DIR>` (the folder containing this `SKILL.md` and `scripts/legal_anonymizer.py`). Always wrap Windows paths in double quotes `"..."`.

### Step 1: Run `chunk` (Auto-Checks Deps + Runs Full-Folder Blind Pass + Mirrors `.grid.jpg` in Workspace)

For an **entire folder** of case documents (`.pdf`, `.docx`, `.txt`, `.jpg`, `.jpeg`, `.png`):

```bash
python "<SKILL_DIR>/scripts/legal_anonymizer.py" chunk --dir "<PASTA_DOS_DOCUMENTOS>"
```

For a **single file**:

```bash
python "<SKILL_DIR>/scripts/legal_anonymizer.py" chunk --file "<CAMINHO_DO_ARQUIVO>"
```

**What `chunk` outputs**:
- `"session_id"`: Shared session ID (`caso_YYYYMMDD_HHMMSS_xxxxxx`).
- `"entities_staging_file"`: `<PASTA_DOS_DOCUMENTOS>/anonymization/_work/session/discovered_entities.json`.
- `"vision_batches_max_4_per_turn"`: Pre-sliced batches of **at most 4 workspace-relative `.grid.jpg` paths** per turn ready for `show_file`.
- `"scanned_pages_to_inspect_with_vision"`: Per-page metadata including `"grid_image"`, `"auto_matched_boxes_count"` (red boxes already applied by the blind script), and `"candidate_blue_badges"` (remaining unmatched `#ID` lines).
- `"inline_pre_masked_text"`: Full pre-masked text across all files (with all deterministic regex, qualification, receipt, and ID entities already replaced by `<PESSOA_N>`, `<EMPRESA_N>`, `<CPF_N>`, etc.).

### Step 2: Mandatory Vision Backup — View `.grid.jpg` Batches (`<= 4` per Turn) & Populate `entities_staging_file`

1. Step through `"vision_batches_max_4_per_turn"` by calling `show_file` on **1 batch (at most 4 `.grid.jpg` files) per turn** until every `.grid.jpg` has been visually inspected:
   - Check the **bold red boxes** on each page: anything inside a red box is **already** redacted by the blind script.
   - Check the **unboxed areas and blue `#ID` badges**: look specifically for any unboxed person names, nicknames in chat screenshots (`"Juju"`, `"Tia Lu"`, `"Dudu"`), unboxed handwritten signatures, or unboxed ID/receipt lines.
2. Write any additional entities or blue `#ID` badge numbers you spotted into `"entities_staging_file"` (`discovered_entities.json`):

```json
{
  "PESSOA": [
    "ANA BEATRIZ PEREIRA DE ALMEIDA CASTRO",
    "FERNANDA LUIZA DA COSTA BARRETO",
    "JULIANA DA COSTA BARRETO",
    "MARCOS VINICIUS BARRETO"
  ],
  "APELIDO": [
    "Tia Lu",
    "Dudu",
    "Juju"
  ],
  "EMPRESA": [],
  "ENDERECO": [],
  "PROCESSO_PRIVADO": [],
  "JURISPRUDENCIA_CITADA": [],
  "CONTA_BANCARIA": [],
  "VISUAL_REDACTIONS": {
    "senha da Juliana.jpeg": {
      "line_ids": [2, 3, 4, 7]
    }
  }
}
```

### Step 3: Run `anonymize` & Visually Verify `redacted_preview_images`

For a **folder**:

```bash
python "<SKILL_DIR>/scripts/legal_anonymizer.py" anonymize --dir "<PASTA_DOS_DOCUMENTOS>" --session "<SESSION_ID>"
```

For a **single file**:

```bash
python "<SKILL_DIR>/scripts/legal_anonymizer.py" anonymize --file "<CAMINHO_DO_ARQUIVO>" --session "<SESSION_ID>"
```

- `anonymize` automatically reads `discovered_entities.json`, propagates all name/company/address variants across the entire session, writes all Cloud-ready `.anonymized.pdf` / `.anonymized.jpeg` / `.anonymized.docx` / `.anonymized.txt` files into `<PASTA_DOS_DOCUMENTOS>/anonymization/`, and outputs `"redacted_preview_images"` (1,024-token `.redacted_preview.jpg` paths already mirrored into your workspace).
- **Always look at the previews of ID cards, receipts and screenshots** before saying a file is done: call `show_file` on each `.redacted_preview.jpg` (at most 4 per turn). The text placeholders say nothing about a photo, a signature or a sideways number: only the preview shows whether they are covered.
- **If something is still visible in a preview, or a file comes back `needs_attention`, fix it in this order and run `anonymize` again with the SAME `--session`** (do not run `chunk` again, and never mark the file as done with a caveat):
  1. Text you can read (a name, a nickname, a number): add the exact text to `PESSOA` / `APELIDO` / `CONTA_BANCARIA` in `discovered_entities.json`.
  2. A line that has a blue `#ID` badge: add that ID to `"VISUAL_REDACTIONS": {"<file>": {"line_ids": [...]}}`. Add only the IDs of the lines that show personal data. Never add every ID on the page: that blacks out the headers and tables and still misses what has no badge.
  3. Anything without a badge (a face photo, a thumbprint, a signature, a number printed sideways): add a rectangle, `"VISUAL_REDACTIONS": {"<file>": {"boxes": [[xmin, ymin, xmax, ymax]]}}`, reading the four numbers from the 0-1000 tick marks on the edges of the `.grid.jpg` (x grows to the right, y grows downwards). Make the rectangle a little larger than the thing.
- If any file had complex visual additions (such as a WhatsApp screenshot or custom `VISUAL_REDACTIONS`), call `show_file` on its `.redacted_preview.jpg` (at most 4 images per turn) to visually confirm that every sensitive region is cleanly covered by a black `<CATEGORIA_ID>` box.

---

## 2. Restoration Workflow (De-Anonymizing Cloud LLM Outputs & `.docx` Files)

When the user brings back a response, petition draft, or edited `.docx` from a Cloud LLM containing placeholders (`<PESSOA_1>`, `<CPF_1>`, etc.), restore the original client data and original embedded `.docx` images with one command:

```bash
python "<SKILL_DIR>/scripts/legal_anonymizer.py" restore --file "<ARQUIVO_PARA_RESTAURAR>" --session "<SESSION_ID>"
```

---

## 2b. Cloud Helpers (LocalChat `ask_cloud`)

LocalChat can let the local model consult a cloud model (Gemini). Before any question leaves the PC, LocalChat replaces
every string in this skill's vault (`~/.pt_legal_anonymizer/sessions/*/mapping.json`, or `PT_LEGAL_ANONYMIZER_HOME`)
with its placeholder (`<PESSOA_1>`…), then CPFs, case numbers, e-mails, phones and keys, then has the local model check
what is left. So:
- Run `chunk`/`anonymize` first: every entity you confirm here is also protected in cloud questions.
- Never paste raw document text into `ask_cloud`. Ask about the law, the argument or the code in general terms, or send
  anonymized chunk text (it already carries placeholders). Keep placeholders exactly as written.
- The answer comes back with the real values filled in locally; `restore` is only needed for files.

## 3. Reference Taxonomy

For the full list of 24+ entity categories (`<PESSOA_N>`, `<APELIDO_N>`, `<CPF_N>`, `<CNPJ_N>`, `<RG_N>`, `<CNH_N>`, `<OAB_N>`, `<PROCESSO_N>`, `<CONTA_BANCARIA_N>`, `<ID_TRANSACAO_N>`, `<CHAVE_PIX_N>`, `<ASSINATURA_N>`, `<FOTO_N>`, `<BIOMETRIA_N>`, `<QR_CODE_N>`, etc.), consult `references/portuguese-legal-taxonomy.md`.
