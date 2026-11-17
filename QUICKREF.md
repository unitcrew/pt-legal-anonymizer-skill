**Script:** `python "<SKILL_DIR>/scripts/legal_anonymizer.py" <command> …`. `<SKILL_DIR>` is the skill folder LocalChat lists. Put every path in double quotes, accents and all (never `\u` escapes). Run commands plainly, never wrapped in `| Out-File`. The result is JSON and progress lines show while it runs.

**The loop (one case folder at a time):**
1. `chunk --dir "<FOLDER>"` (add `--output-dir "<FOLDER>\<name>-redact"` once, the first time, if the user wants another output folder). It prints the `session_id`, the `entities_staging_file`, the text with known IDs already masked, and the page images (`.grid.jpg`) to look at.
2. **Look.** Open the page images with `read_file` (4 at a time, the image is shown to you). Read the masked text. Write what still identifies someone into the `entities_staging_file` (format below).
3. `anonymize --dir "<FOLDER>" --session <ID>`. It redoes only what changed; `--only <part of a file name>` redoes one file.
4. `verify --dir "<FOLDER>" --session <ID> --fix`. It reads the outputs back, fixes every leak it finds in them itself (text replaced by its placeholder, PDF words blacked out), then checks again.
5. **Look again.** Open the `.redacted_preview.jpg` of every page that had personal data and check it with your own eyes. If something is still visible, add it (step 2) and repeat 3–4. The scripts run blind: your eyes have the last word.
6. `remember` (scope chat) after each file and each folder: what is done, the session id, the output folder, anything that went wrong. Use `status --dir "<FOLDER>" --session <ID>` to see where a session stands.

**Entities file format** (`discovered_entities.json`): one list per category, each value written exactly as it appears in the document:
```json
{"PESSOA": ["JOSÉ DA SILVA", "Maria Souza"], "CPF": ["123.456.789-09"], "RG": [], "OAB": ["OAB/MG 123.456"],
 "ENDERECO": ["Rua das Flores, 100"], "TELEFONE": [], "EMAIL": [], "PROCESSO_PRIVADO": [],
 "VISUAL_REDACTIONS": {"<file name>.pdf": {"line_ids": [12, 13], "boxes": [[100, 820, 480, 900]]}}}
```
- `PESSOA`: only real names (capitalized, letters only). Never dates, years, values or ordinary words.
- `VISUAL_REDACTIONS`: `line_ids` are the blue `#ID` badges on a `.grid.jpg`. `boxes` are `[xmin, ymin, xmax, ymax]` read from the 0–1000 tick marks, for a signature, stamp, photo or handwriting. Both hide that spot on that page only.
- Never list cities, states, courts, or cited case law (court, case number, relator, DJe): those stay as they are.

**If a step fails:** read the error, then try something different. Never repeat the same call. If something is blocked (away mode, a missing file), say so, `remember` it, and go on with the next file. Never read the scripts' code: this card and `status` say how they behave, and the full guide (`read_skill`) has the details.
