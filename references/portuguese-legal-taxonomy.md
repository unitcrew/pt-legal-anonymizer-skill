# Portuguese Legal Anonymization Taxonomy & Edge-Case Reference (v4.0)

This reference defines the exact boundary between **private identifying data (must be anonymized)** and **public juridical structure (must remain unmasked)** in Brazilian and Portuguese legal documents (PJe, eproc, e-SAJ, SEEU, Projudi, REDS/Police Reports, bank PIX receipts, Whisper audio transcripts, contracts, notarial deeds, and Sisbajud/Infojud/Renajud returns).

## 1. Two-Tier Entity Categories & Semantic Placeholder Schema

Every anonymized entity receives a deterministic tag in the format `<CATEGORY_ID>` (canonical root) or `<CATEGORY_IDa>`, `<CATEGORY_IDb>` (surface variant of the same legal entity).

| Category Tag | Tier | Scope & Legal Examples | Variant Linking & Coreference Behavior | 
| ----- | ----- | ----- | ----- | 
| `<PESSOA_N>` | Tier 1 (Contextual) | Natural persons: Plaintiff (*Autor / Exequente / Requerente / Impetrante / Solicitante / Vítima*), Defendant (*Réu / Executado / Requerido*), Parents (*Pai / Mãe*), Deceased & Estate (*de cujus / Espólio de ...*), Heirs, Spouses, Witnesses, Police Officers (*Sargento / Soldado*), Bailiffs (*Oficial de Justiça*), Court Experts (*Perito*), and Private Attorneys. | Full name `"Jaciara Aparecida Silva"` -> `<PESSOA_1>`. Automatically links `"Jaciara Silva"`, `"Sr. Silva"`, `"Senhora Jaciara"`, `"solicitante Jaciara"`, standalone distinctive first names (`"Jaciara"`), dotted initials (`"J.A.S."`, `"J. A. S."`), and 1-char OCR/Whisper spelling variants (`"Jacyara"`, `"Elizangela"` <-> `"Elisangela"` via *Cour de cassation* `check_similarities`) as `<PESSOA_1a>`, `<PESSOA_1b>`. | 
| `<APELIDO_N>` | Tier 1 (Contextual) | Nicknames, *alcunhas* (`"vulgo Baiano"`, `"Zezinho da Oficina"`), informal shortened names (`"Dona Jaci"`), social names, and social media usernames (`"@jaciara_silva"`). | Can be registered standalone (`<APELIDO_1>`) or linked directly to a canonical `PESSOA` (`{"Jaciara Aparecida Silva": ["Dona Jaci"]}` -> `<PESSOA_1a>`). | 
| `<EMPRESA_N>` | Tier 1 (Contextual) | Private legal entities: Corporations (`S.A.`), Limited liability companies (`Ltda.`), `MEI`s, Supermarkets, Stores, Credit cooperatives (`Sicoob Acicredi`), Private banks (`Banco Bradesco S.A.`), Fintechs, Employers, Clinics, and Condominiums. | Links both legal-suffix-stripped (`"Supermercado Alvorada"` -> `<EMPRESA_1a>`) and business-prefix-stripped (`"Alvorada"` -> `<EMPRESA_1b>`) variants to `"Supermercado Alvorada Ltda"` (`<EMPRESA_1>`). | 
| `<ENDERECO_N>` / `<NUMERO_N>` | Tier 1 (Contextual) | Private physical addresses: Street names with or without house/building numbers (`Av. Juca Stockler, 528`, `RUA  CANDIDA ORNELAS`), apartment/suite numbers, residential blocks/lots (`QR 1, Casa 39, Conjunto D`), named rural estates (`Fazenda Santa Helena`, `Sítio Córrego Fundo`), workplaces, and form-split house/complement numbers (`NÚMERO \n 228`). | Automatically expands street prefixes (`Av.` <-> `Av` <-> `Avenida`, `R.` <-> `Rua`), multi-word street cores (`"Juca Stockler"`), double-spaced PDF spans, and form-split house numbers (`Regra #24`). | 
| `<PROCESSO_N>` | Tier 1 + Pass 1 | **Private Proceeding Numbers Only (`JURISprocesso`)**: First- and second-instance CNJ numbers (`NNNNNNN-DD.AAAA.J.TR.OOOO`), TJ-MG appeal format (`1.0000.25.247738-5/001`), *Carta Precatória*, *Inquérito Policial* (`IP nº ...`), *Termo Circunstanciado* (`TCO`), and *Processo Administrativo / PAD* belonging to the parties. | Context-aware disambiguation (`is_jurisprudence_context`) automatically preserves CNJ numbers inside cited case law / ementas (`TJSP`, `TJMG`, `STJ`, `Rel. Des.`, `Data do Julgamento`). Any pre-masked precedent can also be unmasked via `JURISPRUDENCIA_CITADA` in Pass 2 (`Regra #1` to `Regra #3B`). | 
| `<CPF_N>` | Pass 1 + Tier 2 Safety Net | 11-digit Brazilian Individual Taxpayer Registry numbers (`XXX.XXX.XXX-XX`, OCR-spaced, partially masked `***.456.789-**` on bank receipts, or unformatted 11-digit strings). | Validated by Modulo-11 check digits (`Regra #6` to `Regra #8`) to avoid masking 10/11-digit PJe document IDs; OCR-damaged CPFs can be added in Pass 2. | 
| `<CNPJ_N>` | Pass 1 + Tier 2 Safety Net | 14-digit Brazilian National Registry of Legal Entities numbers (`XX.XXX.XXX/XXXX-XX` or unformatted 14-digit strings). | Validated by Modulo-11 check digits (`Regra #4`, `Regra #5`). | 
| `<PIS_PASEP_N>` | Pass 1 + Tier 2 Safety Net | 11-digit PIS/PASEP/NIT/NIS social security numbers (`XXX.XXXXX.XX-X`) in labor and social-security lawsuits. | Validated by Modulo-11 weights `[3, 2, 9, 8, 7, 6, 5, 4, 3, 2]` (`Regra #17`). | 
| `<PROTOCOLO_BO_N>` | Pass 1 + Tier 2 Safety Net | Police Report (REDS / Boletim de Ocorrência) protocol numbers (`Nº 2025-035867821-001`). | Deterministic regex capture (`Regra #21`). | 
| `<RG_N>` / `<CNH_N>` / `<CTPS_N>` | Pass 1 + Tier 2 Safety Net | State identity cards (inline `RG nº MG-12.345.678` or multi-line form tables under `CARTEIRA DE IDENTIDADE CIVIL` / `NÚMERO DOCUMENTO IDENTIDADE`), driver licenses (`CNH`), and labor booklets (`CTPS`). | Guarded against state/federal highway designations (`MG-179`, `BR-116`, `SP-330`) (`Regra #10`, `Regra #10B`, `Regra #18`, `Regra #19`). | 
| `<OAB_N>` / `<CONSELHO_PROFISSIONAL_N>` | Pass 1 + Tier 2 Safety Net | Bar association registrations (`OAB/MG 123.456`) and professional council IDs (`CRM/MG 45.678`, `CREA-SP 506123456`, `CAU`, `CRC`, `COREN`, `CRO`, `CRP`, `CRF`, `CREFITO`). | Deterministic regex capture (`Regra #9`, `Regra #26`) + Pass 2 safety net. | 
| `<MATRICULA_IMOVEL_N>` / `<REGISTRO_CARTORIO_N>` | Pass 1 + Tier 2 Safety Net | Real estate registry numbers (`matrícula nº 17.800 do CRI`) and civil/notarial book/page/term coordinates (`Livro B-14, Folha 82, Termo 4512`, `Termo de Casamento nº ...`). | Deterministic regex capture (`Regra #12`, `Regra #27`) + Pass 2 safety net. | 
| `<MATRICULA_N>` | Pass 1 + Tier 2 Safety Net | Police / military / civil servant functional registration numbers (`PM1576503`, `MATRÍCULA \n 1425321`, `REGISTRO GERAL \n 36018`). | Links prefixed (`PM1576503` -> `<MATRICULA_1>`) and bare numeric (`1576503` -> `<MATRICULA_1a>`) forms automatically (`Regra #22`). | 
| `<CONTA_BANCARIA_N>` / `<CHAVE_PIX_N>` / `<ID_TRANSACAO_N>` / `<QR_CODE_N>` | Pass 1 + Tier 2 Safety Net | Bank branch (`Agência`), credit cooperative (`Cooperativa: 3125 / Conta: 98765-4`), informal bank accounts (`Nubank 0001 / 9988776-5`), PIX UUID and `EndToEndId` (`E...`) keys, receipt authentication codes, and visual PIX QR codes on scanned receipts. | Deterministic regex capture (`Regra #11`, `Regra #20`, `Regra #25`) + OpenCV QR detector (`visual_redactor.py`) + Pass 2 safety net. | 
| `<TELEFONE_N>` / `<EMAIL_N>` / `<CEP_N>` / `<PLACA_N>` / `<GPS_N>` | Pass 1 + Tier 2 Safety Net | Landline/mobile/WhatsApp numbers (including compact REDS `(35)123-148-148`), emails, 8-digit postal codes (`37890-000`), legacy/Mercosul vehicle plates (`ABC1D23`), and exact DMS GPS coordinates (`-20º 44' 11,9"`). | Deterministic regex capture (`Regra #13` to `Regra #16`, `Regra #23`) + Pass 2 safety net. | 

## 2. What Must NEVER Be Anonymized (Preserving Legal Reasoning)

Over-redaction destroys downstream legal utility in Cloud Claude (as demonstrated by the *Text Anonymization Benchmark* and *UlyssesLegalNER-Br*). Do **not** register or mask the following items:

1. **Public Cited Jurisprudence & Precedents (`JURISprocedimento` / `JURISprecedente`)**:

   * Keep case numbers inside quoted ementas, appellate precedents, and higher-court citations unmasked (e.g., `TJMG - Apelação Cível 5007360-91.2020.8.13.0702, Rel. Des. Evandro Lopes, j. 26/06/2024`, `TJSP; Recurso Inominado nº 1001877-27.2021.8.26.0129`, `AgRg no AREsp nº 81.329 - PR`, `ADI nº 3.767/STF`, `Súmula nº 80/STF`).

   * If Pass-1 regex ever pre-masks a cited precedent as `<PROCESSO_N>` (because it lacked an adjacent `Rel. Des.` or `Ementa:` label), place `"<PROCESSO_N>"` inside `"JURISPRUDENCIA_CITADA"` in Pass 2 so Python automatically restores that precedent to cleartext.

2. **Public Court Venues, Municipalities, and States (`LOC_PUB`)**:

   * Keep city names, state abbreviations, and court districts visible when they appear without a private street address (e.g., `Comarca de Poços de Caldas/MG`, `Passos/MG`, `Nova Resende/MG`, `Foro Central Cível de São Paulo/SP`).

3. **Courts, Chambers, Police Units, Public Institutions, and Public Registries**:

   * Keep `STF`, `STJ`, `CJF`, `CNJ`, `TRF-1` through `TRF-6`, `TJMG`, `TJSP`, `1ª Vara Cível`, `16ª Delegacia de Polícia Civil/Passos`, `77 CIA PM/12 BPM/18 RPM`, `Ministério Público`, `Defensoria Pública`, `Cartório de Registro de Imóveis`, `INSS`, `Receita Federal`, `Sisbajud`, `Renajud`, and `Infojud` unmasked.

4. **Statutes, Procedural Articles, and Electronic Court Document IDs (`LEGISLACAO` & PJe IDs)**:

   * Keep all statutory citations (`Art. 772, III, do CPC`, `Art. 828 do CPC`, `Lei nº 9.099/95`, `Lei nº 7.347/85`) and PJe/eproc movement identifiers (`ID 10635709142`, `Id. 10543118735`, `fls. 142/148`) unmasked.

5. **Dates, Deadlines, and Monetary Amounts (`R$`)**:

   * Keep dates (`03/08/2025`), procedural deadlines (`prazo de 5 dias`), and monetary figures (`R$ 181,05`) unmasked so prescription (*prescrição/decadência*), interest, and debt calculations remain exact.

## 9. Biometric, Visual & Embedded Document Elements (v6.0)

| Placeholder Tag | Target Entities | Detection & Redaction Rule | 
| ----- | ----- | ----- | 
| `<ASSINATURA_N>` | Handwritten signatures (`assinatura manuscrita`), rubrics (`rubrica`), and cursive signer blocks above `<PESSOA_N>` / `<CPF_N>` or near `ASSINATURA DO TITULAR` | Automatically detected via OpenCV clean-ink density scanning above signer blocks and near `ASSINATURA` labels in `visual_redactor.py`, or via `[INK_REGION_N]` `#ID` selection; garbled cursive OCR noise is suppressed from `.anonymized.txt` | 
| `<FOTO_N>` | 3x4 portrait face photos on scanned ID cards (`RG`, `CNH`, `CTPS`, `OAB`) | Automatically detected via OpenCV frontal-face Haar cascade + portrait frame expansion in `visual_redactor.py`, or via manual `boxes` | 
| `<BIOMETRIA_N>` | Thumbprints / fingerprint blocks (`impressão digital` / `polegar direito`) on scanned `RG` and notarized instruments | Redacted via `#ID` (`[INK_REGION_N]`) or `boxes` with `category: "BIOMETRIA"` | 
| `<QR_CODE_N>` | Validation QR codes on PIX receipts, `CNH-e`, `RG digital`, and PJe/eproc authentication footers | Automatically detected and black-boxed via `cv2.QRCodeDetector` | 
| `IMAGEM REMOVIDA (N)` | Embedded images inside `.docx` files (`word/media/*` referenced by `document.xml`, headers, footers, comments) | Replaced in-place by `anonymize_docx_embedded_images()` with an opaque neutral placeholder of identical pixel dimensions and format (or visually redacted via `--docx-image-mode redact`), while storing base64 originals in the session vault for 100% byte-identical `restore` | 

## 10. Public Geographic & Institutional Whitelist Rules (Never Anonymize)

1. **Municipalities, Cities, States, and Comarcas**:

   * Never anonymize isolated cities, municipalities, states, or court jurisdictions (`Comarca de Nova Resende/MG`, `Município de Conceição da Aparecida-MG`, `natural de Alpinópolis-MG`, `Poços de Caldas/MG`, `São Paulo/SP`), as territorial jurisdiction (`competência territorial`) is essential for legal analysis.

   * `legal_anonymizer.py` v6.0 automatically protects `Município de ...-UF`, `Cidade de ...-UF`, `Comarca de ...-UF`, and `natural de ...-UF` spans from partial name-token propagation (preventing first/middle names like `"Aparecida"` from corrupting `"Município de Conceição da Aparecida-MG"`).

2. **Generic Legal & Address Framing Nouns**:

   * Generic framing words (`"logradouro"`, `"endereço"`, `"domicílio"`, `"residente"`, `"outorgante"`, `"outorgantes"`, `"outorgado"`, `"outorgados"`) are stripped from `<ENDERECO_N>` cores and excluded from component-token leak checks so `"residente e com domicílio no logradouro"` remains readable and never triggers a false-positive leak warning.