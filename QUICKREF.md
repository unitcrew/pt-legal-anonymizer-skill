**Anonimizar = UMA página por vez, você decide cada caixa.** Script: `python "{baseDir}/scripts/anon.py" <comando>`.

1. `start --dir "<PASTA>"` — a ÚNICA vez que você digita um caminho (copie-o exatamente; se errar um acento, o script acha a pasta real). Ele lista os documentos (D1, D2…) e já mostra a primeira página. Se a pasta já tem um trabalho começado, ele continua de onde parou.
2. **Olhe a imagem da página** (LocalChat a mostra sozinho; senão abra com `read_file`). Ela tem uma grade 0–1000 e caixas LARANJA numeradas (S1, S2…): são só SUGESTÕES, todas ligadas.
3. Decida e rode UM `apply`:
   - `--drop S2,S5` desliga sugestões erradas (cabeçalho, órgão público, cidade, número de processo/BO que pode ficar).
   - `--add "texto exato"` oculta um texto que faltou (o script acha onde está). Categoria opcional: `--add "PESSOA: Fulano"`.
   - `--add-line L14` oculta a linha inteira (veja a lista de linhas). `--add-box x0,y0,x1,y1` oculta um retângulo da grade (assinatura, rosto, carimbo, manuscrito, algo que o OCR não leu).
   - `--remove A1` desfaz uma adição; `--keep S2` religa uma sugestão. `reset` volta ao começo da página.
4. O `apply` mostra a **página FINAL** (é o arquivo de saída). Confira com os seus olhos: ainda dá para ler nome, CPF, RG, endereço, telefone, e-mail, conta, placa, assinatura ou rosto? Se sim, `apply` de novo. Se algo foi coberto sem precisar, `--drop`/`--remove`.
5. Limpo? `done --note "o que foi ocultado"`. A nota fica salva; a página seguinte aparece sozinha. Ao terminar a última página de um documento, o arquivo anonimizado é gravado em `<PASTA>/anonymization/`.

Regras: trabalhe só na página mostrada; nunca leia o código do script; nunca escreva caminhos depois do `start` (use `page` para rever a página atual, `status` para ver o progresso, `goto D1-P2` para reabrir uma página). Se um comando der erro, leia a mensagem: ela diz o que fazer. O que foi ocultado numa página é sugerido sozinho nas próximas e em todos os documentos do trabalho.
Mantenha legíveis: cidades, estados, tribunais, varas, órgãos públicos, jurisprudência citada, datas de fatos e valores.
