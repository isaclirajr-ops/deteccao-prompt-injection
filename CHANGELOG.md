# Histórico de versões

## 2.0.0 — 07-11-2026

- **Dois níveis:** varredura rápida sempre (cerca de 16 ms por página) e OCR só com gatilho, com teto de 60 s; OCR por amostragem nas páginas escaneadas; `--profundo` a pedido.
- **PDF:** texto sobreposto, fonte com mapa de caracteres adulterado, ActualText, versões anteriores salvas no arquivo, arquivos embutidos varridos.
- **Word:** variáveis ocultas, blocos altChunk, macros, modelo remoto e vínculos externos, objetos embutidos varridos.
- **Novos formatos:** Excel, PowerPoint e imagens; anexos de e-mail varridos.
- **Unicode e codificação:** seletores de variação, letras estilizadas e espaçadas, homóglifos na busca de frases, base64, hexadecimal, binário e ROT13.
- **SUSPEITO:** bloqueio da leitura, laudo técnico em PDF, versão «só o visível» e decisão do usuário (`--liberar`); laudo sob pedido (`--laudo`); modo pasta.
- Autoteste ampliado para 49 casos.

## 1.0.0 — 07-11-2026

- Primeira versão pública.
- Varredura técnica de PDF, Word, e-mail e HTML; três níveis (LIMPO, ATENÇÃO, SUSPEITO).
- Plugin do Claude Code com hook automático antes da leitura de documentos e preparo automático do ambiente Python.
- Pacote da skill para o claude.ai.
- Testes automáticos em Windows, macOS e Linux.
