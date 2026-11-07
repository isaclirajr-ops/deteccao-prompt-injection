# Segurança

## Encontrou uma técnica que a varredura não pega?

Abra uma *issue* descrevendo a técnica: como o texto foi escondido, em que formato de arquivo e qual veredito a varredura deu. Se possível, anexe um **documento sintético** que reproduza o problema.

**Nunca anexe documento real de processo**, mesmo de autos públicos: ele pode conter dados pessoais e informações de clientes. Monte um exemplo com texto fictício. O arquivo `plugin/skills/deteccao-prompt-injection/scripts/testar_varredura.py` mostra como gerar documentos de teste em poucas linhas.

## Falso positivo em documento legítimo?

Abra uma *issue* com o trecho do relatório (seção do achado e motivo), sem dados pessoais. Exemplos comuns que já são tratados como ATENÇÃO, e não como SUSPEITO: carimbos de assinatura eletrônica, boletos e formulários sobrepostos, OCR de baixa qualidade.

## O que o plugin faz no seu computador

- Lê o arquivo que o Claude vai abrir e grava um relatório em `~/.cache/varredura-prompt-injection/`.
- Na primeira sessão, cria um ambiente Python próprio (pasta de dados do plugin) e instala PyMuPDF, python-docx, lxml e beautifulsoup4 pelo `pip`.
- Não acessa a internet em nenhum outro momento, não envia dados e não coleta telemetria. O código é curto e pode ser auditado: `plugin/hooks/hook_varredura.py` e `plugin/skills/deteccao-prompt-injection/scripts/varredura_prompt_injection.py`.
