# deteccao-prompt-injection (plugin do Claude Code)

Detecta prompt injection (instruções escondidas para IA) em petições, decisões, laudos, contratos e e-mails antes que o Claude os analise. Antes de cada leitura de PDF, Word, e-mail ou HTML, um hook roda uma varredura técnica local, sem IA e sem internet: texto da cor do fundo, fonte minúscula, modo invisível, camada OCR divergente, comentários, revisões e caracteres invisíveis. O resultado chega ao Claude como LIMPO, ATENÇÃO ou SUSPEITO.

Instalação, dentro do Claude Code:

```
/plugin marketplace add isaclirajr-ops/deteccao-prompt-injection
/plugin install deteccao-prompt-injection@deteccao-prompt-injection
```

Requer Python 3.10 ou mais novo. Na primeira sessão, o plugin prepara sozinho o ambiente Python dele. Instalação, configuração de pastas ignoradas, OCR e limites: veja o [README do repositório](https://github.com/isaclirajr-ops/deteccao-prompt-injection#readme).
