#!/usr/bin/env python3
"""Gera dist/deteccao-prompt-injection.zip para enviar em claude.ai (Configurações → Capacidades → Skills)."""

import zipfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SKILL = RAIZ / "plugin" / "skills" / "deteccao-prompt-injection"
SAIDA = RAIZ / "dist" / "deteccao-prompt-injection.zip"


def main():
    SAIDA.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(SAIDA, "w", zipfile.ZIP_DEFLATED) as z:
        for arq in sorted(SKILL.rglob("*")):
            if arq.is_file() and "__pycache__" not in arq.parts and arq.suffix != ".pyc":
                z.write(arq, Path("deteccao-prompt-injection") / arq.relative_to(SKILL))
    print(SAIDA)


if __name__ == "__main__":
    main()
