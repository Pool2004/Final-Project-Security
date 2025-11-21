"""Casos de uso para verificar integridad de archivos mediante SHA-256.

Este módulo expone una interfaz de línea de comandos con dos acciones:

1. `digest`: genera el hash SHA-256 de un archivo y lo imprime/guarda.
2. `compare`: compara un archivo con un hash conocido (archivo o valor literal).

Ejemplos:
    python caso_hashing.py digest mensaje.txt --out mensaje.sha256
    python caso_hashing.py compare mensaje.txt --hash-file mensaje.sha256
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Iterable

BUFFER_SIZE = 4096


def sha256_chunks(chunks: Iterable[bytes]) -> str:
    """Calcula el hash SHA-256 para una secuencia de bloques de bytes."""
    h = hashlib.sha256()
    for chunk in chunks:
        h.update(chunk)
    return h.hexdigest()


def sha256_file(path: Path, buffer_size: int = BUFFER_SIZE) -> str:
    """Devuelve el hash SHA-256 de un archivo."""
    with path.open("rb") as stream:
        return sha256_chunks(iter(lambda: stream.read(buffer_size), b""))


def cmd_digest(args: argparse.Namespace) -> None:
    file_path = Path(args.file)
    if not file_path.is_file():
        raise SystemExit(f"El archivo '{file_path}' no existe.")

    digest = sha256_file(file_path)
    print(f"SHA-256 ({file_path.name}): {digest}")

    if args.out:
        output_path = Path(args.out)
        output_path.write_text(digest + "\n", encoding="utf-8")
        print(f"Hash guardado en {output_path}")


def _read_hash_value(args: argparse.Namespace) -> str:
    if args.hash_value:
        return args.hash_value.strip().lower()
    if args.hash_file:
        contents = Path(args.hash_file).read_text(encoding="utf-8")
        return contents.strip().lower()
    raise SystemExit("Debes proporcionar --hash-value o --hash-file.")


def cmd_compare(args: argparse.Namespace) -> None:
    file_path = Path(args.file)
    if not file_path.is_file():
        raise SystemExit(f"El archivo '{file_path}' no existe.")

    expected = _read_hash_value(args)
    current = sha256_file(file_path)

    if expected == current.lower():
        print("✅ Coincidencia: el archivo mantiene su integridad.")
    else:
        print("❌ No coincide: el archivo fue modificado o el hash es incorrecto.")
        print(f"Hash actual:   {current}")
        print(f"Hash esperado: {expected}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verificación de integridad basada en SHA-256."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    digest = subparsers.add_parser("digest", help="Genera el hash SHA-256 de un archivo.")
    digest.add_argument("file", help="Ruta al archivo objetivo.")
    digest.add_argument(
        "--out",
        help="Ruta del archivo donde guardar el hash resultante (opcional).",
    )
    digest.set_defaults(func=cmd_digest)

    compare = subparsers.add_parser(
        "compare", help="Compara el archivo con un hash previamente obtenido."
    )
    compare.add_argument("file", help="Archivo a verificar.")
    group = compare.add_mutually_exclusive_group(required=True)
    group.add_argument("--hash-value", help="Hash esperado (cadena hex).")
    group.add_argument("--hash-file", help="Archivo que contiene el hash esperado.")
    compare.set_defaults(func=cmd_compare)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
