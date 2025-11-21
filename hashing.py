"""Calcula y valida huellas SHA-256 usando una CLI con clases."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Iterable

# Glosario rápido:
# - "huella": resumen SHA-256 del archivo.
# - "origen": archivo que el usuario desea verificar.


class HashToolkit:
    """Administrador de operaciones SHA-256."""

    def __init__(self, block_size: int = 4096):
        self.block_size = block_size

    def _checksum(self, chunks: Iterable[bytes]) -> str:
        digest = hashlib.sha256()
        for piece in chunks:
            digest.update(piece)
        return digest.hexdigest()

    def digest_file(self, path: Path) -> str:
        if not path.is_file():
            raise SystemExit(f"No se encontró el origen '{path}'.")
        with path.open("rb") as stream:
            return self._checksum(iter(lambda: stream.read(self.block_size), b""))

    def write_digest(self, path: Path, digest: str) -> None:
        path.write_text(digest + "\n", encoding="utf-8")

    def compare(self, path: Path, expected: str) -> tuple[bool, str]:
        actual = self.digest_file(path)
        return actual.lower() == expected.lower(), actual


class HashCLI:
    def __init__(self, toolkit: HashToolkit | None = None):
        self.toolkit = toolkit or HashToolkit()

    @staticmethod
    def _read_expected(args: argparse.Namespace) -> str:
        if args.hash_value:
            return args.hash_value.strip().lower()
        if args.hash_file:
            return Path(args.hash_file).read_text(encoding="utf-8").strip().lower()
        raise SystemExit("Proporciona --hash-value o --hash-file.")

    def handler_digest(self, args: argparse.Namespace) -> None:
        origen = Path(args.file)
        huella = self.toolkit.digest_file(origen)
        print(f"SHA-256 ({origen.name}): {huella}")
        if args.out:
            destino = Path(args.out)
            self.toolkit.write_digest(destino, huella)
            print(f"Huellas guardadas en {destino}")

    def handler_compare(self, args: argparse.Namespace) -> None:
        origen = Path(args.file)
        esperado = self._read_expected(args)
        coincide, actual = self.toolkit.compare(origen, esperado)
        if coincide:
            print("✅ Integridad confirmada.")
        else:
            print("❌ Huellas distintas; revisa el archivo.")
            print(f"Actual:   {actual}")
            print(f"Esperado: {esperado}")

    def build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description="Utilidad simple para SHA-256.")
        sub = parser.add_subparsers(dest="cmd", required=True)

        digest = sub.add_parser("digest", help="Calcula la huella de un archivo.")
        digest.add_argument("file", help="Ruta del archivo origen.")
        digest.add_argument("--out", help="Archivo donde copiar la huella.")
        digest.set_defaults(func=self.handler_digest)

        compare = sub.add_parser("compare", help="Compara un archivo con una huella conocida.")
        compare.add_argument("file", help="Ruta del archivo origen.")
        group = compare.add_mutually_exclusive_group(required=True)
        group.add_argument("--hash-value", help="Huella escrita manualmente.")
        group.add_argument("--hash-file", help="Ruta del archivo con la huella.")
        compare.set_defaults(func=self.handler_compare)

        return parser

    def run(self, argv: list[str] | None = None) -> None:
        parser = self.build_parser()
        args = parser.parse_args(argv)
        args.func(args)


def main() -> None:
    HashCLI().run()


if __name__ == "__main__":
    main()
