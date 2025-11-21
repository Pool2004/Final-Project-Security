import argparse
import io
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from caso_hashing import HashCLI, HashToolkit


class TestHashingToolkit(unittest.TestCase):
    def setUp(self) -> None:
        self.toolkit = HashToolkit()

    def test_digest_and_compare(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archivo = Path(tmp) / "demo.txt"
            archivo.write_text("contenido demo", encoding="utf-8")

            digest = self.toolkit.digest_file(archivo)
            self.assertEqual(digest, self.toolkit.digest_file(archivo))

            match, current = self.toolkit.compare(archivo, digest)
            self.assertTrue(match)
            self.assertEqual(current, digest)

    def test_cli_handlers(self) -> None:
        cli = HashCLI(self.toolkit)
        with tempfile.TemporaryDirectory() as tmp, io.StringIO() as buffer:
            archivo = Path(tmp) / "archivo.txt"
            archivo.write_text("hash me", encoding="utf-8")
            salida = Path(tmp) / "hash.txt"

            cli.handler_digest(argparse.Namespace(file=str(archivo), out=str(salida)))
            self.assertTrue(salida.read_text(encoding="utf-8").strip().isalnum())

            with redirect_stdout(buffer):
                cli.handler_compare(
                    argparse.Namespace(
                        file=str(archivo),
                        hash_value=salida.read_text().strip(),
                        hash_file=None,
                    )
                )
            self.assertIn("Integridad confirmada", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()