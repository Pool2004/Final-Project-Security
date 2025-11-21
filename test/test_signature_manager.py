import argparse
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from firma import SignatureManager


class TestSignatureManager(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = SignatureManager()

    def test_sign_verify_cycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            priv_path = Path(tmp) / "priv.pem"
            pub_path = Path(tmp) / "pub.pem"

            priv, pub = self.manager.generar_llavero()
            self.manager.guardar_privada(priv, priv_path, password=None)
            self.manager.guardar_publica(pub, pub_path)

            loaded_priv = self.manager.cargar_privada(priv_path, password=None)
            loaded_pub = self.manager.cargar_publica(pub_path)

            signature = self.manager.firmar_mensaje(loaded_priv, "release listo")
            self.assertTrue(self.manager.verificar_sello(loaded_pub, "release listo", signature))
            self.assertFalse(self.manager.verificar_sello(loaded_pub, "texto alterado", signature))

    def test_cli_commands(self):
        with tempfile.TemporaryDirectory() as tmp, io.StringIO() as buf, patch(
            "getpass.getpass", lambda _: ""
        ):
            priv_path = Path(tmp) / "priv.pem"
            pub_path = Path(tmp) / "pub.pem"

            self.manager.cmd_gen(
                argparse.Namespace(
                    private=str(priv_path),
                    public=str(pub_path),
                    bits=2048,
                    password=False,
                )
            )
            self.assertTrue(priv_path.exists())
            self.assertTrue(pub_path.exists())

            with redirect_stdout(buf):
                self.manager.cmd_sign(
                    argparse.Namespace(
                        message="firmame",
                        private=str(priv_path),
                        password=False,
                    )
                )
            self.assertIn("Sello (hex)", buf.getvalue())


if __name__ == "__main__":
    unittest.main()