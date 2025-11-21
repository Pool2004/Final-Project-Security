import argparse
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from cifrado_aes import AESCLI, AESGCMManager


class TestAESManager(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = AESGCMManager()

    def test_encrypt_decrypt_roundtrip(self):
        packet = self.manager.encrypt("mensaje oculto")
        recovered = self.manager.decrypt(
            key_hex=packet.key.hex(),
            nonce_hex=packet.nonce.hex(),
            ciphertext_hex=packet.ciphertext.hex(),
        )
        self.assertEqual(recovered, "mensaje oculto")

    def test_cli_json_flow(self):
        cli = AESCLI(self.manager)
        with tempfile.TemporaryDirectory() as tmp, io.StringIO() as buf:
            output = Path(tmp) / "bundle.json"
            cli.handler_encrypt(argparse.Namespace(message="hola mundo", key=None, json_out=str(output)))
            self.assertTrue(output.is_file())

            with redirect_stdout(buf):
                cli.handler_decrypt(
                    argparse.Namespace(
                        json_in=str(output),
                        key=None,
                        nonce=None,
                        ciphertext=None,
                    )
                )
            self.assertIn("hola mundo", buf.getvalue())


if __name__ == "__main__":
    unittest.main()