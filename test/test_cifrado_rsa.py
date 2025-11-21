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

from caso_cifrado_rsa import RSAEncryptionTool, cmd_decrypt, cmd_encrypt, cmd_gen


class TestRSAEncryptionTool(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = RSAEncryptionTool()

    def test_roundtrip_and_persist(self):
        priv, pub = self.tool.generate_keypair()
        ciphertext = self.tool.encrypt(pub, "mensaje asimétrico")
        plaintext = self.tool.decrypt(priv, ciphertext)
        self.assertEqual(plaintext, "mensaje asimétrico")

        with tempfile.TemporaryDirectory() as tmp:
            priv_path = Path(tmp) / "priv.pem"
            pub_path = Path(tmp) / "pub.pem"
            self.tool.save_private_key(priv, priv_path, password=None)
            self.tool.save_public_key(pub, pub_path)

            loaded_priv = self.tool.load_private_key(priv_path, password=None)
            loaded_pub = self.tool.load_public_key(pub_path)
            self.assertEqual(
                self.tool.decrypt(loaded_priv, self.tool.encrypt(loaded_pub, "otra prueba")),
                "otra prueba",
            )

    def test_cli_commands(self):
        with tempfile.TemporaryDirectory() as tmp, io.StringIO() as buf, patch(
            "getpass.getpass", lambda _: ""
        ):
            priv_path = Path(tmp) / "priv.pem"
            pub_path = Path(tmp) / "pub.pem"

            cmd_gen(
                argparse.Namespace(
                    private=str(priv_path),
                    public=str(pub_path),
                    bits=2048,
                    password=False,
                )
            )
            self.assertTrue(priv_path.exists() and pub_path.exists())

            with redirect_stdout(buf):
                cmd_encrypt(
                    argparse.Namespace(
                        message="hola rsa",
                        public=str(pub_path),
                        out=None,
                    )
                )
            ciphertext_hex = buf.getvalue().splitlines()[-1].strip()

            with io.StringIO() as out:
                with redirect_stdout(out):
                    cmd_decrypt(
                        argparse.Namespace(
                            ciphertext=ciphertext_hex,
                            private=str(priv_path),
                            password=False,
                        )
                    )
                self.assertIn("hola rsa", out.getvalue())


if __name__ == "__main__":
    unittest.main()