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

from caso_hashing import HashCLI
from cifrado_aes import AESCLI
from caso_cifrado_rsa import cmd_decrypt, cmd_encrypt, cmd_gen
from firma import SignatureManager


class TestCLISmoke(unittest.TestCase):
    def test_hash_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            archivo = Path(tmp) / "data.txt"
            archivo.write_text("contenido de prueba", encoding="utf-8")
            salida = Path(tmp) / "data.sha256"

            HashCLI().run(["digest", str(archivo), "--out", str(salida)])
            self.assertTrue(salida.exists())

            HashCLI().run(["compare", str(archivo), "--hash-file", str(salida)])

    def test_aes_cli(self):
        with tempfile.TemporaryDirectory() as tmp, io.StringIO() as buf:
            paquete = Path(tmp) / "aes.json"
            AESCLI().run(["encrypt", "mensaje secreto", "--json-out", str(paquete)])
            self.assertTrue(paquete.exists())
            with redirect_stdout(buf):
                AESCLI().run(["decrypt", "--json-in", str(paquete)])
            self.assertIn("mensaje secreto", buf.getvalue())

    def test_rsa_cli(self):
        with tempfile.TemporaryDirectory() as tmp, patch(
            "getpass.getpass", lambda _: ""
        ):
            priv_path = Path(tmp) / "smoke_priv.pem"
            pub_path = Path(tmp) / "smoke_pub.pem"

            cmd_gen(
                argparse.Namespace(
                    private=str(priv_path),
                    public=str(pub_path),
                    bits=2048,
                    password=False,
                )
            )
            self.assertTrue(priv_path.exists() and pub_path.exists())

            with io.StringIO() as encrypt_buf, redirect_stdout(encrypt_buf):
                cmd_encrypt(
                    argparse.Namespace(
                        message="hola rsa cli",
                        public=str(pub_path),
                        out=None,
                    )
                )
                ciphertext_hex = encrypt_buf.getvalue().splitlines()[-1].strip()

            with io.StringIO() as decrypt_buf, redirect_stdout(decrypt_buf):
                cmd_decrypt(
                    argparse.Namespace(
                        ciphertext=ciphertext_hex,
                        private=str(priv_path),
                        password=False,
                    )
                )
                self.assertIn("hola rsa cli", decrypt_buf.getvalue())

    def test_signature_cli(self):
        with tempfile.TemporaryDirectory() as tmp, io.StringIO() as buf, patch(
            "getpass.getpass", lambda _: ""
        ):
            manager = SignatureManager()
            priv_path = Path(tmp) / "sig_priv.pem"
            pub_path = Path(tmp) / "sig_pub.pem"

            manager.run(
                [
                    "gen",
                    "--private",
                    str(priv_path),
                    "--public",
                    str(pub_path),
                    "--bits",
                    "2048",
                ]
            )
            self.assertTrue(priv_path.exists() and pub_path.exists())

            with io.StringIO() as sign_buf, redirect_stdout(sign_buf):
                manager.run(
                    [
                        "sign",
                        "mensaje firmado",
                        "--private",
                        str(priv_path),
                    ]
                )
                sello = sign_buf.getvalue().splitlines()[-1].strip()

            with redirect_stdout(buf):
                manager.run(
                    [
                        "verify",
                        "mensaje firmado",
                        sello,
                        "--public",
                        str(pub_path),
                    ]
                )
            self.assertIn("Firma válida", buf.getvalue())


if __name__ == "__main__":
    unittest.main()