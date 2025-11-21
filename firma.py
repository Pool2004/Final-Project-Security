"""Herramienta sencilla para firmas digitales RSA-PSS."""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

DEFAULT_PRIV = "sign_private.pem"
DEFAULT_PUB = "sign_public.pem"

# Glosario breve:
# - "sello": firma digital en hex.
# - "llavero": conjunto de archivos PEM (privada/pública).


class SignatureManager:
    """Orquesta la generación de llaveros y firmas usando RSA-PSS."""

    def __init__(self, key_size: int = 2048):
        self.key_size = key_size

    def _prompt_password(self, confirm: bool) -> bytes | None:
        password = getpass.getpass("Contraseña para la clave privada (enter para ninguna): ")
        if not password:
            return None
        if confirm:
            repeat = getpass.getpass("Confirma la contraseña: ")
            if repeat != password:
                raise SystemExit("Las contraseñas no coinciden.")
        return password.encode("utf-8")

    def generar_llavero(self) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        privada = rsa.generate_private_key(public_exponent=65537, key_size=self.key_size)
        return privada, privada.public_key()

    @staticmethod
    def guardar_privada(key: rsa.RSAPrivateKey, destino: Path, password: bytes | None) -> None:
        algoritmo = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=algoritmo,
        )
        destino.write_bytes(pem)

    @staticmethod
    def guardar_publica(key: rsa.RSAPublicKey, destino: Path) -> None:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        destino.write_bytes(pem)

    @staticmethod
    def cargar_privada(origen: Path, password: bytes | None) -> rsa.RSAPrivateKey:
        return serialization.load_pem_private_key(origen.read_bytes(), password=password)

    @staticmethod
    def cargar_publica(origen: Path) -> rsa.RSAPublicKey:
        return serialization.load_pem_public_key(origen.read_bytes())

    @staticmethod
    def firmar_mensaje(key: rsa.RSAPrivateKey, message: str) -> bytes:
        return key.sign(
            message.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    @staticmethod
    def verificar_sello(key: rsa.RSAPublicKey, message: str, signature: bytes) -> bool:
        try:
            key.verify(
                signature,
                message.encode("utf-8"),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def cmd_gen(self, args: argparse.Namespace) -> None:
        priv, pub = self.generar_llavero()
        priv_path = Path(args.private)
        pub_path = Path(args.public)
        password = self._prompt_password(confirm=True) if args.password else None
        self.guardar_privada(priv, priv_path, password)
        self.guardar_publica(pub, pub_path)
        print(f"Llavero creado: {priv_path} / {pub_path}")

    def cmd_sign(self, args: argparse.Namespace) -> None:
        ruta = Path(args.private)
        if not ruta.exists():
            raise SystemExit(f"No existe la clave privada en {ruta}")
        password = self._prompt_password(confirm=False) if args.password else None
        priv = self.cargar_privada(ruta, password=password)
        sello = self.firmar_mensaje(priv, args.message)
        print("Sello (hex):")
        print(sello.hex())

    def cmd_verify(self, args: argparse.Namespace) -> None:
        ruta = Path(args.public)
        if not ruta.exists():
            raise SystemExit(f"No existe la clave pública en {ruta}")
        pub = self.cargar_publica(ruta)
        try:
            sello = bytes.fromhex(args.signature)
        except ValueError as exc:
            raise SystemExit("La firma suministrada no es hex válida.") from exc
        es_valido = self.verificar_sello(pub, args.message, sello)
        print("✅ Firma válida." if es_valido else "❌ Firma inválida.")

    def build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description="Firmas RSA-PSS en CLI.")
        sub = parser.add_subparsers(dest="cmd", required=True)

        gen = sub.add_parser("gen", help="Generar llavero nuevo.")
        gen.add_argument("--private", default=DEFAULT_PRIV, help="Archivo PEM para la clave privada.")
        gen.add_argument("--public", default=DEFAULT_PUB, help="Archivo PEM para la clave pública.")
        gen.add_argument("--bits", type=int, default=2048, help="Tamaño de clave.")
        gen.add_argument("--password", action="store_true", help="Proteger la clave privada con contraseña.")
        gen.set_defaults(func=self.cmd_gen)

        sign = sub.add_parser("sign", help="Firmar mensaje en texto plano.")
        sign.add_argument("message", help="Contenido a firmar.")
        sign.add_argument("--private", default=DEFAULT_PRIV, help="Ruta de la clave privada.")
        sign.add_argument("--password", action="store_true", help="Solicitar contraseña para abrir el PEM.")
        sign.set_defaults(func=self.cmd_sign)

        verify = sub.add_parser("verify", help="Verificar un sello digital.")
        verify.add_argument("message", help="Mensaje original.")
        verify.add_argument("signature", help="Firma en hex.")
        verify.add_argument("--public", default=DEFAULT_PUB, help="Ruta de la clave pública.")
        verify.set_defaults(func=self.cmd_verify)

        return parser

    def run(self, argv: list[str] | None = None) -> None:
        parser = self.build_parser()
        args = parser.parse_args(argv)
        args.func(args)


def main() -> None:
    SignatureManager().run()


if __name__ == "__main__":
    main()
