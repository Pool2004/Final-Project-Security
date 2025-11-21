"""Ejercicio práctico de cifrado asimétrico con RSA-OAEP."""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

DEFAULT_PRIV = "rsa_private.pem"
DEFAULT_PUB = "rsa_public.pem"


class RSAEncryptionTool:
    """Gestiona claves y operaciones RSA-OAEP."""

    def __init__(self, key_size: int = 2048):
        self.key_size = key_size

    def generate_keypair(self) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        private = rsa.generate_private_key(public_exponent=65537, key_size=self.key_size)
        return private, private.public_key()

    @staticmethod
    def save_private_key(key: rsa.RSAPrivateKey, path: Path, password: bytes | None) -> None:
        algorithm = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=algorithm,
        )
        path.write_bytes(pem)

    @staticmethod
    def save_public_key(key: rsa.RSAPublicKey, path: Path) -> None:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        path.write_bytes(pem)

    @staticmethod
    def load_private_key(path: Path, password: bytes | None) -> rsa.RSAPrivateKey:
        return serialization.load_pem_private_key(path.read_bytes(), password=password)

    @staticmethod
    def load_public_key(path: Path) -> rsa.RSAPublicKey:
        return serialization.load_pem_public_key(path.read_bytes())

    @staticmethod
    def encrypt(public_key: rsa.RSAPublicKey, message: str) -> bytes:
        return public_key.encrypt(
            message.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @staticmethod
    def decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> str:
        data = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return data.decode("utf-8")


def _prompt_password(confirm: bool) -> bytes | None:
    pwd = getpass.getpass("Contraseña para la clave privada (enter para ninguna): ")
    if not pwd:
        return None
    if confirm:
        again = getpass.getpass("Confirma la contraseña: ")
        if again != pwd:
            raise SystemExit("Las contraseñas no coinciden.")
    return pwd.encode("utf-8")


def cmd_gen(args: argparse.Namespace) -> None:
    tool = RSAEncryptionTool(key_size=args.bits)
    private, public = tool.generate_keypair()
    priv_path = Path(args.private)
    pub_path = Path(args.public)
    password = _prompt_password(confirm=True) if args.password else None
    tool.save_private_key(private, priv_path, password=password)
    tool.save_public_key(public, pub_path)
    print(f"Par RSA generado en {priv_path} (privada) y {pub_path} (pública).")


def cmd_encrypt(args: argparse.Namespace) -> None:
    tool = RSAEncryptionTool()
    pub_path = Path(args.public)
    if not pub_path.exists():
        raise SystemExit(f"No existe la clave pública en {pub_path}. Ejecuta 'gen' primero.")
    public = tool.load_public_key(pub_path)
    ciphertext = tool.encrypt(public, args.message)
    hex_value = ciphertext.hex()
    print("Ciphertext (hex) listo para compartir:")
    print(hex_value)
    if args.out:
        Path(args.out).write_text(hex_value + "\n", encoding="utf-8")
        print(f"Ciphertext guardado en {args.out}")


def cmd_decrypt(args: argparse.Namespace) -> None:
    tool = RSAEncryptionTool()
    priv_path = Path(args.private)
    if not priv_path.exists():
        raise SystemExit(f"No existe la clave privada en {priv_path}.")
    password = _prompt_password(confirm=False) if args.password else None
    private = tool.load_private_key(priv_path, password=password)
    try:
        ciphertext = bytes.fromhex(args.ciphertext.strip())
    except ValueError as exc:
        raise SystemExit("El ciphertext no es hex válido.") from exc
    try:
        message = tool.decrypt(private, ciphertext)
    except Exception as exc:
        raise SystemExit(f"No se pudo descifrar: {exc}") from exc
    print("Mensaje descifrado:")
    print(message)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Demo de cifrado RSA-OAEP.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    gen = subparsers.add_parser("gen", help="Generar clave privada/pública RSA.")
    gen.add_argument("--private", default=DEFAULT_PRIV, help="Archivo PEM para la clave privada.")
    gen.add_argument("--public", default=DEFAULT_PUB, help="Archivo PEM para la clave pública.")
    gen.add_argument("--bits", type=int, default=2048, help="Tamaño de clave (2048+).")
    gen.add_argument("--password", action="store_true", help="Proteger la clave privada con contraseña.")
    gen.set_defaults(func=cmd_gen)

    encrypt = subparsers.add_parser("encrypt", help="Cifrar un mensaje con la clave pública.")
    encrypt.add_argument("message", help="Texto plano a cifrar.")
    encrypt.add_argument("--public", default=DEFAULT_PUB, help="Ruta del PEM público.")
    encrypt.add_argument("--out", help="Archivo donde guardar el ciphertext hex.")
    encrypt.set_defaults(func=cmd_encrypt)

    decrypt = subparsers.add_parser("decrypt", help="Descifrar usando la clave privada.")
    decrypt.add_argument("ciphertext", help="Ciphertext en hex.")
    decrypt.add_argument("--private", default=DEFAULT_PRIV, help="Ruta del PEM privado.")
    decrypt.add_argument("--password", action="store_true", help="Solicitar contraseña del PEM privado.")
    decrypt.set_defaults(func=cmd_decrypt)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

