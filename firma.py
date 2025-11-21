"""CLI para generar firmas digitales basadas en RSA-PSS."""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

DEFAULT_PRIV = "sign_private.pem"
DEFAULT_PUB = "sign_public.pem"


def generar_par_claves_firma(key_size: int = 2048) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def guardar_clave_privada(private_key, ruta: Path, password: bytes | None) -> None:
    encryption_alg = (
        serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_alg,
    )
    ruta.write_bytes(pem)


def guardar_clave_publica(public_key, ruta: Path) -> None:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    ruta.write_bytes(pem)


def cargar_clave_privada(ruta: Path, password: bytes | None) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(ruta.read_bytes(), password=password)


def cargar_clave_publica(ruta: Path) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(ruta.read_bytes())


def firmar_mensaje(private_key, mensaje: str) -> bytes:
    datos = mensaje.encode("utf-8")
    return private_key.sign(
        datos,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verificar_firma(public_key, mensaje: str, firma: bytes) -> bool:
    try:
        public_key.verify(
            firma,
            mensaje.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def _prompt_password(confirm: bool) -> bytes | None:
    pwd = getpass.getpass("Contraseña para la clave privada (enter para ninguna): ")
    if not pwd:
        return None
    if confirm:
        repeat = getpass.getpass("Confirma la contraseña: ")
        if repeat != pwd:
            raise SystemExit("Las contraseñas no coinciden.")
    return pwd.encode("utf-8")


def cmd_gen(args: argparse.Namespace) -> None:
    private_key, public_key = generar_par_claves_firma(key_size=args.bits)
    priv_path = Path(args.private)
    pub_path = Path(args.public)
    password = _prompt_password(confirm=True) if args.password else None
    guardar_clave_privada(private_key, priv_path, password)
    guardar_clave_publica(public_key, pub_path)
    print(f"Claves creadas en {priv_path} (privada) y {pub_path} (pública).")


def cmd_sign(args: argparse.Namespace) -> None:
    priv_path = Path(args.private)
    if not priv_path.exists():
        raise SystemExit(f"No se encontró la clave privada en {priv_path}.")
    password = _prompt_password(confirm=False) if args.password else None
    private_key = cargar_clave_privada(priv_path, password=password)
    firma = firmar_mensaje(private_key, args.message)
    print("Firma (hex) lista para compartir:")
    print(firma.hex())


def cmd_verify(args: argparse.Namespace) -> None:
    pub_path = Path(args.public)
    if not pub_path.exists():
        raise SystemExit(f"No se encontró la clave pública en {pub_path}.")
    public_key = cargar_clave_publica(pub_path)
    try:
        firma = bytes.fromhex(args.signature)
    except ValueError as exc:
        raise SystemExit("La firma proporcionada no es hex válida.") from exc
    valido = verificar_firma(public_key, args.message, firma)
    print("✔️ Firma válida." if valido else "✖️ Firma inválida.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Digital Signatures helper.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    gen = subparsers.add_parser("gen", help="Generar un nuevo par de claves RSA.")
    gen.add_argument("--private", default=DEFAULT_PRIV, help="Archivo de salida para la clave privada.")
    gen.add_argument("--public", default=DEFAULT_PUB, help="Archivo de salida para la clave pública.")
    gen.add_argument("--bits", type=int, default=2048, help="Tamaño de clave (mínimo 2048).")
    gen.add_argument("--password", action="store_true", help="Solicitar contraseña para la clave privada.")
    gen.set_defaults(func=cmd_gen)

    sign = subparsers.add_parser("sign", help="Firmar un mensaje en texto plano.")
    sign.add_argument("message", help="Mensaje que será firmado.")
    sign.add_argument("--private", default=DEFAULT_PRIV, help="Ruta de la clave privada.")
    sign.add_argument("--password", action="store_true", help="Solicitar contraseña de la clave privada.")
    sign.set_defaults(func=cmd_sign)

    verify = subparsers.add_parser("verify", help="Verificar una firma existente.")
    verify.add_argument("message", help="Mensaje original.")
    verify.add_argument("signature", help="Firma en hex.")
    verify.add_argument("--public", default=DEFAULT_PUB, help="Ruta de la clave pública.")
    verify.set_defaults(func=cmd_verify)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
