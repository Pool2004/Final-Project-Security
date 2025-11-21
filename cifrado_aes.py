"""Herramienta CLI para cifrado simétrico AES-GCM."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12


@dataclass
class CipherBundle:
    key: bytes
    nonce: bytes
    ciphertext: bytes

    def to_hex_dict(self) -> dict[str, str]:
        return {
            "key": self.key.hex(),
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
        }


def generar_clave_aes_256() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def cifrar_mensaje(key: bytes, mensaje: str) -> CipherBundle:
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, mensaje.encode("utf-8"), None)
    return CipherBundle(key=key, nonce=nonce, ciphertext=ciphertext)


def descifrar_mensaje(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    aesgcm = AESGCM(key)
    datos = aesgcm.decrypt(nonce, ciphertext, None)
    return datos.decode("utf-8")


def parse_hex_value(value: str, label: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise SystemExit(f"{label} no es un hex válido.") from exc


def cmd_encrypt(args: argparse.Namespace) -> None:
    key = parse_hex_value(args.key, "La clave") if args.key else generar_clave_aes_256()
    bundle = cifrar_mensaje(key, args.message)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(bundle.to_hex_dict(), indent=2), encoding="utf-8")
        print(f"Paquete cifrado guardado en {args.json_out}")
    else:
        print("Clave (hex):      ", bundle.key.hex())
        print("Nonce (hex):      ", bundle.nonce.hex())
        print("Ciphertext (hex): ", bundle.ciphertext.hex())


def _load_bundle(args: argparse.Namespace) -> CipherBundle:
    if args.json_in:
        data = json.loads(Path(args.json_in).read_text(encoding="utf-8"))
        try:
            return CipherBundle(
                key=parse_hex_value(data["key"], "key"),
                nonce=parse_hex_value(data["nonce"], "nonce"),
                ciphertext=parse_hex_value(data["ciphertext"], "ciphertext"),
            )
        except KeyError as exc:
            raise SystemExit(f"Falta el campo {exc.args[0]} en {args.json_in}.") from exc

    if not (args.key and args.nonce and args.ciphertext):
        raise SystemExit("Debes proporcionar --json-in o trio de --key/--nonce/--ciphertext.")

    return CipherBundle(
        key=parse_hex_value(args.key, "clave"),
        nonce=parse_hex_value(args.nonce, "nonce"),
        ciphertext=parse_hex_value(args.ciphertext, "ciphertext"),
    )


def cmd_decrypt(args: argparse.Namespace) -> None:
    bundle = _load_bundle(args)
    try:
        mensaje = descifrar_mensaje(bundle.key, bundle.nonce, bundle.ciphertext)
    except Exception as exc:
        raise SystemExit(f"No se pudo descifrar: {exc}") from exc
    print("Mensaje recuperado:")
    print(mensaje)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AES-GCM helper.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt = subparsers.add_parser("encrypt", help="Cifrar un mensaje en memoria.")
    encrypt.add_argument("message", help="Mensaje en texto plano.")
    encrypt.add_argument(
        "--key",
        help="Clave AES-256 en hex. Si se omite, se genera una nueva.",
    )
    encrypt.add_argument("--json-out", help="Archivo JSON donde guardar resultados.")
    encrypt.set_defaults(func=cmd_encrypt)

    decrypt = subparsers.add_parser("decrypt", help="Descifrar un mensaje en AES-GCM.")
    decrypt.add_argument("--json-in", help="Archivo JSON generado por encrypt.")
    decrypt.add_argument("--key", help="Clave en hex (alternativa a json).")
    decrypt.add_argument("--nonce", help="Nonce en hex (alternativa a json).")
    decrypt.add_argument("--ciphertext", help="Ciphertext en hex (alternativa a json).")
    decrypt.set_defaults(func=cmd_decrypt)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
