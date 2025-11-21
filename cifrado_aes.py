
"""CLI directa para cifrar/descifrar mensajes con AES-GCM."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12

# Glosario:
# - "paquete": diccionario con clave, nonce y ciphertext en hex.
# - "vector": nonce aleatorio recomendado para GCM (12 bytes).


class AESPacket:
    """Representa un paquete AES-GCM en memoria."""

    def __init__(self, key: bytes, nonce: bytes, ciphertext: bytes):
        self.key = key
        self.nonce = nonce
        self.ciphertext = ciphertext

    def to_dict(self) -> dict[str, str]:
        return {"key": self.key.hex(), "nonce": self.nonce.hex(), "ciphertext": self.ciphertext.hex()}

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> AESPacket:
        try:
            return cls(
                key=bytes.fromhex(data["key"]),
                nonce=bytes.fromhex(data["nonce"]),
                ciphertext=bytes.fromhex(data["ciphertext"]),
            )
        except KeyError as exc:
            raise SystemExit(f"Falta el campo {exc.args[0]} en el paquete.") from exc
        except ValueError as exc:
            raise SystemExit("Valores hex inválidos en el paquete.") from exc


class AESGCMManager:
    """Orquestador de cifrado/descifrado sacado a clase."""

    def __init__(self, nonce_size: int = NONCE_SIZE):
        self.nonce_size = nonce_size

    @staticmethod
    def _parse_hex(value: str, label: str) -> bytes:
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise SystemExit(f"{label} no es hex válido.") from exc

    def encrypt(self, message: str, key_hex: str | None = None) -> AESPacket:
        key = self._parse_hex(key_hex, "Clave") if key_hex else AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(self.nonce_size)
        aes = AESGCM(key)
        ciphertext = aes.encrypt(nonce, message.encode("utf-8"), None)
        return AESPacket(key, nonce, ciphertext)

    def decrypt(
        self,
        *,
        json_in: Path | None = None,
        key_hex: str | None = None,
        nonce_hex: str | None = None,
        ciphertext_hex: str | None = None,
    ) -> str:
        if json_in:
            data = json.loads(json_in.read_text(encoding="utf-8"))
            packet = AESPacket.from_dict(data)
        else:
            if not (key_hex and nonce_hex and ciphertext_hex):
                raise SystemExit("Indica --json-in o trio de --key/--nonce/--ciphertext.")
            packet = AESPacket(
                key=self._parse_hex(key_hex, "Clave"),
                nonce=self._parse_hex(nonce_hex, "Nonce"),
                ciphertext=self._parse_hex(ciphertext_hex, "Ciphertext"),
            )
        aes = AESGCM(packet.key)
        try:
            mensaje = aes.decrypt(packet.nonce, packet.ciphertext, None)
        except Exception as exc:
            raise SystemExit(f"No se pudo descifrar: {exc}") from exc
        return mensaje.decode("utf-8")


class AESCLI:
    def __init__(self, manager: AESGCMManager | None = None):
        self.manager = manager or AESGCMManager()

    def handler_encrypt(self, args: argparse.Namespace) -> None:
        packet = self.manager.encrypt(args.message, key_hex=args.key)
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(packet.to_dict(), indent=2), encoding="utf-8")
            print(f"Paquete guardado en {args.json_out}")
        else:
            print("Clave (hex):      ", packet.key.hex())
            print("Nonce (hex):      ", packet.nonce.hex())
            print("Ciphertext (hex): ", packet.ciphertext.hex())

    def handler_decrypt(self, args: argparse.Namespace) -> None:
        mensaje = self.manager.decrypt(
            json_in=Path(args.json_in) if args.json_in else None,
            key_hex=args.key,
            nonce_hex=args.nonce,
            ciphertext_hex=args.ciphertext,
        )
        print("Mensaje recuperado:")
        print(mensaje)

    def build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description="Pequeña utilidad AES-GCM.")
        sub = parser.add_subparsers(dest="cmd", required=True)

        enc = sub.add_parser("encrypt", help="Cifrar texto plano.")
        enc.add_argument("message", help="Frase a proteger.")
        enc.add_argument("--key", help="Clave AES-256 (hex). Si no se envía, se genera.")
        enc.add_argument("--json-out", help="Ruta para guardar el paquete en JSON.")
        enc.set_defaults(func=self.handler_encrypt)

        dec = sub.add_parser("decrypt", help="Descifrar usando un paquete AES-GCM.")
        dec.add_argument("--json-in", help="Archivo JSON producido por encrypt.")
        dec.add_argument("--key", help="Clave en hex (alternativa a json).")
        dec.add_argument("--nonce", help="Nonce en hex (alternativa a json).")
        dec.add_argument("--ciphertext", help="Ciphertext en hex (alternativa a json).")
        dec.set_defaults(func=self.handler_decrypt)

        return parser

    def run(self, argv: list[str] | None = None) -> None:
        parser = self.build_parser()
        args = parser.parse_args(argv)
        args.func(args)


def main() -> None:
    AESCLI().run()


if __name__ == "__main__":
    main()
