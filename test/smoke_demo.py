"""Prueba de humo para las utilidades criptográficas."""

from __future__ import annotations

import json
from pathlib import Path

from caso_cifrado_rsa import decrypt_message as rsa_decrypt
from caso_cifrado_rsa import encrypt_message as rsa_encrypt
from caso_cifrado_rsa import generate_keypair as rsa_generate
from caso_hashing import sha256_file
from cifrado_aes import cifrar_mensaje, descifrar_mensaje, generar_clave_aes_256
from firma import generar_par_claves_firma, firmar_mensaje, verificar_firma

ARTIFACTS_DIR = Path("test_artifacts")


def heading(title: str) -> None:
    print(f"\n=== {title} ===")


def demo_hashing() -> None:
    heading("HASHING")
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    sample = ARTIFACTS_DIR / "hash_demo.txt"
    sample.write_text("archivo con integridad", encoding="utf-8")
    digest = sha256_file(sample)
    (ARTIFACTS_DIR / "hash_demo.txt.sha256").write_text(digest + "\n", encoding="utf-8")
    print("SHA-256:", digest)


def demo_aes() -> None:
    heading("AES-GCM")
    key = generar_clave_aes_256()
    bundle = cifrar_mensaje(key, "mensaje ultra secreto")
    recovered = descifrar_mensaje(key, bundle.nonce, bundle.ciphertext)
    print("Nonce:", bundle.nonce.hex())
    print("Ciphertext:", bundle.ciphertext.hex()[:40] + "...")
    print("Mensaje recuperado:", recovered)


def demo_rsa_encryption() -> None:
    heading("RSA-OAEP")
    private_key, public_key = rsa_generate()
    ciphertext = rsa_encrypt(public_key, "canal asimétrico")
    print("Ciphertext length:", len(ciphertext))
    message = rsa_decrypt(private_key, ciphertext)
    print("Mensaje descifrado:", message)


def demo_signatures() -> None:
    heading("RSA-PSS")
    private_key, public_key = generar_par_claves_firma()
    firma = firmar_mensaje(private_key, "entrega oficial")
    print("Firma (hex parcial):", firma.hex()[:40] + "...")
    print("Verificación:", verificar_firma(public_key, "entrega oficial", firma))


def main() -> None:
    demo_hashing()
    demo_aes()
    demo_rsa_encryption()
    demo_signatures()
    print("\nSmoke test finalizado sin errores.")


if __name__ == "__main__":
    main()

