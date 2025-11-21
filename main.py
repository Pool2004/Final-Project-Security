"""Script de orquestación que prueba todas las utilidades del laboratorio."""

from __future__ import annotations

import json
from pathlib import Path

from caso_cifrado_rsa import DEFAULT_PRIV as RSA_DEFAULT_PRIV
from caso_cifrado_rsa import DEFAULT_PUB as RSA_DEFAULT_PUB
from caso_cifrado_rsa import RSAEncryptionTool
from caso_hashing import HashToolkit
from cifrado_aes import AESGCMManager
from firma import DEFAULT_PRIV as SIGN_DEFAULT_PRIV
from firma import DEFAULT_PUB as SIGN_DEFAULT_PUB
from firma import SignatureManager

BASE_DIR = Path(__file__).parent
INPUTS_DIR = BASE_DIR / "inputs"
OUTPUTS_DIR = BASE_DIR / "outputs"


def _ensure_inputs() -> dict[str, Path]:
    """Crea archivos de entrada de prueba si no existen."""
    INPUTS_DIR.mkdir(exist_ok=True)
    samples = {
        "hash_input.txt": "Mensaje de prueba para hashing.\nDetecta cualquier modificación.\n",
        "aes_message.txt": "Este texto será protegido con AES-GCM.\nMantén la confidencialidad.\n",
        "rsa_message.txt": "RSA-OAEP cifra este mensaje asimétricamente.\nComparte la clave pública.\n",
        "signature_message.txt": "Firma este contenido para garantizar autenticidad.\n",
    }
    paths: dict[str, Path] = {}
    for name, content in samples.items():
        path = INPUTS_DIR / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")
        paths[name] = path
    return paths


def run_hashing(file_path: Path) -> None:
    tool = HashToolkit()
    digest = tool.digest_file(file_path)
    OUTPUTS_DIR.mkdir(exist_ok=True)
    digest_path = OUTPUTS_DIR / f"{file_path.stem}.sha256"
    tool.write_digest(digest_path, digest)
    match, actual = tool.compare(file_path, digest)
    status = "OK" if match else "MISMATCH"
    print(f"[HASH ] SHA-256 guardado en {digest_path} ({status}) => {actual}")


def run_aes(file_path: Path) -> None:
    manager = AESGCMManager()
    message = file_path.read_text(encoding="utf-8")
    packet = manager.encrypt(message)
    packet_path = OUTPUTS_DIR / "aes_packet.json"
    packet_path.write_text(json.dumps(packet.to_dict(), indent=2), encoding="utf-8")
    recovered = manager.decrypt(json_in=packet_path)
    recovered_path = OUTPUTS_DIR / "aes_decrypted.txt"
    recovered_path.write_text(recovered, encoding="utf-8")
    print(
        f"[AES  ] Paquete AES-GCM almacenado en {packet_path}. Texto recuperado en {recovered_path}."
    )


def run_rsa(file_path: Path) -> None:
    tool = RSAEncryptionTool()
    private, public = tool.generate_keypair()
    priv_path = OUTPUTS_DIR / RSA_DEFAULT_PRIV
    pub_path = OUTPUTS_DIR / RSA_DEFAULT_PUB
    tool.save_private_key(private, priv_path, password=None)
    tool.save_public_key(public, pub_path)

    message = file_path.read_text(encoding="utf-8")
    ciphertext = tool.encrypt(public, message)
    cipher_path = OUTPUTS_DIR / "rsa_ciphertext.hex"
    cipher_path.write_text(ciphertext.hex() + "\n", encoding="utf-8")
    plaintext = tool.decrypt(private, ciphertext)
    plain_path = OUTPUTS_DIR / "rsa_decrypted.txt"
    plain_path.write_text(plaintext, encoding="utf-8")
    print(
        f"[RSA  ] Claves en {priv_path.name}/{pub_path.name}. Ciphertext en {cipher_path}. Texto claro en {plain_path}."
    )


def run_signature(file_path: Path) -> None:
    manager = SignatureManager()
    private, public = manager.generar_llavero()
    priv_path = OUTPUTS_DIR / SIGN_DEFAULT_PRIV
    pub_path = OUTPUTS_DIR / SIGN_DEFAULT_PUB
    manager.guardar_privada(private, priv_path, password=None)
    manager.guardar_publica(public, pub_path)

    message = file_path.read_text(encoding="utf-8")
    signature = manager.firmar_mensaje(private, message)
    signature_path = OUTPUTS_DIR / "signature.hex"
    signature_path.write_text(signature.hex() + "\n", encoding="utf-8")
    is_valid = manager.verificar_sello(public, message, signature)
    verdict = "válida" if is_valid else "inválida"
    print(
        f"[FIRMA] Llavero en {priv_path.name}/{pub_path.name}. Firma guardada en {signature_path} ({verdict})."
    )


def main() -> None:
    INPUTS_DIR.mkdir(exist_ok=True)
    OUTPUTS_DIR.mkdir(exist_ok=True)
    paths = _ensure_inputs()
    print("== Iniciando pruebas integradas ==")
    run_hashing(paths["hash_input.txt"])
    run_aes(paths["aes_message.txt"])
    run_rsa(paths["rsa_message.txt"])
    run_signature(paths["signature_message.txt"])
    print("== Listo. Revisa la carpeta 'outputs' para ver los artefactos generados ==")


if __name__ == "__main__":
    main()

