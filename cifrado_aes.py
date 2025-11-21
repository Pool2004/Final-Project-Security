"""
cifrado_aes.py

Herramienta simple para cifrado simétrico con AES-GCM entre dos equipos.

Modos:
- E: Encriptar un mensaje -> imprime CLAVE, NONCE, CIPHERTEXT (en hex) para compartir.
- D: Desencriptar -> pide CLAVE, NONCE, CIPHERTEXT (en hex) y muestra el mensaje original.

Equipo A puede encriptar y enviar los valores hex por correo.
Equipo B puede desencriptar introduciendo esos valores.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generar_clave_aes_256():
    return AESGCM.generate_key(bit_length=256)

def cifrar_mensaje(key, mensaje):
    datos = mensaje.encode("utf-8")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # recomendado para GCM
    ciphertext = aesgcm.encrypt(nonce, datos, None)
    return nonce, ciphertext

def descifrar_mensaje(key, nonce, ciphertext):
    aesgcm = AESGCM(key)
    datos = aesgcm.decrypt(nonce, ciphertext, None)
    return datos.decode("utf-8")

def modo_encriptar():
    print("=== MODO ENCRIPTAR (AES-GCM) ===")
    mensaje = input("Escribe el mensaje que quieres cifrar: ")

    key = generar_clave_aes_256()
    nonce, ciphertext = cifrar_mensaje(key, mensaje)

    print("\n--- RESULTADOS (COPIAR Y ENVIAR) ---")
    print(f"CLAVE (hex):      {key.hex()}")
    print(f"NONCE (hex):      {nonce.hex()}")
    print(f"CIPHERTEXT (hex): {ciphertext.hex()}")
    print("----------------------------------")
    print("Envía estos 3 valores a tu compañero por un canal seguro (por ejemplo, correo).")

def modo_desencriptar():
    print("=== MODO DESENCRIPTAR (AES-GCM) ===")
    key_hex = input("Introduce la CLAVE (hex): ").strip()
    nonce_hex = input("Introduce el NONCE (hex): ").strip()
    ciphertext_hex = input("Introduce el CIPHERTEXT (hex): ").strip()

    try:
        key = bytes.fromhex(key_hex)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
    except ValueError:
        print("Error: alguna de las cadenas no es hex válida.")
        return

    try:
        mensaje = descifrar_mensaje(key, nonce, ciphertext)
        print("\nMensaje descifrado:")
        print(mensaje)
    except Exception as e:
        print("\nError al descifrar. Es probable que los datos hayan sido alterados o que la clave/nonce sean incorrectos.")
        print(f"Detalle técnico: {e}")

def main():
    print("=== AES TOOL (AES-GCM) ===")
    print("Selecciona modo:")
    print("  [E] Encriptar")
    print("  [D] Desencriptar")
    modo = input("Opción (E/D): ").strip().upper()

    if modo == "E":
        modo_encriptar()
    elif modo == "D":
        modo_desencriptar()
    else:
        print("Opción no válida.")

if __name__ == "__main__":
    main()
