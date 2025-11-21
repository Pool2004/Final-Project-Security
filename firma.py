"""
signature_tool.py

Herramienta para firmas digitales con RSA entre dos equipos.

Modos:
- GEN: Generar par de claves de firma -> sign_private.pem, sign_public.pem
- SIGN: Firmar un mensaje con la clave privada -> firma (hex)
- VERIFY: Verificar una firma (hex) usando la clave pública y el mensaje

Uso típico:
- Host: GEN -> envía sign_public.pem a la VM.
- Host: SIGN -> envía mensaje + firma (hex) + clave pública a la VM.
- VM: VERIFY -> comprueba si la firma es válida.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from pathlib import Path

SIGN_PRIVATE_FILE = "sign_private.pem"
SIGN_PUBLIC_FILE = "sign_public.pem"

def generar_par_claves_firma():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def guardar_clave_privada(private_key, ruta, password=None):
    if password:
        encryption_alg = serialization.BestAvailableEncryption(password)
    else:
        encryption_alg = serialization.NoEncryption()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_alg,
    )
    with open(ruta, "wb") as f:
        f.write(pem)

def guardar_clave_publica(public_key, ruta):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(ruta, "wb") as f:
        f.write(pem)

def cargar_clave_privada(ruta, password=None):
    with open(ruta, "rb") as f:
        data = f.read()
    private_key = serialization.load_pem_private_key(data, password=password)
    return private_key

def cargar_clave_publica(ruta):
    with open(ruta, "rb") as f:
        data = f.read()
    public_key = serialization.load_pem_public_key(data)
    return public_key

def firmar_mensaje(private_key, mensaje):
    datos = mensaje.encode("utf-8")
    firma = private_key.sign(
        datos,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return firma

def verificar_firma(public_key, mensaje, firma):
    datos = mensaje.encode("utf-8")
    try:
        public_key.verify(
            firma,
            datos,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

def modo_gen():
    print("=== MODO GEN (Generar claves de firma) ===")
    private_key, public_key = generar_par_claves_firma()
    guardar_clave_privada(private_key, SIGN_PRIVATE_FILE, password=None)
    guardar_clave_publica(public_key, SIGN_PUBLIC_FILE)
    print(f"Claves de firma generadas en '{SIGN_PRIVATE_FILE}' y '{SIGN_PUBLIC_FILE}'.")
    print("Envía 'sign_public.pem' a tu compañero para que pueda verificar firmas.")

def modo_sign():
    print("=== MODO SIGN (Firmar mensaje) ===")
    if not Path(SIGN_PRIVATE_FILE).exists():
        print(f"No se encontró '{SIGN_PRIVATE_FILE}'. Genera primero las claves (modo GEN).")
        return
    private_key = cargar_clave_privada(SIGN_PRIVATE_FILE, password=None)
    mensaje = input("Mensaje a firmar: ")
    firma = firmar_mensaje(private_key, mensaje)
    print("\nFirma (hex) - envía esto junto con el mensaje y la clave pública:")
    print(firma.hex())

def modo_verify():
    print("=== MODO VERIFY (Verificar firma) ===")
    if not Path(SIGN_PUBLIC_FILE).exists():
        print(f"No se encontró '{SIGN_PUBLIC_FILE}'. Asegúrate de tener la clave pública de firma.")
        return
    public_key = cargar_clave_publica(SIGN_PUBLIC_FILE)
    mensaje = input("Introduce el mensaje (tal como se firmó): ")
    firma_hex = input("Introduce la firma (hex): ").strip()
    try:
        firma = bytes.fromhex(firma_hex)
    except ValueError:
        print("La firma no es hex válida.")
        return

    es_valida = verificar_firma(public_key, mensaje, firma)
    print("\n¿Firma válida?", es_valida)

def main():
    print("=== SIGNATURE TOOL ===")
    print("Modos:")
    print("  GEN    - Generar claves de firma")
    print("  SIGN   - Firmar un mensaje")
    print("  VERIFY - Verificar una firma")
    modo = input("Modo (GEN/SIGN/VERIFY): ").strip().upper()

    if modo == "GEN":
        modo_gen()
    elif modo == "SIGN":
        modo_sign()
    elif modo == "VERIFY":
        modo_verify()
    else:
        print("Modo no válido.")

if __name__ == "__main__":
    main()
