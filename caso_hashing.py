"""
caso_hashing.py

Demostración de hashes con SHA-256 para comprobar integridad entre dos equipos.

Uso típico:
- Equipo A (host): calcula el hash de un archivo, lo guarda y envía el archivo al Equipo B.
- Equipo B (VM): recalcula el hash del archivo y lo compara.

Si los hashes coinciden, el archivo no fue alterado en el camino.
"""

import hashlib
from pathlib import Path

def sha256_file(ruta):
    """
    Devuelve el hash SHA-256 del contenido de un archivo.
    """
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(4096), b""):
            h.update(bloque)
    return h.hexdigest()

def main():
    print("=== DEMO SHA-256 (integridad de archivo) ===")
    ruta_archivo = input("Nombre del archivo a hashear (ej: mensaje.txt): ").strip()

    if not Path(ruta_archivo).exists():
        print(f"El archivo '{ruta_archivo}' no existe en esta carpeta.")
        return

    hash_archivo = sha256_file(ruta_archivo)
    print(f"\nHash SHA-256 de '{ruta_archivo}':\n{hash_archivo}\n")

    # Guardamos el hash en un archivo .hash para poder enviarlo o guardarlo
    hash_filename = ruta_archivo + ".hash.txt"
    with open(hash_filename, "w", encoding="utf-8") as f:
        f.write(hash_archivo + "\n")

    print(f"Hash guardado en el archivo: {hash_filename}")
    print("Puedes enviar el archivo original y opcionalmente este hash a tu compañero.")

if __name__ == "__main__":
    main()
