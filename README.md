# Final-Project-Security
Integrantes:

- Jean Paul Ordoñez Ibarguen
- Juan David Garzón
- Isabella Castañeda

Proyecto final de seguridad — herramientas didácticas para demostraciones básicas de criptografía simétrica, hashing y firmas digitales.

**Descripción**
- **Propósito**: Colección de scripts sencillos para aprender y demostrar conceptos de seguridad: cifrado simétrico (AES-GCM), verificación de integridad (SHA-256) y firmas digitales (RSA).
- **Audiencia**: estudiantes o compañeros que quieren practicar intercambio de mensajes seguros entre máquinas (por ejemplo, host ↔ VM) con ejemplos prácticos.

**Archivos principales**
- `aes_tool.py`: Herramienta para cifrado/descifrado con AES-GCM.
	- Modo E (Encriptar): genera una clave AES-256, nonce y ciphertext (imprime los tres en hex para compartir).
	- Modo D (Desencriptar): recibe clave, nonce y ciphertext en hex y recupera el mensaje.
- `signature_tool.py`: Generación de par de claves RSA, firma y verificación.
	- Modo GEN: genera `sign_private.pem` y `sign_public.pem`.
	- Modo SIGN: firma un mensaje con la clave privada y muestra la firma en hex.
	- Modo VERIFY: verifica la firma usando la clave pública.
- `hash_demo.py`: Calcula el hash SHA-256 de un archivo y guarda el resultado en un archivo `.hash.txt` para comprobar integridad.
- `requirements.txt`: Lista de dependencias (solo `cryptography` es externa).

**Dependencias**
- **Python**: recomendado Python 3.8 o superior.
- **Paquetes**: `cryptography>=3.4` (ya incluido en `requirements.txt`).
	- Los demás módulos usados (`os`, `hashlib`, `pathlib`) pertenecen a la biblioteca estándar.

**Instalación**
1. Crear y activar un entorno virtual (recomendado):

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
```

2. Instalar dependencias:

```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

Nota: en Windows el paquete `cryptography` suele instalarse via rueda (wheel). Si hay problemas, actualiza `pip` y vuelve a intentar.

**Uso**
- Ejecutar cualquiera de los scripts desde la carpeta del proyecto:

```powershell
python aes_tool.py
python signature_tool.py
python hash_demo.py
```

- Resumen de uso por script:
	- `aes_tool.py`
		- Selecciona `E` para encriptar: introduce el mensaje; el script imprimirá `CLAVE (hex)`, `NONCE (hex)` y `CIPHERTEXT (hex)` que debes compartir con el receptor.
		- Selecciona `D` para desencriptar: pega la `CLAVE`, `NONCE` y `CIPHERTEXT` en hex para recuperar el mensaje.
	- `signature_tool.py`
		- `GEN`: genera `sign_private.pem` y `sign_public.pem`.
		- `SIGN`: solicita el mensaje y devuelve la firma en hex (comparte firma + mensaje + `sign_public.pem`).
		- `VERIFY`: pega el mensaje y la firma en hex para comprobar si la firma es válida.
	- `hash_demo.py`
		- Introduce el nombre del archivo a hashear (ej: `mensaje.txt`). El script crea `mensaje.txt.hash.txt` con el SHA-256.

**Ejemplos rápidos**
- Encriptar con `aes_tool.py`:

```powershell
python aes_tool.py
# Elegir E, escribir mensaje -> copiar claves/valores hex
```

- Generar claves y firmar con `signature_tool.py`:

```powershell
python signature_tool.py
# Elegir GEN -> genera sign_private.pem y sign_public.pem
# Luego elegir SIGN para firmar un mensaje
```

**Seguridad y limitaciones**
- Estos scripts son didácticos, no son una implementación preparada para producción.
- Las claves y firmas se manejan en archivos y en salida estándar; usa canales seguros para compartir claves/valores en entornos reales.
- `AES-GCM` usa `os.urandom(12)` para el `nonce` (recomendado). No reutilices la misma clave+nonce para múltiples mensajes.

**Contribuir / Mejoras sugeridas**
- Añadir argumentos de línea de comando para evitar interacción manual (ej. `argparse`).
- Añadir manejo de contraseñas/almacenamiento seguro para claves privadas.

**Contacto / Autor**
- Repositorio: `Final-Project-Security` (autor: Pool2004)

---
Si quieres, hago un commit con este `README.md` y empujo los cambios (git). ¿Lo hago ahora? 

