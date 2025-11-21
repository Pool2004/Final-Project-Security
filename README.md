# SecOps Lab Toolkit

Mini laboratorio de criptografía pensado para tareas rápidas: verificar integridad de archivos, cifrar mensajes (simétrico/asimétrico) y firmar contenido. Todo corre desde CLI y cada script está orientado a objetos para facilitar la reutilización en otros proyectos.

## Puesta en marcha express
1. **Clona o copia** este repositorio.
2. **Prepara un entorno** (PowerShell):
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

## Scripts y ejecución

| Script | Qué hace | Ejemplos |
| --- | --- | --- |
| `caso_hashing.py` | Calcula/valida hashes SHA-256 con `HashIntegrityTool`. | `python caso_hashing.py digest documento.pdf --out documento.sha256`<br>`python caso_hashing.py compare documento.pdf --hash-file documento.sha256` |
| `cifrado_aes.py` | `AESGCMTool` cifra/descifra mensajes con AES-GCM, opcionalmente serializando a JSON. | `python cifrado_aes.py encrypt "mensaje secreto"`<br>`python cifrado_aes.py decrypt --json-in paquete.json` |
| `caso_cifrado_rsa.py` | `RSAEncryptionTool` genera claves RSA-OAEP y permite cifrar/descifrar. | `python caso_cifrado_rsa.py gen --password`<br>`python caso_cifrado_rsa.py encrypt "texto"`<br>`python caso_cifrado_rsa.py decrypt <cipher_hex>` |
| `firma.py` | `RSASignatureTool` crea claves RSA-PSS, firma y verifica mensajes. | `python firma.py gen --password`<br>`python firma.py sign "release listo"`<br>`python firma.py verify "release listo" <firma_hex>` |

> Tip: cada script incluye `--help` con todas las opciones disponibles.

## Buenas prácticas rápidas
- No reutilices la misma combinación clave+nonce en AES-GCM.
- Protege tus `.pem` con `--password` si los vas a mover entre máquinas.
- Guarda los hashes en carpetas separadas del archivo original para detectar manipulaciones.

## ¿Qué sigue?
- Crear módulos (`python -m secops_lab ...`), agregar pruebas y automatizar reportes si lo usas en cursos o talleres.