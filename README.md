# SecOps Lab Toolkit

Colección compacta de utilidades de línea de comandos para practicar conceptos de seguridad ofensiva y defensiva: verificación de integridad, cifrado simétrico y firmas digitales. Cada script fue reescrito con `argparse`, mensajes contextualizados y opciones modernas para automatizar laboratorios host ↔ VM.

## Componentes
- `caso_hashing.py`: CLI con subcomandos `digest` (genera hashes) y `compare` (valida un archivo contra un hash en texto o archivo).
- `cifrado_aes.py`: cifrado/descifrado AES-256-GCM con empaquetado opcional en JSON (`encrypt`, `decrypt`).
- `firma.py`: orquestación de claves RSA-PSS, firmas y verificación (`gen`, `sign`, `verify`) con protección por contraseña opcional.

## Requisitos
- Python 3.9 o superior.
- Dependencias listadas en `requirements.txt`.

Instalación recomendada:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

## Flujo de trabajo

### Hashes
```powershell
python caso_hashing.py digest evidencia.iso --out evidencia.sha256
python caso_hashing.py compare evidencia.iso --hash-file evidencia.sha256
python caso_hashing.py compare evidencia.iso --hash-value <hash_hex>
```

### AES-GCM
```powershell
python cifrado_aes.py encrypt "Mensaje ultra secreto" --json-out paquete.json
python cifrado_aes.py decrypt --json-in paquete.json
# o con parámetros individuales
python cifrado_aes.py decrypt --key <hex> --nonce <hex> --ciphertext <hex>
```

### Firmas RSA
```powershell
python firma.py gen --password
python firma.py sign "Release 1.2 listo"
python firma.py verify "Release 1.2 listo" <firma_hex>
```

## Buenas prácticas
- No reutilizar el mismo par `clave + nonce` para AES-GCM.
- Guardar los archivos `sign_private.pem` en soportes cifrados; habilitar `--password` para agregar PBKDF + AES al PEM.
- Mantener los hashes en rutas separadas del archivo original para detectar alteraciones.

## Ideas futuras
- Empaquetar como módulo (`python -m secopslab ...`).
- Añadir soporte para entrada/salida por tuberías y pruebas unitarias mínimas.
- Incorporar generación automatizada de reportes HTML con resultados criptográficos.