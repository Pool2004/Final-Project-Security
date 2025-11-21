import hashlib

from caso_hashing import sha256_chunks, sha256_file


def test_sha256_file(tmp_path):
    sample = tmp_path / "mensaje.txt"
    sample.write_text("integridad total", encoding="utf-8")

    digest = sha256_file(sample)

    assert digest == hashlib.sha256(b"integridad total").hexdigest()


def test_sha256_chunks_custom_iterable():
    data = [b"hola", b" ", b"mundo"]

    digest = sha256_chunks(data)

    assert digest == hashlib.sha256(b"hola mundo").hexdigest()

