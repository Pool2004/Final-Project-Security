from cifrado_aes import NONCE_SIZE, cifrar_mensaje, descifrar_mensaje


def test_cifrar_y_descifrar(monkeypatch):
    key = bytes.fromhex("11" * 32)
    test_nonce = b"\x01" * NONCE_SIZE
    monkeypatch.setattr("cifrado_aes.os.urandom", lambda n: test_nonce)

    bundle = cifrar_mensaje(key, "mensaje secreto")

    assert bundle.key == key
    assert bundle.nonce == test_nonce
    assert descifrar_mensaje(key, bundle.nonce, bundle.ciphertext) == "mensaje secreto"

