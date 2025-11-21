from caso_cifrado_rsa import (
    decrypt_message,
    encrypt_message,
    generate_keypair,
)


def test_rsa_encrypt_decrypt_roundtrip():
    private_key, public_key = generate_keypair(bits=2048)
    message = "mensaje para canal asimétrico"

    ciphertext = encrypt_message(public_key, message)
    recovered = decrypt_message(private_key, ciphertext)

    assert recovered == message

