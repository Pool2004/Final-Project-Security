from firma import (
    generar_par_claves_firma,
    firmar_mensaje,
    verificar_firma,
)


def test_firmar_y_verificar():
    private_key, public_key = generar_par_claves_firma()
    message = "release v2.0 listo"

    signature = firmar_mensaje(private_key, message)

    assert verificar_firma(public_key, message, signature)
    assert not verificar_firma(public_key, "mensaje alterado", signature)

