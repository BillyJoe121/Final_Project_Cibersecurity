from pathlib import Path
import pytest
from crypto_lib import generate_keys, load_private_key, load_public_key, sign_file, verify_file

def test_sign_and_verify(tmp_path):
    # Generar claves
    priv_pem, pub_pem = generate_keys()
    (tmp_path/"priv.pem").write_bytes(priv_pem)
    (tmp_path/"pub.pem").write_bytes(pub_pem)

    priv = load_private_key(tmp_path/"priv.pem")
    pub  = load_public_key(tmp_path/"pub.pem")

    # sample.txt
    sample = tmp_path/"sample.txt"
    sample.write_text("contenido de prueba")

    sig = tmp_path/"sample.sig"
    sign_file(priv, sample, sig)

    # Verifica sin excepción
    verify_file(pub, sample, sig)

    # Alteración -> debe fallar
    sample.write_text("modificado")
    with pytest.raises(Exception):
        verify_file(pub, sample, sig)
