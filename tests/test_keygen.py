from pathlib import Path
from crypto_lib import generate_keys, load_private_key, load_public_key

def test_keygen_and_load(tmp_path):
    priv_pem, pub_pem = generate_keys(passphrase=b"abc")
    p_priv = tmp_path / "priv.pem"
    p_pub  = tmp_path / "pub.pem"
    p_priv.write_bytes(priv_pem)
    p_pub.write_bytes(pub_pem)

    priv = load_private_key(p_priv, passphrase=b"abc")
    pub  = load_public_key(p_pub)
    assert priv and pub
