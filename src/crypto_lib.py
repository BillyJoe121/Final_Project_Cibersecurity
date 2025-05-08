from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def generate_keys(key_size=2048, passphrase: bytes=None):
    """Genera y devuelve (priv_pem, pub_pem)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    encryption = (serialization.BestAvailableEncryption(passphrase)
                  if passphrase else serialization.NoEncryption())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem

def load_private_key(path: Path, passphrase: bytes=None):
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=passphrase)

def load_public_key(path: Path):
    data = path.read_bytes()
    return serialization.load_pem_public_key(data)

def sign_file(priv_key, in_path: Path, sig_path: Path):
    data = in_path.read_bytes()
    signature = priv_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    sig_path.write_bytes(signature)

def verify_file(pub_key, in_path: Path, sig_path: Path):
    data = in_path.read_bytes()
    signature = sig_path.read_bytes()
    pub_key.verify(
        signature,
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
