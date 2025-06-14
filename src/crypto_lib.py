from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature 



def generate_keys(key_size: int = 2048, passphrase: bytes = None) -> tuple[bytes, bytes]:
    """
    Genera un par de claves RSA (privada y pública) en formato PEM.
    La clave privada puede ser cifrada con una passphrase.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size

    )

    encryption_algorithm = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase else
        serialization.NoEncryption()
    )

    priv_pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )

    pub_pem_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem_bytes, pub_pem_bytes

def load_private_key(key_path: Path, passphrase: bytes = None):
    """
    Carga una clave privada RSA desde un archivo PEM.
    Returns un objeto de clave privada RSA.
    """
    key_data_bytes = key_path.read_bytes()
    return serialization.load_pem_private_key(
        key_data_bytes,
        password=passphrase

    )

def load_public_key(key_path: Path):
    """
    Carga una clave pública RSA desde un archivo PEM.
    Returns un objeto de clave pública RSA.
    """
    key_data_bytes = key_path.read_bytes()
    return serialization.load_pem_public_key(
        key_data_bytes

    )

def sign_file(private_key_obj, file_to_sign_path: Path, signature_output_path: Path):
    """
    Firma el contenido de un archivo usando un objeto de clave privada y guarda la firma.
    """
    data_to_sign_bytes = file_to_sign_path.read_bytes()
    signature_bytes = private_key_obj.sign(
        data_to_sign_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature_output_path.write_bytes(signature_bytes)

def verify_file_signature(public_key_obj, original_file_path: Path, signature_file_path: Path):
    """
    Verifica la firma de un archivo usando un objeto de clave pública.
    Lanza cryptography.exceptions.InvalidSignature si la verificación falla.
    """
    original_data_bytes = original_file_path.read_bytes()
    signature_bytes = signature_file_path.read_bytes()
    public_key_obj.verify( 
        signature_bytes,
        original_data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )



def sign_message(private_key_pem_bytes: bytes, message_bytes: bytes, passphrase: bytes = None) -> bytes:
    """
    Carga una clave privada RSA desde bytes PEM, firma message_bytes y devuelve la firma.
    Utiliza PSS padding y SHA256.
    Returns Bytes de la firma digital.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem_bytes,
        password=passphrase
    )
    signature_bytes = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature_bytes

def verify_message_signature(public_key_pem_bytes: bytes, message_bytes: bytes, signature_bytes: bytes):
    """
    Carga una clave pública RSA desde bytes PEM y verifica la firma para message_bytes.
    Utiliza PSS padding y SHA256.
    """
    public_key = serialization.load_pem_public_key(
        public_key_pem_bytes
    )
    public_key.verify( 
        signature_bytes,
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
