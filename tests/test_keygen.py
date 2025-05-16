import pytest
from pathlib import Path
# from cryptography.exceptions import InvalidSignature # No se usa aquí
from cryptography.hazmat.primitives import serialization # Para TypeError
import os

from src.crypto_lib import (
    generate_keys,
    load_private_key,
    load_public_key
)

INVALID_PEM_CONTENT = b"-----BEGIN INVALID KEY-----\nNOTAREALKEY\n-----END INVALID KEY-----"

# ... (test_generate_keys_no_passphrase y test_generate_keys_with_passphrase se mantienen igual si pasaron) ...
# Los tests que pasaron (indicados con '.') no los incluyo aquí para brevedad.
# Si alguno de esos también necesita ajuste por mensajes, el principio es el mismo.

def test_generate_keys_no_passphrase(tmp_path):
    """Prueba la generación de claves sin passphrase y su carga."""
    priv_path = tmp_path / "priv_no_pass.pem"
    pub_path = tmp_path / "pub_no_pass.pem"

    priv_pem, pub_pem = generate_keys(passphrase=None)
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

    assert priv_path.exists()
    assert pub_path.exists()

    loaded_priv = load_private_key(priv_path, passphrase=None)
    loaded_pub = load_public_key(pub_path)
    assert loaded_priv is not None
    assert loaded_pub is not None

def test_generate_keys_with_passphrase(tmp_path):
    """Prueba la generación de claves con passphrase y su carga correcta."""
    priv_path = tmp_path / "priv_with_pass.pem"
    pub_path = tmp_path / "pub_with_pass.pem" # Necesario para generar la clave privada
    passphrase = b"supersecret123"

    priv_pem, pub_pem = generate_keys(passphrase=passphrase)
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

    assert priv_path.exists()
    assert pub_path.exists()

    loaded_priv = load_private_key(priv_path, passphrase=passphrase)
    loaded_pub = load_public_key(pub_path)
    assert loaded_priv is not None
    assert loaded_pub is not None

def test_load_private_key_incorrect_passphrase(tmp_path):
    """Prueba que cargar una clave privada cifrada con passphrase incorrecta falla."""
    priv_path = tmp_path / "priv_incorrect_pass.pem"
    correct_passphrase = b"correct_password"
    incorrect_passphrase = b"wrong_password"

    priv_pem, _ = generate_keys(passphrase=correct_passphrase)
    priv_path.write_bytes(priv_pem)

    # Ajustar el match para ser más general o buscar una subcadena clave
    with pytest.raises(ValueError, match="Could not deserialize key data.*bad decrypt"):
        load_private_key(priv_path, passphrase=incorrect_passphrase)

def test_load_encrypted_private_key_without_passphrase(tmp_path):
    """Prueba que cargar una clave privada cifrada sin passphrase falla."""
    priv_path = tmp_path / "priv_encrypted_no_pass_provided.pem"
    passphrase = b"verysecret"

    priv_pem, _ = generate_keys(passphrase=passphrase)
    priv_path.write_bytes(priv_pem)

    with pytest.raises(TypeError, match="Password was not given but private key is encrypted"):
        load_private_key(priv_path, passphrase=None)

def test_load_unencrypted_private_key_with_passphrase_fails(tmp_path): # Nombre y lógica cambiados
    """
    Prueba que cargar una clave privada NO cifrada pero PROVEYENDO una passphrase
    AHORA se espera que falle con TypeError.
    """
    priv_path = tmp_path / "priv_unencrypted_pass_provided.pem"
    passphrase_provided = b"unnecessary_password"

    priv_pem, _ = generate_keys(passphrase=None) # Clave no cifrada
    priv_path.write_bytes(priv_pem)

    with pytest.raises(TypeError, match="Password was given but private key is not encrypted"): # Esperar TypeError
        load_private_key(priv_path, passphrase=passphrase_provided)


def test_load_non_existent_key(tmp_path): # Asumiendo que este pasó
    """Prueba que cargar una clave desde una ruta no existente falla."""
    non_existent_path = tmp_path / "non_existent_key.pem"
    with pytest.raises(FileNotFoundError):
        load_private_key(non_existent_path)
    with pytest.raises(FileNotFoundError):
        load_public_key(non_existent_path)


def test_load_invalid_pem_private_key(tmp_path):
    """Prueba que cargar una clave privada PEM inválida/corrupta falla."""
    invalid_priv_key_path = tmp_path / "invalid_priv.pem"
    invalid_priv_key_path.write_bytes(INVALID_PEM_CONTENT)

    # Ajustar el match
    with pytest.raises(ValueError, match="Could not deserialize key data"):
        load_private_key(invalid_priv_key_path)

def test_load_invalid_pem_public_key(tmp_path):
    """Prueba que cargar una clave pública PEM inválida/corrupta falla."""
    invalid_pub_key_path = tmp_path / "invalid_pub.pem"
    invalid_pub_key_path.write_bytes(INVALID_PEM_CONTENT)

    # Ajustar el match al mensaje específico o una parte clave
    with pytest.raises(ValueError, match="Unable to load PEM file.*InvalidData"):
        load_public_key(invalid_pub_key_path)