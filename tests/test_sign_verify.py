import pytest
from pathlib import Path
import os  # Para generar contenido aleatorio y manipular archivos

# Importar excepciones y funciones necesarias de crypto_lib
from src.crypto_lib import (
    generate_keys,
    load_private_key,  # Necesario para cargar claves para sign_file/verify_file_signature
    load_public_key,  # Necesario para cargar claves para sign_file/verify_file_signature
    sign_file,
    verify_file_signature,  # Nombre correcto según crypto_lib.py
    sign_message,
    verify_message_signature
)
# Para capturar errores de verificación
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization  # Para excepciones de carga


# --- Fixtures ---

@pytest.fixture
def generated_path_keys(tmp_path):
    """Fixture para generar un par de claves (sin passphrase) y guardarlas en archivos."""
    priv_path = tmp_path / "test_priv.pem"
    pub_path = tmp_path / "test_pub.pem"
    priv_pem, pub_pem = generate_keys()
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return load_private_key(priv_path), load_public_key(pub_path), priv_path, pub_path


@pytest.fixture
def sample_file(tmp_path):
    """Fixture para crear un archivo de ejemplo."""
    file_path = tmp_path / "sample_data.txt"
    content = os.urandom(1024)  # 1KB de datos aleatorios
    file_path.write_bytes(content)
    return file_path, content


@pytest.fixture
def generated_bytes_keys_no_pass():
    """Fixture para generar un par de claves PEM en bytes (sin passphrase)."""
    return generate_keys(passphrase=None)


@pytest.fixture
def generated_bytes_keys_with_pass():
    """Fixture para generar un par de claves PEM en bytes (con passphrase)."""
    passphrase = b"bytes_secret"
    return generate_keys(passphrase=passphrase), passphrase


SAMPLE_MESSAGE_BYTES = os.urandom(512)  # Mensaje de prueba en bytes

# --- Pruebas para funciones basadas en Rutas de Archivo (sign_file, verify_file_signature) ---


def test_path_sign_verify_ok(generated_path_keys, sample_file, tmp_path):
    """Prueba el flujo completo de firma y verificación exitosa usando rutas de archivo."""
    priv_key_obj, pub_key_obj, _, _ = generated_path_keys
    file_to_sign, _ = sample_file
    signature_path = tmp_path / "sample_data.sig"

    sign_file(priv_key_obj, file_to_sign, signature_path)
    assert signature_path.exists()
    assert signature_path.read_bytes() != b""

    verify_file_signature(pub_key_obj, file_to_sign, signature_path)


def test_path_verify_tampered_data(generated_path_keys, sample_file, tmp_path):
    """Prueba que la verificación falla si los datos del archivo original son alterados."""
    priv_key_obj, pub_key_obj, _, _ = generated_path_keys
    file_to_sign, original_content = sample_file
    signature_path = tmp_path / "sample_data_tampered_data.sig"

    sign_file(priv_key_obj, file_to_sign, signature_path)
    file_to_sign.write_bytes(original_content + b"extra_tampered_bytes")

    with pytest.raises(InvalidSignature):
        verify_file_signature(pub_key_obj, file_to_sign, signature_path)


def test_path_verify_tampered_signature(generated_path_keys, sample_file, tmp_path):
    """Prueba que la verificación falla si el archivo de firma es alterado."""
    priv_key_obj, pub_key_obj, _, _ = generated_path_keys
    file_to_sign, _ = sample_file
    signature_path = tmp_path / "sample_data_tampered_sig.sig"

    sign_file(priv_key_obj, file_to_sign, signature_path)
    current_sig = signature_path.read_bytes()
    signature_path.write_bytes(current_sig[::-1])  # Invertir la firma

    with pytest.raises(InvalidSignature):
        verify_file_signature(pub_key_obj, file_to_sign, signature_path)


def test_path_verify_wrong_public_key(tmp_path, sample_file):
    """Prueba que la verificación falla si se usa una clave pública incorrecta."""
    priv_pem1, _ = generate_keys()
    priv_key_obj1 = serialization.load_pem_private_key(
        priv_pem1, password=None)
    _, pub_pem2 = generate_keys()
    pub_key_obj2_incorrect = serialization.load_pem_public_key(pub_pem2)

    file_to_sign, _ = sample_file
    signature_path = tmp_path / "sample_data_wrong_pubkey.sig"

    sign_file(priv_key_obj1, file_to_sign, signature_path)

    with pytest.raises(InvalidSignature):
        verify_file_signature(pub_key_obj2_incorrect,
                              file_to_sign, signature_path)


# --- Pruebas para funciones basadas en Bytes (sign_message, verify_message_signature) ---

def test_bytes_sign_verify_ok_no_passphrase(generated_bytes_keys_no_pass):
    """Prueba firma y verificación exitosa con bytes, sin passphrase."""
    priv_pem_bytes, pub_pem_bytes = generated_bytes_keys_no_pass
    signature = sign_message(
        priv_pem_bytes, SAMPLE_MESSAGE_BYTES, passphrase=None)
    assert signature is not None and signature != b""
    verify_message_signature(pub_pem_bytes, SAMPLE_MESSAGE_BYTES, signature)


def test_bytes_sign_verify_ok_with_passphrase(generated_bytes_keys_with_pass):
    """Prueba firma y verificación exitosa con bytes, con passphrase."""
    (priv_pem_bytes, pub_pem_bytes), passphrase = generated_bytes_keys_with_pass
    signature = sign_message(
        priv_pem_bytes, SAMPLE_MESSAGE_BYTES, passphrase=passphrase)
    assert signature is not None and signature != b""
    verify_message_signature(pub_pem_bytes, SAMPLE_MESSAGE_BYTES, signature)


def test_bytes_sign_fail_incorrect_passphrase(generated_bytes_keys_with_pass):
    """Prueba que la firma con bytes falla si la passphrase es incorrecta."""
    (priv_pem_bytes, _), _ = generated_bytes_keys_with_pass
    incorrect_passphrase = b"wrong_bytes_secret"

    with pytest.raises(ValueError, match="Could not deserialize key data.*bad decrypt"):  # CORREGIDO
        sign_message(priv_pem_bytes, SAMPLE_MESSAGE_BYTES,
                     passphrase=incorrect_passphrase)


def test_bytes_verify_tampered_data(generated_bytes_keys_no_pass):
    """Prueba que la verificación con bytes falla si el mensaje es alterado."""
    priv_pem_bytes, pub_pem_bytes = generated_bytes_keys_no_pass
    signature = sign_message(priv_pem_bytes, SAMPLE_MESSAGE_BYTES)
    tampered_message = SAMPLE_MESSAGE_BYTES + b"tampered"
    with pytest.raises(InvalidSignature):
        verify_message_signature(pub_pem_bytes, tampered_message, signature)


def test_bytes_verify_tampered_signature(generated_bytes_keys_no_pass):
    """Prueba que la verificación con bytes falla si la firma es alterada."""
    priv_pem_bytes, pub_pem_bytes = generated_bytes_keys_no_pass
    signature = sign_message(priv_pem_bytes, SAMPLE_MESSAGE_BYTES)
    tampered_signature = signature[::-1]  # Invertir la firma
    with pytest.raises(InvalidSignature):
        verify_message_signature(
            pub_pem_bytes, SAMPLE_MESSAGE_BYTES, tampered_signature)


def test_bytes_verify_wrong_public_key(generated_bytes_keys_no_pass):
    """Prueba que la verificación con bytes falla si se usa una clave pública incorrecta."""
    priv_pem_bytes1, _ = generated_bytes_keys_no_pass
    _, pub_pem_bytes2_incorrect = generate_keys(passphrase=None)
    signature = sign_message(priv_pem_bytes1, SAMPLE_MESSAGE_BYTES)
    with pytest.raises(InvalidSignature):
        verify_message_signature(
            pub_pem_bytes2_incorrect, SAMPLE_MESSAGE_BYTES, signature)


def test_bytes_sign_invalid_private_key_format():
    """Prueba que firmar con bytes de clave privada PEM inválidos falla."""
    with pytest.raises(ValueError, match="Could not deserialize key data"):  # CORREGIDO
        sign_message(b"ESTO NO ES UNA CLAVE PEM", SAMPLE_MESSAGE_BYTES)


def test_bytes_verify_invalid_public_key_format():
    """Prueba que verificar con bytes de clave pública PEM inválidos falla."""
    priv_pem, _ = generate_keys()
    signature = sign_message(priv_pem, SAMPLE_MESSAGE_BYTES)
    with pytest.raises(ValueError, match="Unable to load PEM file.*MalformedFraming"):  # CORREGIDO
        verify_message_signature(
            b"ESTO TAMPOCO ES UNA CLAVE PEM", SAMPLE_MESSAGE_BYTES, signature)
