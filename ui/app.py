import os
import sys
from io import BytesIO
from zipfile import ZipFile
from pathlib import Path
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

# Añadir la raíz del proyecto al PYTHONPATH para importar desde src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import (
    Flask, render_template, request, send_file,
    flash, redirect, url_for
)

# Asumimos que cryptography y sus excepciones están disponibles
from cryptography.exceptions import InvalidSignature


try:
    from src.crypto_lib import generate_keys, sign_message, verify_message_signature
except ImportError:

    print("ERROR: No se pudo importar crypto_lib.py o sus funciones necesarias.")
    print("Asegúrate de que src/crypto_lib.py exista y contenga generate_keys, sign_message, y verify_message_signature.")


    def generate_keys(*args, **kwargs): raise RuntimeError("crypto_lib.generate_keys no disponible")
    def sign_message(*args, **kwargs): raise RuntimeError("crypto_lib.sign_message no disponible")
    def verify_message_signature(*args, **kwargs): raise RuntimeError("crypto_lib.verify_message_signature no disponible")


app = Flask(__name__)


app.secret_key = os.environ.get("FLASK_SECRET_KEY", "voy_a_poner_aquí_mi_secret_key_muy_insegura")
if app.secret_key == "desarrollo_fallback_secret_key_muy_insegura" and os.environ.get("FLASK_ENV") != "development":
    print("ADVERTENCIA: Estás usando una FLASK_SECRET_KEY por defecto e insegura en un entorno que no parece ser de desarrollo.")


# ───────────────────────────── Rutas ──────────────────────────────────────────

@app.route("/")
def index():
    # Redirigir a la página de generación de claves como la página principal.
    return redirect(url_for('keygen'))

# ── 1) Generación de par de claves RSA ───────────────────────────────────────
@app.route("/keygen", methods=["GET", "POST"])
def keygen():
    if request.method == "POST":
        # Usar .get() para evitar KeyError si los campos no están presentes, aunque 'required' en HTML debería prevenirlo.
        priv_key_form_name = request.form.get("priv_name")
        pub_key_form_name = request.form.get("pub_name")
        passphrase_form = request.form.get("passphrase") # Será string vacío si no se llena, no None

        # Validar que los nombres de archivo no estén vacíos
        if not priv_key_form_name:
            flash("El nombre para el archivo de la clave privada es obligatorio.", "error")
            return render_template("keygen.html")
        if not pub_key_form_name:
            flash("El nombre para el archivo de la clave pública es obligatorio.", "error")
            return render_template("keygen.html")

        # Asegurar que los nombres tengan la extensión .pem
        name_priv = priv_key_form_name if priv_key_form_name.endswith(".pem") else f"{priv_key_form_name}.pem"
        name_pub = pub_key_form_name if pub_key_form_name.endswith(".pem") else f"{pub_key_form_name}.pem"

        # La passphrase será None si el string está vacío, de lo contrario, se codifica.
        passphrase_bytes = passphrase_form.encode() if passphrase_form else None

        try:
            priv_pem_bytes, pub_pem_bytes = generate_keys(
                passphrase=passphrase_bytes
            )
        except Exception as e:
            # Captura genérica para errores inesperados durante la generación de claves
            flash(f"Error crítico al generar claves: {e}", "error")
            return render_template("keygen.html")

        # Crear un archivo ZIP en memoria para las claves
        zip_buffer = BytesIO()
        with ZipFile(zip_buffer, "w") as zf:
            zf.writestr(name_priv, priv_pem_bytes)
            zf.writestr(name_pub, pub_pem_bytes)
        zip_buffer.seek(0) # Rebobinar el buffer para la lectura con send_file

        flash(f"Claves generadas y empaquetadas en 'keys.zip'.", "success")
        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name="keys.zip",
            mimetype="application/zip"
        )

    return render_template("keygen.html")

# ── 2) Firmar archivo ────────────────────────────────────────────────────────
@app.route("/sign", methods=["GET", "POST"])
def sign():
    if request.method == "POST":
        input_file = request.files.get("input_file") # Nombre genérico del campo de archivo
        key_file = request.files.get("privkey")
        passphrase_form = request.form.get("passphrase")

        # Validaciones robustas de los archivos
        if not input_file or not input_file.filename:
            flash("No se seleccionó el archivo a firmar.", "error")
            return redirect(request.url)
        if not key_file or not key_file.filename:
            flash("No se seleccionó el archivo de clave privada.", "error")
            return redirect(request.url)

        try:
            input_bytes = input_file.read()
            private_key_bytes = key_file.read()
            passphrase_bytes = passphrase_form.encode() if passphrase_form else None

            # Usar la función centralizada de crypto_lib
            signature_bytes = sign_message(
                private_key_pem_bytes=private_key_bytes,
                message_bytes=input_bytes,
                passphrase=passphrase_bytes
            )

            # Preparar la firma para la descarga
            sig_stream = BytesIO(signature_bytes)
            original_filename_stem = Path(input_file.filename).stem
            signature_download_name = f"{original_filename_stem}.sig"

            flash(f"Archivo firmado con éxito. Descargando '{signature_download_name}'.", "success")
            return send_file(
                sig_stream,
                as_attachment=True,
                download_name=signature_download_name,
                mimetype="application/octet-stream"
            )

        except (ValueError, UnsupportedAlgorithm, TypeError) as e:
            # Errores comunes al cargar/usar la clave privada (PEM malformado, passphrase incorrecta, tipo de clave no soportado)
            flash(f"Error con la clave privada: {e}. Verifique la contraseña o el formato del archivo de clave.", "error")
        except Exception as e:
            # Otros errores inesperados durante el proceso de firma
            flash(f"Error inesperado al firmar el archivo: {e}", "error")

        return redirect(request.url) # Redirigir en caso de error para mostrar flash

    return render_template("sign.html")

# ── 3) Verificación de firma ───────────────────────────────────────────────────
@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        input_file = request.files.get("input_file") # Nombre genérico
        sig_file = request.files.get("sig")
        pub_key_file = request.files.get("pubkey")

        # Validaciones robustas
        if not input_file or not input_file.filename:
            flash("No se seleccionó el archivo original.", "error")
            return redirect(request.url)
        if not sig_file or not sig_file.filename:
            flash("No se seleccionó el archivo de firma (.sig).", "error")
            return redirect(request.url)
        if not pub_key_file or not pub_key_file.filename:
            flash("No se seleccionó el archivo de clave pública (.pem).", "error")
            return redirect(request.url)

        try:
            original_bytes = input_file.read()
            signature_bytes = sig_file.read()
            public_key_bytes = pub_key_file.read()

            # Usar la función centralizada de crypto_lib
            verify_message_signature(
                public_key_pem_bytes=public_key_bytes,
                message_bytes=original_bytes,
                signature_bytes=signature_bytes
            )
            flash("¡Verificación EXITOSA! La firma es válida para el archivo proporcionado.", "success")

        except InvalidSignature:
            flash("Verificación FALLIDA: La firma no es válida para el archivo y la clave pública proporcionados.", "error")
        except (ValueError, UnsupportedAlgorithm, TypeError) as e:
            # Errores comunes al cargar/usar la clave pública
            flash(f"Error con la clave pública: {e}. Verifique el formato del archivo de clave.", "error")
        except Exception as e:
            # Otros errores inesperados
            flash(f"Error inesperado durante la verificación: {e}", "error")

        return redirect(request.url) # Redirigir para mostrar el mensaje flash

    return render_template("verify.html")

# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Determinar si se está en un entorno de producción (ej. Heroku, Docker)
    # Esto es solo un ejemplo simple; podrías tener una lógica más robusta.
    is_production = os.environ.get("FLASK_ENV") == "production"

    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", 5000)),
        debug=not is_production # debug=True en desarrollo, False en producción
    )