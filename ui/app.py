import os, sys
from io import BytesIO
from zipfile import ZipFile
from pathlib import Path

# ── poner la raíz del proyecto en el PYTHONPATH ────────────────────────────────
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import (
    Flask, render_template, request, send_file,
    flash, redirect, url_for
)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from src.crypto_lib import (
    generate_keys,
    load_private_key,
    load_public_key
)

app = Flask(__name__)
app.secret_key = "cámbiala_por_una_más_segura"        # ← pon algo robusto

# ───────────────────────────── rutas ──────────────────────────────────────────
@app.route("/")
def index():
    return render_template("base.html")

# ── 1) generar claves ─────────────────────────────────────────────────────────
@app.route("/keygen", methods=["GET", "POST"])
def keygen():
    if request.method == "POST":
        name_priv = request.form["priv_name"] or "private.pem"
        name_pub  = request.form["pub_name"]  or "public.pem"
        pw        = request.form.get("passphrase") or None

        priv_pem, pub_pem = generate_keys(
            passphrase=(pw.encode() if pw else None)
        )

        buf = BytesIO()
        with ZipFile(buf, "w") as zf:
            zf.writestr(name_priv, priv_pem)
            zf.writestr(name_pub,  pub_pem)
        buf.seek(0)

        return send_file(
            buf,
            as_attachment=True,
            download_name="keys.zip",
            mimetype="application/zip"
        )

    return render_template("keygen.html")

# ── 2) firmar PDF ─────────────────────────────────────────────────────────────
@app.route("/sign", methods=["GET", "POST"])
def sign():
    if request.method == "POST":
        pdf_file  = request.files.get("pdf")
        key_file  = request.files.get("privkey")
        pw        = request.form.get("passphrase") or None

        if not (pdf_file and key_file):
            flash("PDF y clave privada son obligatorios.", "error")
            return redirect(request.url)

        try:
            # leer datos en memoria
            pdf_bytes = pdf_file.read()
            key_bytes = key_file.read()

            priv = serialization.load_pem_private_key(
                key_bytes,
                password=(pw.encode() if pw else None)
            )
            signature = priv.sign(
                pdf_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            flash(f"Error al firmar: {e}", "error")
            return redirect(request.url)

        sig_stream = BytesIO(signature)
        sig_stream.seek(0)
        sig_name = f"{Path(pdf_file.filename).stem}.sig"

        return send_file(
            sig_stream,
            as_attachment=True,
            download_name=sig_name,
            mimetype="application/octet-stream"
        )

    return render_template("sign.html")

# ── 3) verificar firma ────────────────────────────────────────────────────────
@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        pdf_file = request.files.get("pdf")
        sig_file = request.files.get("sig")
        pub_file = request.files.get("pubkey")

        if not (pdf_file and sig_file and pub_file):
            flash("PDF, firma y clave pública son obligatorios.", "error")
            return redirect(request.url)

        try:
            pdf_bytes = pdf_file.read()
            sig_bytes = sig_file.read()
            pub_bytes = pub_file.read()

            pub = serialization.load_pem_public_key(pub_bytes)
            pub.verify(
                sig_bytes,
                pdf_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            flash("¡Verificación OK!", "success")
        except Exception as e:
            flash(f"Verificación fallida: {e}", "error")

        return redirect(request.url)

    return render_template("verify.html")

# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)
