import argparse
from pathlib import Path
from crypto_lib import (
    generate_keys,
    load_private_key,
    load_public_key,
    sign_file,
    verify_file
)

def main():
    parser = argparse.ArgumentParser(prog="signature_tool")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    # 1) Generación de par de claves
    gen = subparsers.add_parser("keygen", help="Genera un par de claves RSA")
    gen.add_argument(
        "--out-priv", required=True,
        help="Ruta donde se guardará la clave privada (PEM)"
    )
    gen.add_argument(
        "--out-pub", required=True,
        help="Ruta donde se guardará la clave pública (PEM)"
    )
    gen.add_argument(
        "--pass", dest="pw", metavar="PASSPHRASE",
        help="Frase de paso para cifrar la clave privada"
    )

    # 2) Firmar archivo
    sign = subparsers.add_parser("sign", help="Firma un archivo con clave privada")
    sign.add_argument(
        "--key", required=True,
        help="Ruta al archivo PEM de la clave privada"
    )
    sign.add_argument(
        "--in", dest="inp", required=True,
        help="Archivo a firmar"
    )
    sign.add_argument(
        "--out", dest="outp", required=True,
        help="Ruta donde se guardará la firma (.sig)"
    )
    sign.add_argument(
        "--pass", dest="pw", metavar="PASSPHRASE",
        help="Frase de paso de la clave privada, si está cifrada"
    )

    # 3) Verificación de firma
    verify = subparsers.add_parser("verify", help="Verifica la firma de un archivo")
    verify.add_argument(
        "--key", required=True,
        help="Ruta al archivo PEM de la clave pública"
    )
    verify.add_argument(
        "--in", dest="inp", required=True,
        help="Archivo original"
    )
    verify.add_argument(
        "--sig", required=True,
        help="Archivo de firma (.sig) generado"
    )

    args = parser.parse_args()

    if args.cmd == "keygen":
        priv_pem, pub_pem = generate_keys(
            passphrase=(args.pw.encode() if args.pw else None)
        )
        Path(args.out_priv).write_bytes(priv_pem)
        Path(args.out_pub).write_bytes(pub_pem)
        print("Claves RSA generadas.")

    elif args.cmd == "sign":
        priv = load_private_key(
            Path(args.key),
            passphrase=(args.pw.encode() if args.pw else None)
        )
        sign_file(priv, Path(args.inp), Path(args.outp))
        print(f"Archivo firmado: {args.outp}")

    elif args.cmd == "verify":
        pub = load_public_key(Path(args.key))
        try:
            verify_file(pub, Path(args.inp), Path(args.sig))
            print("¡Verificación OK!")
        except Exception as e:
            print("Falló la verificación:", e)

if __name__ == "__main__":
    main()
