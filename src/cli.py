import argparse
from pathlib import Path
from crypto_lib import (
    generate_keys, load_private_key, load_public_key,
    sign_file, verify_file
)

def main():
    p = argparse.ArgumentParser(prog="signature_tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("keygen")
    gen.add_argument("--out-priv",  required=True)
    gen.add_argument("--out-pub",   required=True)
    gen.add_argument("--pass",      dest="pw", help="passphrase")

    sign = sub.add_parser("sign")
    sign.add_argument("--key",   required=True)
    sign.add_argument("--in",    dest="inp", required=True)
    sign.add_argument("--out",   dest="outp", required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("--key",   required=True)
    verify.add_argument("--in",    dest="inp", required=True)
    verify.add_argument("--sig",   required=True)

    args = p.parse_args()
    if args.cmd == "keygen":
        priv_pem, pub_pem = generate_keys(passphrase=(args.pw.encode() if args.pw else None))
        Path(args.out_priv).write_bytes(priv_pem)
        Path(args.out_pub).write_bytes(pub_pem)
        print("Claves RSA generadas.")
    elif args.cmd == "sign":
        priv = load_private_key(Path(args.key), passphrase=None)
        sign_file(priv, Path(args.inp), Path(args.outp))
        print(f"Archivo firmado: {args.outp}")
    else:  # verify
        pub = load_public_key(Path(args.key))
        try:
            verify_file(pub, Path(args.inp), Path(args.sig))
            print("¡Verificación OK!")
        except Exception as e:
            print("Falló la verificación:", e)

if __name__ == "__main__":
    main()
