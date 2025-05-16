# 02 Cómo usar la CLI

La interfaz de línea de comandos está implementada con `click` y se instala automáticamente junto con el paquete.

## 1. Cifrar y descifrar archivos

# Cifrar
cybersec encrypt --in secret.pdf --out secret.pdf.enc --algo AESGCM --key mykey.bin

# Descifrar
cybersec decrypt --in secret.pdf.enc --out secret.pdf --key mykey.bin

*Si no proporcionas `--key`, la CLI generará una nueva y la guardará en `~/.cybersec/keys/`.*


## 2. Firmas digitales


cybersec gen-key --type ed25519 --out alice
cybersec sign --file contract.pdf --priv alice.prv
cybersec verify --file contract.pdf --sig contract.pdf.sig --pub alice.pub



## 3. Gestor de contraseñas

La CLI incluye un gestor cifrado (similar a _pass_) basado en _envelope encryption_.

# Crear bóveda
cybersec pass-manager init

# Guardar contraseña
cybersec pass-manager add github
# → Se abrirá tu editor $EDITOR para introducir la contraseña

# Recuperar
cybersec pass-manager get github

