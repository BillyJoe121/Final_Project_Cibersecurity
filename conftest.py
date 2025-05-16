import sys
import os

# Añade el directorio raíz del proyecto al sys.path
# Esto permite que los tests dentro de la carpeta 'tests'
# importen módulos desde 'src' como 'from src.crypto_lib import ...'
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
