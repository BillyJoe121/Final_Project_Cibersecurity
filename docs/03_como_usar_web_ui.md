# 03 Cómo usar la Web UI

La interfaz web proporciona toda la funcionalidad de la CLI pero con una experiencia gráfica 


## 1. Puesta en marcha

python ui/app.py


Navega a **http://localhost:5000**.  


## 2. Estructura de la UI

1. **Generar Claves** – en este apartado podremos generar las claves publica y privada para firmar nuestros archivos, una vez dados los nombres a los archivos e ingresado una key el sistema descargará automáticamente ambos archivos en un .zip.  
2. **Firmar un Archivo** – Nos permite seleccionar un archivo de cualquier tipo de nuestro computador, nuestra clave privada y generar un archivo .sig con la firma.  
3. **Verificar Firma** – En este apartado podemos cargar nuestro archivo original, nuestra clave publica y validar que la firma es correcta.  


