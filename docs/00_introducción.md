# 00 Introducción

**Final Project Cybersecurity** es una suite integral de seguridad informática escrita en Python que reúne, en un único repositorio:

* Una **librería** de alto nivel para cifrado simétrico‑asimétrico, firmas digitales, hashing, generación de claves y verificación de las firmas generadas.
* Una **CLI** (Interfaz de Línea de Comandos) para tareas rápidas —ideal para administradores de sistemas.
* Una **aplicación Web** con panel de control para usuarios finales.

* Una **API RESTful** que permite integrar todas las capacidades anteriores en otras aplicaciones o _pipelines_ CI/CD.

El proyecto está construido sobre la potente biblioteca [`cryptography`], complementada con 
**Flask**, **SQLAlchemy** y **Celery/Redis** para tareas asíncronas.  
Su objetivo es facilitar la generación de firmas encriptadas para documentos y la verificación adecuada de dichas firmas.


