# 00 Introducción

**Final Project Cybersecurity** es una suite integral de herramientas para la seguridad informática, desarrollada en Python. Este proyecto centraliza en un único repositorio múltiples componentes diseñados para facilitar la implementación de mecanismos criptográficos en diversos entornos:

- Una **librería de alto nivel** que proporciona funciones para cifrado simétrico y asimétrico, generación y verificación de firmas digitales, funciones hash y manejo seguro de claves criptográficas.
- Una **interfaz de línea de comandos (CLI)** orientada a tareas rápidas y automatización, especialmente útil para administradores de sistemas y entornos técnicos.
- Una **aplicación web** con un panel de control intuitivo, dirigida a usuarios finales que requieren gestionar firmas y validaciones de forma gráfica.
- Una **API RESTful**, que permite integrar todas las funcionalidades anteriores en aplicaciones externas o flujos de integración y entrega continua (CI/CD).

El sistema está construido sobre la biblioteca [`cryptography`](https://cryptography.io/), y se apoya en tecnologías como **Flask**, **SQLAlchemy** y **Celery/Redis** para la gestión de procesos web, persistencia de datos y ejecución de tareas asíncronas, respectivamente.

El objetivo principal del proyecto es proporcionar una plataforma robusta, accesible y segura para la generación y verificación de firmas digitales aplicadas a documentos electrónicos.



