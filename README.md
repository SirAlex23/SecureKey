# 🔑 SecureKey: Generador y Validador de Contraseñas Seguras

[![Python Badge](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Technologies Badge](https://img.shields.io/badge/Techs-Secrets%2FEntropy%2FJS-green?style=for-the-badge)](https://github.com/[tu-usuario]/SecureKey)
[![Repo Size](https://img.shields.io/github/repo-size/[tu-usuario]/SecureKey?style=for-the-badge)](https://github.com/[tu-usuario]/SecureKey)

## 🛡️ Propósito del Proyecto

**SecureKey** es una herramienta de ciberseguridad avanzada diseñada para generar y evaluar la fortaleza de contraseñas. Este proyecto destaca la implementación de la **Entropía de Shannon** para proporcionar una métrica de seguridad objetiva y profesional, midiendo la resistencia teórica a los ataques de fuerza bruta.

## 🚀 Características Clave

* **Generación Criptográficamente Segura:** Utiliza el módulo **`secrets`** de Python, asegurando una generación de contraseñas verdaderamente aleatoria e impredecible.
* **Cálculo de Entropía:** Implementa la fórmula de Shannon ($H = L \cdot \log_2(N)$) para calcular la fortaleza de la contraseña en **bits de seguridad**.
* **Métricas Detalladas:** Proporciona puntuaciones de fortaleza (Débil, Moderada, Fuerte) basadas en umbrales de bits (ej. > 80 bits para Fuerte).
* **Demo Web Interactiva:** Incluye una interfaz en HTML/CSS/JS para una demostración visual y en tiempo real de la validación.

## 🛠️ Tecnologías Utilizadas

* **Lenguaje:** Python 3.x
* **Librerías Clave (Python):**
    * `secrets`: Para generación de números aleatorios criptográficamente seguros.
    * `string`: Para definir los conjuntos de caracteres (keyspace).
    * `math`: Para el cálculo de la función logarítmica ($\log_2$) en la entropía.
* **Demo Web:** HTML, CSS y JavaScript (para simular la lógica de validación en el navegador).

## ⚙️ Instalación y Ejecución

Sigue estos pasos para utilizar el Generador/Validador en tu terminal (CLI).

### Requisitos

Necesitas tener **Python 3** instalado. Este proyecto utiliza únicamente librerías estándar.
