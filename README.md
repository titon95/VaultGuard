# 🔐 VaultGuard

> Gestor de contraseñas local, multi-usuario y de código abierto.  
> Diseñado para personas que se toman la seguridad en serio.

![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-blue)
![Python](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build](https://img.shields.io/github/actions/workflow/status/titon95/VaultGuard/build.yml?label=build)
![Security](https://img.shields.io/badge/cifrado-AES--256--GCM-purple)

---

## ✨ ¿Qué es VaultGuard?

VaultGuard es un gestor de contraseñas **100% local** — tus datos nunca salen de tu ordenador. Sin servidores, sin suscripciones, sin telemetría. Solo tú y tus contraseñas.

Construido con seguridad de nivel profesional: el mismo tipo de cifrado que usan los bancos, con doble autenticación y bloqueo automático.

---

## 🚀 Descarga

| Sistema | Descarga |
|---------|----------|
| 🐧 Linux | [VaultGuard-Linux](../../releases/latest) |
| 🪟 Windows | [VaultGuard-Windows.exe](../../releases/latest) |
| 🍎 macOS | [VaultGuard-Mac](../../releases/latest) |

> Los ejecutables se compilan automáticamente con GitHub Actions. No necesitas instalar Python ni nada más.

---

## 🔒 Seguridad

| Capa | Tecnología |
|------|------------|
| Cifrado de datos | AES-256-GCM |
| Derivación de clave | Argon2id (64MB, 3 iteraciones) |
| Autenticación | Contraseña maestra + TOTP 2FA |
| Secreto 2FA | Cifrado con tu propia clave |
| Portapapeles | Auto-limpieza a los 30 segundos |
| Inactividad | Bloqueo automático a los 5 minutos |
| Fuerza bruta | Bloqueo progresivo tras intentos fallidos |
| Red | Solo localhost — sin conexiones externas |

**Tus contraseñas nunca se almacenan en texto plano.** Cada campo de cada entrada está cifrado individualmente con AES-256-GCM antes de escribirse en disco.

---

## 🎯 Características

- **Multi-usuario** — varias cuentas en el mismo dispositivo, cada una con su bóveda completamente aislada
- **Login en 2 pasos** — primero verifica usuario y contraseña, luego pide el 2FA
- **Categorías** — organiza por Redes sociales, Finanzas, Trabajo, Email, Compras, Gaming
- **Generador de contraseñas** — con control de longitud, símbolos, mayúsculas y números
- **Generador de passphrases** — tipo `coral-storm-lunar-brave`, más fáciles de recordar
- **Indicador de fortaleza** — en tiempo real mientras escribes
- **Alertas de contraseñas débiles** — detecta entradas que necesitan actualizarse
- **Backup cifrado** — exporta tu bóveda con una contraseña separada
- **Gestión de cuenta** — cambia tu contraseña o elimina tu cuenta desde la propia app
- **Extensión para el navegador** — autocompletado en Chrome, Edge, Firefox y Brave

---

## 📸 Capturas

> *(Añade aquí capturas de pantalla de la app)*

---

## 🧩 Extensión del navegador

La extensión detecta la web en la que estás y te ofrece las credenciales guardadas para esa página.

**Chrome / Edge / Brave:**
1. Ve a `chrome://extensions`
2. Activa **Modo desarrollador**
3. Pulsa **Cargar descomprimida**
4. Selecciona la carpeta `extension/`

**Firefox:**
1. Ve a `about:debugging`
2. Cargar complemento temporal → `extension/manifest.json`

> La extensión se comunica con la app a través de `127.0.0.1:27416` — solo funciona en tu propio ordenador.

---

## 🛠️ Ejecutar desde el código fuente

```bash
# Requisitos del sistema (Linux)
sudo apt install python3 python3-venv python3-tk xclip -y

# Instalar dependencias
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Ejecutar
python3 vaultguard.py
```

---

## 📦 Compilar ejecutable tú mismo

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name VaultGuard vaultguard.py
# El ejecutable queda en: dist/VaultGuard
```

O simplemente haz un push al repositorio y GitHub Actions lo compila automáticamente para los 3 sistemas operativos.

---

## 📁 Estructura de datos

Los datos se guardan en `~/.vaultguard/`:

```
~/.vaultguard/
└── users/
    └── tu_usuario/
        ├── config.json   ← salt + secreto TOTP cifrado
        └── vault.db      ← contraseñas cifradas AES-256-GCM
```

Haz una copia de seguridad de esta carpeta regularmente.

---

## 📄 Licencia

MIT — libre para usar, modificar y distribuir.

---

<p align="center">
  Hecho con 🔐 por <a href="https://github.com/titon95">titon95</a>
</p>
