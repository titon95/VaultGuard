#!/usr/bin/env python3
"""
VaultGuard v4.0
Gestor de contraseñas multi-usuario · AES-256-GCM · Argon2id · TOTP 2FA
Auto-lock · Brute-force protection · Categorías · Backup cifrado
"""

import os, sys, json, base64, sqlite3, secrets, string, threading, time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import tkinter as tk
from tkinter import messagebox, filedialog
import customtkinter as ctk
import pyperclip, pyotp, qrcode
from PIL import Image
from io import BytesIO
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ═══════════════════════════════════════════════════════════════
#  CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════════
APP_DIR    = os.path.join(os.path.expanduser("~"), ".vaultguard")
USERS_DIR  = os.path.join(APP_DIR, "users")
PORT       = 27416
CLIP_TTL   = 30     # segundos hasta limpiar portapapeles
LOCK_AFTER = 300    # segundos de inactividad hasta bloqueo

# ═══════════════════════════════════════════════════════════════
#  PALETA — Diseño oscuro violeta premium
# ═══════════════════════════════════════════════════════════════
BG      = "#0c0c10"
SIDE1   = "#111118"   # sidebar categorías
SIDE2   = "#141419"   # sidebar entradas
CARD    = "#1a1a24"
CARD2   = "#22222e"
ACCENT  = "#7c3aed"
AHOVER  = "#6d28d9"
GREEN   = "#10b981"
GHOVER  = "#059669"
RED     = "#ef4444"
YELLOW  = "#f59e0b"
TEXT    = "#f1f5f9"
MUTED   = "#64748b"
BORDER  = "#2a2a38"

AVATAR_PALETTE = ["#7c3aed","#2563eb","#059669","#dc2626",
                  "#d97706","#0891b2","#be185d","#065f46"]

CATEGORIES = [
    ("all",      "🔐", "Todas"),
    ("social",   "📱", "Redes sociales"),
    ("finance",  "🏦", "Finanzas"),
    ("work",     "💼", "Trabajo"),
    ("email",    "📧", "Email"),
    ("shopping", "🛒", "Compras"),
    ("gaming",   "🎮", "Gaming"),
    ("other",    "📁", "Otros"),
]

WORDLIST = [
    "apple","bridge","cloud","dance","eagle","flame","ghost","honey",
    "ivory","jungle","knife","lemon","magic","night","ocean","piano",
    "queen","radio","storm","tiger","vapor","water","yacht","zebra",
    "amber","brave","coral","dream","ember","frost","grace","haven",
    "joker","karma","laser","maple","novel","orbit","pearl","river",
    "solar","torch","unity","viper","whale","youth","alpha","blaze",
    "crisp","delta","earth","forge","gleam","image","jewel","lunar",
    "marsh","oasis","prism","quest","ridge","swift","trend","valid",
    "woven","yield","chess","draco","fable","glyph","hydra","index",
    "pixel","qubit","rogue","shard","thorn","ultra","xenon","zoned",
]

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ═══════════════════════════════════════════════════════════════
#  CRIPTOGRAFÍA
# ═══════════════════════════════════════════════════════════════
def kdf(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"), salt=salt,
        time_cost=3, memory_cost=65536, parallelism=4,
        hash_len=32, type=Type.ID)

def encrypt(text: str, key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, (text or "").encode(), None)

def decrypt(blob, key: bytes) -> str:
    b = bytes(blob)
    return AESGCM(key).decrypt(b[:12], b[12:], None).decode()

def gen_password(length=20, upper=True, lower=True,
                 digits=True, symbols=True) -> str:
    pool = ""
    if upper:   pool += string.ascii_uppercase
    if lower:   pool += string.ascii_lowercase
    if digits:  pool += string.digits
    if symbols: pool += "!@#$%&*_+-=?<>"
    if not pool: pool = string.ascii_letters + string.digits
    while True:
        pw = "".join(secrets.choice(pool) for _ in range(length))
        # garantizar al menos un carácter de cada grupo seleccionado
        ok = True
        if upper   and not any(c.isupper() for c in pw): ok = False
        if lower   and not any(c.islower() for c in pw): ok = False
        if digits  and not any(c.isdigit() for c in pw): ok = False
        if symbols and not any(c in "!@#$%&*_+-=?<>" for c in pw): ok = False
        if ok: return pw

def gen_passphrase(words=4, sep="-") -> str:
    return sep.join(secrets.choice(WORDLIST) for _ in range(words))

def score_password(pw: str) -> tuple:
    pts = sum([
        len(pw) >= 8, len(pw) >= 14,
        any(c.isupper() for c in pw),
        any(c.islower() for c in pw),
        any(c.isdigit() for c in pw),
        any(c in string.punctuation for c in pw),
    ])
    pts = min(pts, 4)
    labels = ["Muy débil", "Débil", "Regular", "Fuerte", "Muy fuerte"]
    colors = [RED, RED, YELLOW, GREEN, GREEN]
    return pts, labels[pts], colors[pts]

# ═══════════════════════════════════════════════════════════════
#  PROTECCIÓN FUERZA BRUTA
# ═══════════════════════════════════════════════════════════════
_bf: dict = {}  # {username: [count, lockout_until]}

def bf_check(username: str) -> tuple:
    if username not in _bf: return False, 0
    count, until = _bf[username]
    if time.time() < until: return True, int(until - time.time())
    return False, 0

def bf_fail(username: str) -> int:
    count = _bf.get(username, [0, 0])[0] + 1
    delays = [0, 0, 5, 15, 30, 60, 120, 300]
    delay  = delays[min(count, len(delays) - 1)]
    _bf[username] = [count, time.time() + delay]
    return count

def bf_reset(username: str):
    _bf.pop(username, None)

# ═══════════════════════════════════════════════════════════════
#  AUTENTICACIÓN MULTI-USUARIO
# ═══════════════════════════════════════════════════════════════
class Auth:
    @staticmethod
    def user_dir(u):  return os.path.join(USERS_DIR, u.strip().lower())
    @staticmethod
    def cfg_path(u):  return os.path.join(Auth.user_dir(u), "config.json")
    @staticmethod
    def vault_path(u):return os.path.join(Auth.user_dir(u), "vault.db")

    @staticmethod
    def list_users():
        if not os.path.exists(USERS_DIR): return []
        return sorted([d for d in os.listdir(USERS_DIR)
                       if os.path.isdir(os.path.join(USERS_DIR, d))
                       and os.path.exists(os.path.join(USERS_DIR, d, "config.json"))])

    @staticmethod
    def exists(u): return os.path.exists(Auth.cfg_path(u))

    @staticmethod
    def create(username: str, password: str):
        salt   = secrets.token_bytes(32)
        key    = kdf(password, salt)
        secret = pyotp.random_base32()
        uri    = pyotp.TOTP(secret).provisioning_uri(username, issuer_name="VaultGuard")
        enc_s  = encrypt(secret, key)
        os.makedirs(Auth.user_dir(username), exist_ok=True)
        json.dump({
            "salt":    base64.b64encode(salt).decode(),
            "totp":    base64.b64encode(enc_s).decode(),
            "created": time.strftime("%Y-%m-%d"),
        }, open(Auth.cfg_path(username), "w"))
        return key, secret, uri

    @staticmethod
    def unlock(username: str, password: str, totp_code: str):
        if not Auth.exists(username): return None
        try:
            cfg    = json.load(open(Auth.cfg_path(username)))
            salt   = base64.b64decode(cfg["salt"])
            key    = kdf(password, salt)
            secret = decrypt(base64.b64decode(cfg["totp"]), key)
            if not pyotp.TOTP(secret).verify(totp_code.strip(), valid_window=1):
                return None
            return key
        except Exception:
            return None

# ═══════════════════════════════════════════════════════════════
#  BASE DE DATOS CIFRADA
# ═══════════════════════════════════════════════════════════════
class Vault:
    def __init__(self, username: str, key: bytes):
        self.key  = key
        self.path = Auth.vault_path(username)
        now = time.strftime("%d/%m/%Y %H:%M")
        with sqlite3.connect(self.path) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name BLOB, url BLOB, username BLOB,
                password BLOB, notes BLOB, category BLOB,
                created TEXT, updated TEXT)""")
            db.commit()
            # Migración automática
            cols = [r[1] for r in db.execute("PRAGMA table_info(entries)").fetchall()]
            for col in ["category", "created", "updated"]:
                if col not in cols:
                    db.execute(f"ALTER TABLE entries ADD COLUMN {col} TEXT DEFAULT ''")
            db.commit()

    def _e(self, s): return encrypt(s or "", self.key)
    def _d(self, b): return decrypt(b, self.key) if b else ""

    def _parse(self, r) -> dict:
        return {"id": r[0], "name": self._d(r[1]), "url": self._d(r[2]),
                "username": self._d(r[3]), "password": self._d(r[4]),
                "notes": self._d(r[5]),
                "category": self._d(r[6]) if r[6] else "other",
                "created": r[7] or "", "updated": r[8] or ""}

    def add(self, name, url, username, password, notes, category):
        now = time.strftime("%d/%m/%Y %H:%M")
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO entries VALUES (NULL,?,?,?,?,?,?,?,?)",
                (self._e(name), self._e(url), self._e(username),
                 self._e(password), self._e(notes), self._e(category), now, now))
            db.commit()

    def update(self, eid, name, url, username, password, notes, category):
        now = time.strftime("%d/%m/%Y %H:%M")
        with sqlite3.connect(self.path) as db:
            db.execute("""UPDATE entries SET name=?,url=?,username=?,
                          password=?,notes=?,category=?,updated=? WHERE id=?""",
                (self._e(name), self._e(url), self._e(username),
                 self._e(password), self._e(notes), self._e(category), now, eid))
            db.commit()

    def delete(self, eid):
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM entries WHERE id=?", (eid,))
            db.commit()

    def all_entries(self) -> list:
        with sqlite3.connect(self.path) as db:
            rows = db.execute(
                "SELECT id,name,url,username,password,notes,category,created,updated FROM entries"
            ).fetchall()
        result = []
        for r in rows:
            try: result.append(self._parse(r))
            except Exception: pass
        return result

    def search(self, q: str = "", category: str = "all") -> list:
        entries = self.all_entries()
        if category != "all":
            entries = [e for e in entries if e["category"] == category]
        if q:
            ql = q.lower()
            entries = [e for e in entries
                       if ql in e["name"].lower()
                       or ql in (e["url"] or "").lower()
                       or ql in e["username"].lower()]
        return sorted(entries, key=lambda e: e["name"].lower())

    def by_url(self, url: str) -> list:
        try: dom = urlparse(url).netloc.lower().replace("www.", "")
        except: dom = ""
        return [e for e in self.all_entries() if dom and dom in (e["url"] or "").lower()]

    def count(self) -> int:
        with sqlite3.connect(self.path) as db:
            return db.execute("SELECT COUNT(*) FROM entries").fetchone()[0]

    def count_by_category(self) -> dict:
        counts = {"all": 0}
        for e in self.all_entries():
            counts["all"] += 1
            cat = e.get("category", "other") or "other"
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    def weak_count(self) -> int:
        return sum(1 for e in self.all_entries() if score_password(e["password"])[0] < 2)

    def export_backup(self, path: str, backup_pw: str):
        """Exporta la bóveda cifrada con una contraseña separada."""
        salt = secrets.token_bytes(32)
        key  = kdf(backup_pw, salt)
        data = json.dumps(self.all_entries())
        enc  = encrypt(data, key)
        with open(path, "wb") as f:
            f.write(b"VGBK" + salt + enc)

# ═══════════════════════════════════════════════════════════════
#  SERVIDOR LOCAL — extensión navegador
# ═══════════════════════════════════════════════════════════════
_vault: Vault | None = None

class _Hdl(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_OPTIONS(self): self.send_response(200); self._cors(); self.end_headers()
    def do_GET(self):
        if not _vault: return self._r(403, {"error": "locked"})
        p = urlparse(self.path); qs = parse_qs(p.query)
        if p.path == "/ping":
            self._r(200, {"ok": True, "count": _vault.count()})
        elif p.path == "/credentials":
            m = _vault.by_url(qs.get("url", [""])[0])
            self._r(200, [{"id":e["id"],"name":e["name"],
                           "username":e["username"],"url":e["url"]} for e in m])
        elif p.path == "/get_password":
            eid = int(qs.get("id",[0])[0])
            e = next((x for x in _vault.all_entries() if x["id"]==eid), None)
            self._r(200 if e else 404,
                    {"username":e["username"],"password":e["password"]} if e else {})
        else: self._r(404, {})
    def _r(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code); self._cors()
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",len(body)); self.end_headers()
        self.wfile.write(body)
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,OPTIONS")

def start_server():
    try:
        s = HTTPServer(("127.0.0.1", PORT), _Hdl)
        threading.Thread(target=s.serve_forever, daemon=True).start()
    except: pass

# ═══════════════════════════════════════════════════════════════
#  UI HELPERS
# ═══════════════════════════════════════════════════════════════
def fr(parent, bg=BG, radius=0, **kw):
    return ctk.CTkFrame(parent, fg_color=bg, corner_radius=radius, **kw)

def lbl(parent, text, size=13, bold=False, color=TEXT, anchor="w", **kw):
    return ctk.CTkLabel(parent, text=text, anchor=anchor,
                        font=("Ubuntu", size, "bold" if bold else "normal"),
                        text_color=color, **kw)

def btn(parent, text, cmd, width=120, fg=ACCENT, hover=AHOVER, **kw):
    return ctk.CTkButton(parent, text=text, command=cmd, width=width, height=36,
                         fg_color=fg, hover_color=hover, corner_radius=8,
                         font=("Ubuntu", 12), **kw)

def inp(parent, ph="", show=None, width=None):
    return ctk.CTkEntry(parent, placeholder_text=ph, show=show,
                        width=width or 380, height=38, fg_color=CARD2,
                        border_color=BORDER, text_color=TEXT,
                        placeholder_text_color=MUTED, corner_radius=8,
                        border_width=1, font=("Ubuntu", 13))

def sep(parent):
    fr(parent, bg=BORDER, radius=0, height=1).pack(fill="x")

def avatar(parent, name: str, size=42):
    color = AVATAR_PALETTE[abs(hash(name)) % len(AVATAR_PALETTE)]
    f = fr(parent, bg=color, radius=size//2, width=size, height=size)
    f.pack_propagate(False)
    lbl(f, (name[0].upper() if name else "?"),
        size//3+4, bold=True, anchor="center"
        ).place(relx=.5, rely=.5, anchor="center")
    return f

# ═══════════════════════════════════════════════════════════════
#  PANTALLA: LOGIN  (2 pasos: credenciales → 2FA)
# ═══════════════════════════════════════════════════════════════
class LoginScreen(ctk.CTkFrame):
    def __init__(self, parent, on_login, on_create):
        super().__init__(parent, fg_color=BG, corner_radius=0)
        self.on_login      = on_login
        self.on_create     = on_create
        self._bf_job       = None
        self._pending_key  = None
        self._pending_user = None
        self._pending_cfg  = None
        self._build_step1()

    # PASO 1: usuario + contraseña
    def _build_step1(self):
        for w in self.winfo_children(): w.destroy()
        outer = fr(self)
        outer.place(relx=.5, rely=.5, anchor="center")

        logo_f = fr(outer, bg=ACCENT, radius=20, width=72, height=72)
        logo_f.pack()
        logo_f.pack_propagate(False)
        lbl(logo_f, "🔐", 32, anchor="center").place(relx=.5, rely=.5, anchor="center")
        lbl(outer, "VaultGuard", 26, bold=True, anchor="center").pack(pady=(14,2))

        # Tabs Entrar / Registrarse
        tabs = fr(outer, bg=CARD2, radius=10)
        tabs.pack(pady=(12,0))
        ctk.CTkButton(tabs, text="Entrar", width=160, height=34,
                      fg_color=ACCENT, hover_color=AHOVER,
                      corner_radius=8, font=("Ubuntu",12,"bold"),
                      command=lambda: None).pack(side="left", padx=4, pady=4)
        ctk.CTkButton(tabs, text="Registrarse", width=160, height=34,
                      fg_color="transparent", hover_color=CARD,
                      corner_radius=8, font=("Ubuntu",12),
                      command=self.on_create, text_color=MUTED).pack(side="left", padx=4, pady=4)

        box = fr(outer, bg=CARD, radius=14)
        box.pack(pady=14, ipadx=4, ipady=4)
        inner = fr(box, bg=CARD)
        inner.pack(padx=28, pady=24)

        users = Auth.list_users()
        if users:
            lbl(inner, "Cuentas en este dispositivo", 10, color=MUTED).pack(anchor="w", pady=(0,6))
            chips = fr(inner, bg=CARD)
            chips.pack(fill="x", pady=(0,10))
            for u in users:
                def pick(name=u):
                    self._user.delete(0,"end")
                    self._user.insert(0, name)
                    self._pw.focus_set()
                ctk.CTkButton(chips, text=f"👤 {u}", command=pick,
                              height=28, corner_radius=14, fg_color=CARD2,
                              hover_color=BORDER, font=("Ubuntu",11),
                              text_color=TEXT, width=max(70, len(u)*9)
                              ).pack(side="left", padx=3)

        lbl(inner, "Usuario", 11, color=MUTED).pack(anchor="w")
        self._user = inp(inner, "Nombre de usuario", width=344)
        self._user.pack(fill="x", pady=(3,0))

        lbl(inner, "Contraseña", 11, color=MUTED).pack(anchor="w", pady=(12,0))
        self._pw = inp(inner, "Tu contraseña maestra", show="●", width=344)
        self._pw.pack(fill="x", pady=(3,0))

        btn(inner, "Continuar  →", self._verify_step1, width=344).pack(fill="x", pady=(18,0))

        self._err = lbl(inner, "", 11, color=RED, anchor="center")
        self._err.pack(pady=(8,0))

        self._user.focus_set()
        self.after(100, lambda: self.winfo_toplevel().bind("<Return>", lambda _: self._verify_step1()))

    def _verify_step1(self):
        username = self._user.get().strip().lower()
        pw       = self._pw.get()
        if not username or not pw:
            self._err.configure(text="Rellena usuario y contraseña"); return
        locked, wait = bf_check(username)
        if locked:
            self._show_countdown(wait); return
        if not Auth.exists(username):
            self._err.configure(text="✗  Usuario no encontrado"); return
        self._err.configure(text="Verificando…"); self.update()
        try:
            cfg  = json.load(open(Auth.cfg_path(username)))
            salt = base64.b64decode(cfg["salt"])
            key  = kdf(pw, salt)
            decrypt(base64.b64decode(cfg["totp"]), key)  # valida contraseña
            self._pending_key  = key
            self._pending_user = username
            self._pending_cfg  = cfg
            self._build_step2()
        except Exception:
            count = bf_fail(username)
            _, wait = bf_check(username)
            if wait > 0: self._show_countdown(wait)
            else: self._err.configure(text=f"✗  Contraseña incorrecta  ({count} intentos)")

    # PASO 2: código 2FA
    def _build_step2(self):
        for w in self.winfo_children(): w.destroy()
        outer = fr(self)
        outer.place(relx=.5, rely=.5, anchor="center")

        av = avatar(outer, self._pending_user, 56)
        av.pack()
        lbl(outer, self._pending_user, 18, bold=True, anchor="center").pack(pady=(8,2))
        lbl(outer, "Introduce el código de tu autenticador",
            12, color=MUTED, anchor="center").pack(pady=(0,16))

        box = fr(outer, bg=CARD, radius=14)
        box.pack(ipadx=4, ipady=4)
        inner = fr(box, bg=CARD)
        inner.pack(padx=28, pady=24)

        lbl(inner, "Código 2FA", 11, color=MUTED).pack(anchor="w")
        self._totp = inp(inner, "6 dígitos del autenticador", width=280)
        self._totp.pack(pady=(3,0))
        self._totp.focus_set()

        btn(inner, "Verificar  →", self._verify_step2, width=280).pack(fill="x", pady=(16,0))

        self._err2 = lbl(inner, "", 11, color=RED, anchor="center")
        self._err2.pack(pady=(8,0))

        btn(outer, "← Cambiar usuario", self._build_step1,
            width=200, fg="transparent", hover=CARD2).pack(pady=10)

        self.after(100, lambda: self.winfo_toplevel().bind("<Return>", lambda _: self._verify_step2()))

    def _verify_step2(self):
        totp = self._totp.get().strip()
        if not totp:
            self._err2.configure(text="Introduce el código"); return
        self._err2.configure(text="Verificando…"); self.update()
        try:
            secret = decrypt(base64.b64decode(self._pending_cfg["totp"]), self._pending_key)
            if pyotp.TOTP(secret).verify(totp, valid_window=1):
                bf_reset(self._pending_user)
                self.on_login(self._pending_user, self._pending_key)
            else:
                count = bf_fail(self._pending_user)
                self._err2.configure(text=f"✗  Código incorrecto  ({count} intentos)")
                self._totp.delete(0,"end"); self._totp.focus_set()
        except Exception:
            self._err2.configure(text="✗  Error de verificación")

    def _show_countdown(self, seconds: int):
        if self._bf_job: self.after_cancel(self._bf_job)
        if seconds <= 0:
            self._err.configure(text="Puedes intentarlo de nuevo"); return
        self._err.configure(text=f"⏳  Demasiados intentos — espera {seconds}s")
        self._bf_job = self.after(1000, lambda: self._show_countdown(seconds-1))
# ═══════════════════════════════════════════════════════════════
#  PANTALLA: CREAR USUARIO
# ═══════════════════════════════════════════════════════════════
class CreateUserScreen(ctk.CTkFrame):
    def __init__(self, parent, on_done, on_back):
        super().__init__(parent, fg_color=BG, corner_radius=0)
        self.on_done = on_done
        self.on_back = on_back
        self._key    = None
        self._step   = 1   # 1=form, 2=QR
        self._build_form()

    def _build_form(self):
        for w in self.winfo_children(): w.destroy()
        outer = fr(self)
        outer.place(relx=.5, rely=.5, anchor="center")

        lbl(outer, "➕  Crear nueva cuenta", 22, bold=True, anchor="center").pack()
        lbl(outer, "Esta cuenta solo existe en este ordenador",
            12, color=MUTED, anchor="center").pack(pady=(4, 20))

        box = fr(outer, bg=CARD, radius=14)
        box.pack(ipadx=20, ipady=20)
        inner = fr(box, bg=CARD)
        inner.pack(padx=28, pady=28)

        lbl(inner, "Nombre de usuario", 11, color=MUTED).pack(anchor="w")
        self._u = inp(inner, "ej: titon", width=380)
        self._u.pack(fill="x", pady=(3, 0))
        self._u.focus_set()

        lbl(inner, "Contraseña maestra", 11, color=MUTED).pack(anchor="w", pady=(12,0))
        self._p1 = inp(inner, "Mínimo 8 caracteres", show="●", width=380)
        self._p1.pack(fill="x", pady=(3, 0))
        self._p1.bind("<KeyRelease>", self._check)

        lbl(inner, "Confirmar contraseña", 11, color=MUTED).pack(anchor="w", pady=(12,0))
        self._p2 = inp(inner, "Repite la contraseña", show="●", width=380)
        self._p2.pack(fill="x", pady=(3, 0))
        self._p2.bind("<KeyRelease>", self._check)

        self._match = lbl(inner, "", 11, color=MUTED, anchor="center")
        self._match.pack(pady=(6,0))

        self._go = btn(inner, "Continuar  →", self._create, width=380)
        self._go.pack(fill="x", pady=(16, 0))

        self._err = lbl(inner, "", 11, color=RED, anchor="center")
        self._err.pack(pady=(6, 0))

        link = fr(outer, bg=BG)
        link.pack(pady=12)
        lbl(link, "¿Ya tienes cuenta?", 12, color=MUTED).pack(side="left", padx=(0,6))
        btn(link, "Volver al login", self.on_back,
            width=140, fg="transparent", hover=CARD2).pack(side="left")

    def _check(self, *_):
        p1, p2 = self._p1.get(), self._p2.get()
        if not p2:    self._match.configure(text="")
        elif p1 == p2: self._match.configure(text="✓ Coinciden",   text_color=GREEN)
        else:          self._match.configure(text="✗ No coinciden", text_color=RED)

    def _create(self):
        u  = self._u.get().strip().lower()
        p1 = self._p1.get()
        p2 = self._p2.get()

        if not u:
            self._err.configure(text="Introduce un nombre de usuario"); return
        if not u.isalnum():
            self._err.configure(text="Solo letras y números en el nombre"); return
        if Auth.exists(u):
            self._err.configure(text=f"El usuario '{u}' ya existe"); return
        if len(p1) < 8:
            self._err.configure(text="La contraseña debe tener al menos 8 caracteres"); return
        if p1 != p2:
            self._err.configure(text="Las contraseñas no coinciden"); return

        self._go.configure(state="disabled", text="Generando clave…")
        self.update()
        self._key, secret, uri = Auth.create(u, p1)
        self._username = u
        self._build_qr(secret, uri)

    def _build_qr(self, secret, uri):
        for w in self.winfo_children(): w.destroy()
        outer = fr(self)
        outer.place(relx=.5, rely=.5, anchor="center")

        lbl(outer, "📱  Configura el autenticador", 22, bold=True, anchor="center").pack()
        lbl(outer, "Escanea el QR con Google Authenticator o Authy",
            12, color=MUTED, anchor="center").pack(pady=(4, 16))

        # QR
        img  = qrcode.make(uri)
        buf  = BytesIO(); img.save(buf, "PNG"); buf.seek(0)
        pil  = Image.open(buf).resize((190, 190))
        self._qr = ctk.CTkImage(pil, size=(190, 190))
        qr_lbl = ctk.CTkLabel(outer, image=self._qr, text="")
        qr_lbl.pack()

        box = fr(outer, bg=CARD, radius=12)
        box.pack(fill="x", pady=12, ipadx=16, ipady=12)
        lbl(box, "Clave manual (guárdala en papel seguro):",
            11, color=MUTED, anchor="center").pack()
        lbl(box, secret, 13, bold=True, color=ACCENT, anchor="center").pack()

        btn(outer, "✅  Ya escaneé el QR — Entrar", self._confirm,
            width=320, fg=GREEN, hover=GHOVER).pack(pady=8)

    def _confirm(self):
        self.on_done(self._username, self._key)

# ═══════════════════════════════════════════════════════════════
#  PANEL PRINCIPAL DE LA BÓVEDA
# ═══════════════════════════════════════════════════════════════
class VaultPanel(ctk.CTkFrame):
    def __init__(self, parent, vault: Vault, username: str, on_lock):
        super().__init__(parent, fg_color=BG, corner_radius=0)
        self.vault      = vault
        self.username   = username
        self.on_lock    = on_lock
        self._sel       = None
        self._cat       = "all"
        self._clip_tmr  = None
        self._editing   = None
        self._build()
        self.refresh()
        root = self.winfo_toplevel()
        root.bind("<Control-n>", lambda _: self._open_form())
        root.bind("<Control-f>", lambda _: self._search.focus_set())
        root.bind("<Escape>",    lambda _: self._cancel_form())

    # ── Layout 3 columnas ────────────────────────────────────────────────────
    def _build(self):
        # Col 1: Categorías (180px)
        self._c1 = ctk.CTkFrame(self, width=190, fg_color=SIDE1, corner_radius=0)
        self._c1.pack(side="left", fill="y")
        self._c1.pack_propagate(False)
        self._build_cat_col()

        # Col 2: Entradas (260px)
        self._c2 = ctk.CTkFrame(self, width=268, fg_color=SIDE2, corner_radius=0)
        self._c2.pack(side="left", fill="y")
        self._c2.pack_propagate(False)
        self._build_entry_col()

        # Col 3: Detalle
        self._c3 = fr(self)
        self._c3.pack(side="right", fill="both", expand=True)
        self._show_welcome()

    # ── Columna 1: Categorías ────────────────────────────────────────────────
    def _build_cat_col(self):
        # Logo + usuario
        top = fr(self._c1, bg=SIDE1)
        top.pack(fill="x", padx=12, pady=(18, 10))

        av = avatar(top, self.username, 38)
        av.pack()
        lbl(top, self.username, 13, bold=True, anchor="center").pack(pady=(6,0))

        self._weak_lbl = lbl(top, "", 10, color=YELLOW, anchor="center")
        self._weak_lbl.pack()

        sep(self._c1)

        # Lista de categorías
        self._cat_btns = {}
        self._cat_frame = fr(self._c1, bg=SIDE1)
        self._cat_frame.pack(fill="both", expand=True, pady=8)
        self._build_cat_buttons()

        sep(self._c1)

        # Botones inferiores
        btm = fr(self._c1, bg=SIDE1)
        btm.pack(fill="x", padx=10, pady=10)
        btn(btm, "📦  Exportar", self._export,
            width=168, fg=CARD2, hover=CARD).pack(fill="x", pady=3)
        btn(btm, "⚙️  Mi cuenta", self._show_account,
            width=168, fg=CARD2, hover=CARD).pack(fill="x", pady=3)
        btn(btm, "🔒  Bloquear", self.on_lock,
            width=168, fg=CARD2, hover=RED).pack(fill="x", pady=3)

    def _build_cat_buttons(self):
        for w in self._cat_frame.winfo_children(): w.destroy()
        counts = self.vault.count_by_category()
        for key, icon, name in CATEGORIES:
            count = counts.get(key, 0)
            is_sel = (key == self._cat)
            row_bg = CARD if is_sel else "transparent"
            row = fr(self._cat_frame, bg=row_bg, radius=8)
            row.pack(fill="x", padx=8, pady=2)

            lbl(row, icon, 15, anchor="center", width=28).pack(side="left", padx=(8,4), pady=8)
            lbl(row, name, 12, bold=is_sel).pack(side="left", fill="x", expand=True)
            if count > 0:
                lbl(row, str(count), 10, color=MUTED).pack(side="right", padx=8)

            def click(k=key):
                self._cat = k
                self._build_cat_buttons()
                self.refresh()
            for w in self._walk(row):
                w.bind("<Button-1>", lambda e, c=click: c())
                w.configure(cursor="hand2")

    # ── Columna 2: Lista de entradas ─────────────────────────────────────────
    def _build_entry_col(self):
        # Cabecera
        top = fr(self._c2, bg=SIDE2)
        top.pack(fill="x", padx=10, pady=(14, 6))

        self._search = ctk.CTkEntry(
            self._c2, placeholder_text="🔍  Buscar  (Ctrl+F)",
            height=34, fg_color=CARD, border_color=BORDER,
            text_color=TEXT, placeholder_text_color=MUTED,
            corner_radius=8, border_width=1, font=("Ubuntu",12))
        self._search.pack(fill="x", padx=10, pady=(0,6))
        self._search.bind("<KeyRelease>", lambda _: self.refresh())

        btn(self._c2, "＋  Nueva  (Ctrl+N)",
            self._open_form, width=248, fg=ACCENT).pack(fill="x", padx=10, pady=(0,6))

        sep(self._c2)

        # Lista
        self._list = ctk.CTkScrollableFrame(
            self._c2, fg_color="transparent",
            scrollbar_button_color=CARD2)
        self._list.pack(fill="both", expand=True, padx=4, pady=4)

        self._count_lbl = lbl(self._c2, "", 10, color=MUTED, anchor="center")
        self._count_lbl.pack(pady=4)

    # ── Refresh lista ────────────────────────────────────────────────────────
    def refresh(self):
        for w in self._list.winfo_children(): w.destroy()
        q       = self._search.get().strip()
        entries = self.vault.search(q, self._cat)
        n       = len(entries)
        self._count_lbl.configure(text=f"{n} entrada{'s' if n!=1 else ''}")

        # Alerta contraseñas débiles
        weak = self.vault.weak_count()
        self._weak_lbl.configure(
            text=f"⚠️  {weak} contraseña{'s débiles' if weak!=1 else ' débil'}"
            if weak else "")

        for e in entries:
            self._make_row(e)

    def _make_row(self, entry):
        is_sel = self._sel and self._sel["id"] == entry["id"]
        row_bg = CARD if is_sel else "transparent"
        row = fr(self._list, bg=row_bg, radius=8)
        row.pack(fill="x", pady=2, padx=4)

        av = avatar(row, entry["name"], 34)
        av.pack(side="left", padx=(6,10), pady=8)

        info = fr(row, bg="transparent")
        info.pack(side="left", fill="x", expand=True)
        lbl(info, entry["name"][:22], 13, bold=True).pack(anchor="w")
        url_s = (entry["url"] or "").replace("https://","").replace("http://","")[:24]
        lbl(info, url_s or "Sin URL", 10, color=MUTED).pack(anchor="w")

        # Indicador fortaleza
        pts = score_password(entry["password"])[0]
        dot_color = [RED,RED,YELLOW,GREEN,GREEN][pts]
        fr(row, bg=dot_color, radius=4, width=6, height=6).pack(side="right", padx=10)

        def click(en=entry):
            self._sel = en
            self.refresh()
            self._show_entry(en)
        for w in self._walk(row):
            w.bind("<Button-1>", lambda e, c=click: c())
            w.configure(cursor="hand2")

    # ── Columna 3: Bienvenida ────────────────────────────────────────────────
    def _show_welcome(self):
        for w in self._c3.winfo_children(): w.destroy()
        c = fr(self._c3)
        c.place(relx=.5, rely=.5, anchor="center")
        lbl(c, "🔐", 52, anchor="center").pack()
        lbl(c, "Bóveda desbloqueada", 18, bold=True, anchor="center").pack(pady=8)
        lbl(c, f"Hola, {self.username}  ·  Ctrl+N para crear una entrada",
            12, color=MUTED, anchor="center").pack()

    # ── Columna 3: Detalle de entrada ─────────────────────────────────────────
    def _show_entry(self, entry: dict):
        for w in self._c3.winfo_children(): w.destroy()

        # Header
        hdr = fr(self._c3, bg=SIDE1, radius=0, height=86)
        hdr.pack(fill="x"); hdr.pack_propagate(False)

        av = avatar(hdr, entry["name"], 50)
        av.pack(side="left", padx=20, pady=16)

        inf = fr(hdr, bg=SIDE1)
        inf.pack(side="left", fill="y", pady=20)
        lbl(inf, entry["name"], 18, bold=True).pack(anchor="w")
        cat_label = next((c[2] for c in CATEGORIES if c[0]==entry.get("category","other")), "Otros")
        lbl(inf, f"{cat_label}  ·  {entry['updated']}", 10, color=MUTED).pack(anchor="w")

        acts = fr(hdr, bg=SIDE1)
        acts.pack(side="right", padx=16)
        btn(acts, "✏️  Editar",
            lambda: self._open_form(entry), width=106, fg=CARD2, hover=CARD).pack(side="left", padx=3)
        btn(acts, "🗑️  Eliminar",
            self._delete, width=106, fg=RED, hover="#c13030").pack(side="left", padx=3)

        # Cuerpo
        body = ctk.CTkScrollableFrame(self._c3, fg_color=BG,
                                       scrollbar_button_color=CARD2)
        body.pack(fill="both", expand=True, padx=20, pady=14)

        def field_card(icon, label, value, secret=False, mono=False):
            if not value: return
            card = fr(body, bg=CARD, radius=10, height=72)
            card.pack(fill="x", pady=5)
            card.pack_propagate(False)

            icon_box = fr(card, bg=CARD2, radius=10, width=44, height=44)
            icon_box.pack(side="left", padx=12, pady=14)
            icon_box.pack_propagate(False)
            lbl(icon_box, icon, 18, anchor="center").place(relx=.5,rely=.5,anchor="center")

            mid = fr(card, bg=CARD)
            mid.pack(side="left", fill="both", expand=True, pady=14)
            lbl(mid, label, 10, color=MUTED).pack(anchor="w")
            dv = tk.StringVar(value="●●●●●●●●" if secret else value)
            ctk.CTkLabel(mid, textvariable=dv, text_color=TEXT,
                         font=("Courier New" if (secret or mono) else "Ubuntu", 13),
                         anchor="w").pack(anchor="w", fill="x")

            rbx = fr(card, bg=CARD)
            rbx.pack(side="right", fill="y", padx=8)

            if secret:
                vis = [False]
                def toggle(d=dv, v=value, s=vis):
                    s[0]=not s[0]; d.set(v if s[0] else "●●●●●●●●")
                ctk.CTkButton(rbx, text="👁", width=34, height=34, command=toggle,
                              fg_color=CARD2, hover_color=BORDER, corner_radius=8,
                              text_color=MUTED).pack(pady=(16,2))

            def copy_it(v=value, lname=label):
                pyperclip.copy(v)
                self._toast(f"✓  {lname} copiado")
                self._arm_clip()
            ctk.CTkButton(rbx, text="📋", width=34, height=34, command=copy_it,
                          fg_color=CARD2, hover_color=BORDER, corner_radius=8,
                          text_color=MUTED).pack(pady=(16,2))

        field_card("🌐", "URL",         entry["url"] or "—")
        field_card("👤", "Usuario",     entry["username"])
        field_card("🔑", "Contraseña",  entry["password"], secret=True, mono=True)
        if entry.get("notes"):
            field_card("📝", "Notas",   entry["notes"])

        # Fortaleza
        pts, label, color = score_password(entry["password"])
        str_row = fr(body, bg=BG)
        str_row.pack(fill="x", pady=(4,0))
        lbl(str_row, f"Fortaleza: ", 11, color=MUTED).pack(side="left")
        lbl(str_row, label, 11, color=color, bold=True).pack(side="left")

        # Toast
        self._toast_var = tk.StringVar()
        ctk.CTkLabel(self._c3, textvariable=self._toast_var,
                     text_color=GREEN, font=("Ubuntu",12)).pack(pady=4)

    # ── Columna 3: Formulario nueva/editar entrada ────────────────────────────
    def _open_form(self, entry=None):
        for w in self._c3.winfo_children(): w.destroy()
        self._editing = entry

        hdr = fr(self._c3, bg=SIDE1, radius=0, height=66)
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        title = "✏️  Editar entrada" if entry else "➕  Nueva entrada"
        lbl(hdr, title, 16, bold=True).pack(side="left", padx=22, pady=18)
        lbl(hdr, "Esc para cancelar", 10, color=MUTED).pack(side="right", padx=18)

        body = ctk.CTkScrollableFrame(self._c3, fg_color=BG,
                                       scrollbar_button_color=CARD2)
        body.pack(fill="both", expand=True, padx=26, pady=12)

        def fld(label, ph="", show=None):
            lbl(body, label, 11, color=MUTED).pack(anchor="w", pady=(10,2))
            e = inp(body, ph, show=show)
            e.pack(fill="x")
            return e

        self._fn  = fld("Nombre  *",         "YouTube, Gmail, banco…")
        self._fu  = fld("URL",                "youtube.com")
        self._fus = fld("Usuario / Email  *", "usuario@email.com")
        self._fp  = fld("Contraseña  *",      "Tu contraseña…", show="●")
        self._fp.bind("<KeyRelease>", self._upd_str)

        # Barra fortaleza
        self._sbar = ctk.CTkProgressBar(body, height=5, corner_radius=3)
        self._sbar.pack(fill="x", pady=(4,0))
        self._sbar.set(0); self._sbar.configure(progress_color=MUTED)
        self._slbl = lbl(body, "", 10, color=MUTED)
        self._slbl.pack(anchor="w")

        # Generador
        gen = fr(body, bg=CARD, radius=10)
        gen.pack(fill="x", pady=10)
        lbl(gen, "⚡  Generador", 12, bold=True).pack(anchor="w", padx=14, pady=(10,4))

        g1 = fr(gen, bg=CARD)
        g1.pack(fill="x", padx=14, pady=(0,4))
        lbl(g1,"Long:",10,color=MUTED).pack(side="left",padx=(0,4))
        self._glen = ctk.CTkEntry(g1, width=46, height=28, fg_color=CARD2,
                                   border_color=BORDER, text_color=TEXT, corner_radius=6)
        self._glen.insert(0,"20"); self._glen.pack(side="left", padx=4)
        self._sym  = tk.BooleanVar(value=True)
        self._upr  = tk.BooleanVar(value=True)
        self._dig  = tk.BooleanVar(value=True)
        for text, var in [("Símbolos",self._sym),("Mayús",self._upr),("Núm",self._dig)]:
            ctk.CTkCheckBox(g1, text=text, variable=var, text_color=TEXT,
                            fg_color=ACCENT, hover_color=AHOVER,
                            width=20).pack(side="left", padx=4)
        btn(g1, "Generar", self._gen_pw, width=80, fg=CARD2, hover=BORDER).pack(side="left",padx=4)

        g2 = fr(gen, bg=CARD)
        g2.pack(fill="x", padx=14, pady=(0,10))
        lbl(g2,"Passphrase:",10,color=MUTED).pack(side="left",padx=(0,4))
        self._pwords = ctk.CTkEntry(g2, width=36, height=26, fg_color=CARD2,
                                     border_color=BORDER, text_color=TEXT, corner_radius=6)
        self._pwords.insert(0,"4"); self._pwords.pack(side="left", padx=4)
        self._psep = ctk.CTkEntry(g2, width=36, height=26, fg_color=CARD2,
                                   border_color=BORDER, text_color=TEXT, corner_radius=6)
        self._psep.insert(0,"-"); self._psep.pack(side="left", padx=4)
        btn(g2, "Frase", self._gen_phrase, width=70, fg=CARD2, hover=BORDER).pack(side="left",padx=4)

        # Categoría
        lbl(body, "Categoría", 11, color=MUTED).pack(anchor="w", pady=(10,2))
        self._cat_var = tk.StringVar(value=entry["category"] if entry else "other")
        cat_row = fr(body, bg=BG)
        cat_row.pack(fill="x")
        for key, icon, name in CATEGORIES[1:]:  # skip "all"
            def sel(k=key):
                self._cat_var.set(k)
                self._refresh_cat_btns(cat_row)
            is_s = (key == self._cat_var.get())
            ctk.CTkButton(cat_row, text=f"{icon} {name[:6]}",
                          command=sel, width=88, height=30,
                          fg_color=ACCENT if is_s else CARD2,
                          hover_color=AHOVER if is_s else CARD,
                          corner_radius=6, font=("Ubuntu",10),
                          text_color=TEXT).pack(side="left", padx=2, pady=2)

        self._fno = fld("Notas (opcional)", "Información adicional…")

        if entry:
            for f, k in [(self._fn,"name"),(self._fu,"url"),(self._fus,"username"),
                         (self._fp,"password"),(self._fno,"notes")]:
                f.insert(0, entry.get(k,""))
            self._upd_str()

        brow = fr(body, bg=BG)
        brow.pack(fill="x", pady=16)
        btn(brow, "💾  Guardar", self._save,
            width=160, fg=GREEN, hover=GHOVER).pack(side="left", padx=(0,10))
        btn(brow, "Cancelar", self._cancel_form,
            width=110, fg=CARD2, hover=CARD).pack(side="left")

        self._fn.focus_set()

    def _refresh_cat_btns(self, row):
        for w in row.winfo_children(): w.destroy()
        for key, icon, name in CATEGORIES[1:]:
            is_s = (key == self._cat_var.get())
            def sel(k=key):
                self._cat_var.set(k)
                self._refresh_cat_btns(row)
            ctk.CTkButton(row, text=f"{icon} {name[:6]}", command=sel,
                          width=88, height=30,
                          fg_color=ACCENT if is_s else CARD2,
                          hover_color=AHOVER if is_s else CARD,
                          corner_radius=6, font=("Ubuntu",10),
                          text_color=TEXT).pack(side="left", padx=2, pady=2)

    def _upd_str(self, *_):
        pw = self._fp.get()
        if not pw: self._sbar.set(0); self._slbl.configure(text=""); return
        pts, txt, col = score_password(pw)
        self._sbar.set(pts/4); self._sbar.configure(progress_color=col)
        self._slbl.configure(text=txt, text_color=col)

    def _gen_pw(self):
        try: l = max(8, min(64, int(self._glen.get())))
        except: l = 20
        pw = gen_password(l, self._upr.get(), True, self._dig.get(), self._sym.get())
        self._fp.delete(0,"end"); self._fp.insert(0,pw); self._upd_str()

    def _gen_phrase(self):
        try: w = max(2, min(8, int(self._pwords.get())))
        except: w = 4
        s = self._psep.get() or "-"
        pw = gen_passphrase(w, s)
        self._fp.delete(0,"end"); self._fp.insert(0,pw); self._upd_str()

    def _save(self):
        name = self._fn.get().strip()
        user = self._fus.get().strip()
        pw   = self._fp.get()
        if not name or not user or not pw:
            messagebox.showwarning("Obligatorios",
                "Nombre, usuario y contraseña son obligatorios."); return
        cat = self._cat_var.get()
        url = self._fu.get().strip()
        notes = self._fno.get().strip()
        if self._editing:
            self.vault.update(self._editing["id"], name, url, user, pw, notes, cat)
        else:
            self.vault.add(name, url, user, pw, notes, cat)
        self._build_cat_buttons()
        self.refresh()
        saved = next((e for e in self.vault.all_entries()
                      if e["name"]==name and e["username"]==user), None)
        if saved: self._sel = saved; self.refresh(); self._show_entry(saved)
        else: self._show_welcome()

    def _cancel_form(self):
        if self._sel: self._show_entry(self._sel)
        else: self._show_welcome()

    def _delete(self):
        if not self._sel: return
        if messagebox.askyesno("Eliminar",
            f"¿Eliminar «{self._sel['name']}»?\nEsta acción no se puede deshacer."):
            self.vault.delete(self._sel["id"])
            self._sel = None
            self._build_cat_buttons()
            self.refresh()
            self._show_welcome()

    def _show_account(self):
        """Panel de gestión de cuenta en columna 3."""
        for w in self._c3.winfo_children(): w.destroy()

        hdr = fr(self._c3, bg=SIDE1, radius=0, height=86)
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        av = avatar(hdr, self.username, 50)
        av.pack(side="left", padx=20, pady=16)
        inf = fr(hdr, bg=SIDE1)
        inf.pack(side="left", fill="y", pady=22)
        lbl(inf, self.username, 18, bold=True).pack(anchor="w")
        lbl(inf, "Gestión de cuenta", 11, color=MUTED).pack(anchor="w")

        body = fr(self._c3)
        body.pack(fill="both", expand=True, padx=28, pady=20)

        # Cambiar contraseña
        pw_card = fr(body, bg=CARD, radius=10)
        pw_card.pack(fill="x", pady=6)
        lbl(pw_card, "🔑  Cambiar contraseña maestra", 13, bold=True
            ).pack(anchor="w", padx=16, pady=(14,4))

        lbl(pw_card, "Contraseña actual", 11, color=MUTED).pack(anchor="w", padx=16)
        self._pw_old = inp(pw_card, "Tu contraseña actual", show="●")
        self._pw_old.pack(padx=16, pady=(3,4), fill="x")

        lbl(pw_card, "Nueva contraseña", 11, color=MUTED).pack(anchor="w", padx=16)
        self._pw_new1 = inp(pw_card, "Nueva contraseña (mín. 8 caracteres)", show="●")
        self._pw_new1.pack(padx=16, pady=(3,4), fill="x")

        lbl(pw_card, "Confirmar nueva", 11, color=MUTED).pack(anchor="w", padx=16)
        self._pw_new2 = inp(pw_card, "Repite la nueva contraseña", show="●")
        self._pw_new2.pack(padx=16, pady=(3,4), fill="x")

        self._pw_msg = lbl(pw_card, "", 11, color=GREEN, anchor="center")
        self._pw_msg.pack(pady=4)

        btn(pw_card, "Cambiar contraseña", self._change_password,
            width=220, fg=ACCENT, hover=AHOVER).pack(pady=(0,14))

        # Zona peligrosa
        del_card = fr(body, bg=CARD, radius=10)
        del_card.pack(fill="x", pady=6)
        lbl(del_card, "🗑️  Eliminar cuenta", 13, bold=True, color=RED
            ).pack(anchor="w", padx=16, pady=(14,4))
        lbl(del_card, "Se borrarán todas tus contraseñas. Esta acción es irreversible.",
            11, color=MUTED).pack(anchor="w", padx=16)
        btn(del_card, "Eliminar mi cuenta", self._delete_account,
            width=200, fg=RED, hover="#c13030").pack(pady=14)

    def _change_password(self):
        old_pw  = self._pw_old.get()
        new_pw1 = self._pw_new1.get()
        new_pw2 = self._pw_new2.get()

        if not old_pw or not new_pw1 or not new_pw2:
            self._pw_msg.configure(text="Rellena todos los campos", text_color=RED); return
        if len(new_pw1) < 8:
            self._pw_msg.configure(text="Mínimo 8 caracteres", text_color=RED); return
        if new_pw1 != new_pw2:
            self._pw_msg.configure(text="Las contraseñas no coinciden", text_color=RED); return

        # Verificar contraseña actual
        try:
            cfg  = json.load(open(Auth.cfg_path(self.username)))
            salt = base64.b64decode(cfg["salt"])
            old_key = kdf(old_pw, salt)
            old_secret = decrypt(base64.b64decode(cfg["totp"]), old_key)
        except Exception:
            self._pw_msg.configure(text="✗  Contraseña actual incorrecta", text_color=RED); return

        # Re-cifrar todo con nueva clave
        self._pw_msg.configure(text="Recifrando bóveda…", text_color=MUTED); self.update()
        new_salt = secrets.token_bytes(32)
        new_key  = kdf(new_pw1, new_salt)
        enc_totp = encrypt(old_secret, new_key)

        # Reescribir config
        json.dump({
            "salt":    base64.b64encode(new_salt).decode(),
            "totp":    base64.b64encode(enc_totp).decode(),
            "created": cfg.get("created",""),
        }, open(Auth.cfg_path(self.username), "w"))

        # Re-cifrar cada entrada de la bóveda
        entries = self.vault.all_entries()
        old_vault = Vault.__new__(Vault)
        old_vault.key  = old_key
        old_vault.path = self.vault.path
        self.vault.key = new_key
        for e in entries:
            self.vault.update(e["id"], e["name"], e["url"], e["username"],
                              e["password"], e["notes"], e["category"])

        self._pw_msg.configure(text="✅  Contraseña cambiada correctamente", text_color=GREEN)
        self._pw_old.delete(0,"end"); self._pw_new1.delete(0,"end"); self._pw_new2.delete(0,"end")

    def _delete_account(self):
        msg = f"¿Eliminar la cuenta «{self.username}» y TODAS sus contraseñas?\n\nEsta acción no se puede deshacer."
        if not messagebox.askyesno("Eliminar cuenta", msg, icon="warning"): return
        import shutil
        shutil.rmtree(Auth.user_dir(self.username), ignore_errors=True)
        self.on_lock()

    def _export(self):
        pw = tk.simpledialog.askstring(
            "Exportar bóveda cifrada",
            "Contraseña para cifrar el backup:\n(puede ser diferente a tu contraseña maestra)",
            show="*", parent=self.winfo_toplevel())
        if not pw: return
        path = filedialog.asksaveasfilename(
            defaultextension=".vgbk",
            filetypes=[("VaultGuard Backup","*.vgbk")],
            initialfile=f"vaultguard_backup_{self.username}.vgbk")
        if not path: return
        try:
            self.vault.export_backup(path, pw)
            messagebox.showinfo("Exportado", f"Backup guardado en:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo exportar:\n{e}")

    # ── Utilidades ────────────────────────────────────────────────────────────
    def _toast(self, msg: str):
        try:
            self._toast_var.set(msg)
            self.after(2800, lambda: self._toast_var.set(""))
        except Exception: pass

    def _arm_clip(self):
        if self._clip_tmr: self._clip_tmr.cancel()
        self._clip_tmr = threading.Timer(CLIP_TTL, lambda: pyperclip.copy(""))
        self._clip_tmr.daemon = True; self._clip_tmr.start()

    def _walk(self, w):
        yield w
        for c in w.winfo_children(): yield from self._walk(c)

# ═══════════════════════════════════════════════════════════════
#  APP PRINCIPAL — gestiona pantallas y auto-lock
# ═══════════════════════════════════════════════════════════════
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("VaultGuard")
        self.geometry("1080x680"); self.minsize(860, 540)
        self.configure(fg_color=BG)
        self._screen    = None
        self._lock_tmr  = None
        self._vault     = None
        start_server()
        self._show_login()
        # Auto-lock: reset con cualquier actividad
        self.bind("<Motion>",   self._activity)
        self.bind("<KeyPress>", self._activity)

    def _show(self, screen):
        if self._screen: self._screen.destroy()
        self._screen = screen
        self._screen.pack(fill="both", expand=True)

    def _show_login(self):
        global _vault
        _vault = None; self._vault = None
        self._cancel_lock_timer()
        self._show(LoginScreen(self,
            on_login=self._on_login,
            on_create=self._show_create))

    def _show_create(self):
        self._show(CreateUserScreen(self,
            on_done=self._on_create_done,
            on_back=self._show_login))

    def _on_create_done(self, username, key):
        # Después de crear usuario, entrar directamente
        self._on_login(username, key)

    def _on_login(self, username: str, key: bytes):
        global _vault
        vault = Vault(username, key)
        _vault = vault; self._vault = vault
        self._show(VaultPanel(self, vault, username, on_lock=self._show_login))
        self.title(f"VaultGuard  ·  {username}")
        self._arm_lock_timer()

    def _arm_lock_timer(self):
        self._cancel_lock_timer()
        self._lock_tmr = threading.Timer(LOCK_AFTER, lambda: self.after(0, self._show_login))
        self._lock_tmr.daemon = True; self._lock_tmr.start()

    def _cancel_lock_timer(self):
        if self._lock_tmr: self._lock_tmr.cancel(); self._lock_tmr = None

    def _activity(self, *_):
        if self._vault: self._arm_lock_timer()


if __name__ == "__main__":
    import tkinter.simpledialog
    App().mainloop()
