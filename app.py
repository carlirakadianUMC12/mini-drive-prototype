"""
Mini Drive (versi online) - backend API untuk akses dari banyak perangkat.

Jalankan:
    pip install -r requirements.txt
    python app.py                      # hanya komputer ini
    HOST=0.0.0.0 python app.py         # bisa diakses perangkat lain di jaringan yang sama
Variabel opsional: HOST, PORT, QUOTA_MB (default 1024), HTTPS=1 (jika sudah pakai HTTPS)
"""
import os
import re
import secrets
import shutil
import sqlite3
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, abort, g, jsonify, request, send_file, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE = Path(__file__).parent.resolve()
# Di Vercel hanya /tmp yang bisa ditulis, dan isinya bersifat sementara (mode demo).
DATA = Path("/tmp/minidrive") if os.environ.get("VERCEL") else BASE
DATA.mkdir(parents=True, exist_ok=True)
STORAGE = DATA / "storage"
DB = DATA / "drive.db"
QUOTA = int(os.environ.get("QUOTA_MB", "1024")) * 1024 * 1024
INVITE = os.environ.get("INVITE_CODE", "")  # jika diisi, pendaftar wajib memasukkan kode ini
STORAGE.mkdir(exist_ok=True)

app = Flask(__name__)
if os.environ.get("BEHIND_PROXY") == "1":  # aktifkan jika berjalan di belakang Nginx
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
key_file = DATA / ".secret_key"
if not os.environ.get("SECRET_KEY") and not key_file.exists():
    key_file.write_text(secrets.token_hex(32))
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or key_file.read_text(),
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)


# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


with sqlite3.connect(DB) as _c:
    _c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL)""")
    _cols = {r[1] for r in _c.execute("PRAGMA table_info(users)")}
    for _col in ("created_at", "last_login"):
        if _col not in _cols:
            _c.execute(f"ALTER TABLE users ADD COLUMN {_col} TEXT")


def now():
    return datetime.now().isoformat(sep=" ", timespec="seconds")


# ---------- helper ----------
def err(msg, code=400):
    return jsonify(error=msg), code


@app.errorhandler(403)
def e403(_): return err("Akses ditolak.", 403)
@app.errorhandler(404)
def e404(_): return err("Tidak ditemukan.", 404)
@app.errorhandler(413)
def e413(_): return err("Ukuran unggahan terlalu besar (maksimal 500 MB per permintaan).", 413)


@app.before_request
def csrf_guard():
    # Form lintas situs tidak bisa menambah header kustom, jadi POST tanpa header ini ditolak.
    if request.method == "POST" and request.headers.get("X-Requested-With") != "fetch":
        abort(403)


def login_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if "uid" not in session:
            return err("Silakan masuk dulu.", 401)
        return view(*a, **kw)
    return wrapper


def user_root():
    root = STORAGE / str(session["uid"])
    root.mkdir(exist_ok=True)
    return root.resolve()


def safe_path(rel):
    root = user_root()
    full = (root / (rel or "").strip("/")).resolve()
    if full != root and root not in full.parents:
        abort(403)
    return full


def clean(name):
    """Bersihkan nama file/folder, spasi dan huruf non-ASCII tetap boleh."""
    name = re.sub(r'[\x00-\x1f<>:"/\\|?*]', "", name or "").strip().lstrip(".")
    return name[:150]


def unique(folder, name):
    target, n = folder / name, 1
    stem, suffix = Path(name).stem, Path(name).suffix
    while target.exists():
        target = folder / f"{stem}({n}){suffix}"
        n += 1
    return target


def folder_size(p):
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file())


_attempts = {}


def too_many_attempts():
    ip, now = request.remote_addr, time.time()
    count, first = _attempts.get(ip, (0, now))
    if now - first > 600:
        count, first = 0, now
    _attempts[ip] = (count + 1, first)
    return count + 1 > 10


# ---------- akun ----------
@app.get("/")
def index():
    return send_file(BASE / "mini drive.html")


@app.get("/api/me")
def me():
    return jsonify(user=session.get("name"))


@app.post("/api/register")
def register():
    d = request.get_json(silent=True) or {}
    if INVITE and not secrets.compare_digest(str(d.get("invite") or ""), INVITE):
        return err("Kode undangan salah.", 403)
    name, pw = (d.get("username") or "").strip(), d.get("password") or ""
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", name):
        return err("Nama pengguna 3-30 karakter: huruf, angka, titik, strip, atau garis bawah.")
    if len(pw) < 6:
        return err("Kata sandi minimal 6 karakter.")
    try:
        db().execute("INSERT INTO users(username,password,created_at) VALUES(?,?,?)",
                     (name, generate_password_hash(pw), now()))
        db().commit()
    except sqlite3.IntegrityError:
        return err("Nama pengguna sudah dipakai.", 409)
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    if too_many_attempts():
        return err("Terlalu banyak percobaan. Coba lagi dalam 10 menit.", 429)
    d = request.get_json(silent=True) or {}
    row = db().execute("SELECT * FROM users WHERE username=?",
                       ((d.get("username") or "").strip(),)).fetchone()
    if not row or not check_password_hash(row["password"], d.get("password") or ""):
        return err("Nama pengguna atau kata sandi salah.", 401)
    _attempts.pop(request.remote_addr, None)
    db().execute("UPDATE users SET last_login=? WHERE id=?", (now(), row["id"]))
    db().commit()
    session.clear()
    session.permanent = True
    session["uid"], session["name"] = row["id"], row["username"]
    return jsonify(user=row["username"])


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


# ---------- file & folder ----------
@app.get("/api/list")
@login_required
def list_dir():
    folder = safe_path(request.args.get("path", ""))
    if not folder.is_dir():
        return err("Folder tidak ditemukan.", 404)
    root, items = user_root(), []
    for p in folder.iterdir():
        st = p.stat()
        items.append(dict(name=p.name, is_dir=p.is_dir(),
                          size=0 if p.is_dir() else st.st_size,
                          modified=int(st.st_mtime * 1000),
                          path=p.relative_to(root).as_posix()))
    items.sort(key=lambda i: (not i["is_dir"], i["name"].lower()))
    return jsonify(items=items, used=folder_size(root), quota=QUOTA)


@app.post("/api/upload")
@login_required
def upload():
    folder = safe_path(request.form.get("path", ""))
    if not folder.is_dir():
        return err("Folder tidak ditemukan.", 404)
    used, saved, skipped = folder_size(user_root()), 0, []
    for f in request.files.getlist("files"):
        name = clean(f.filename)
        if not name:
            continue
        target = unique(folder, name)
        f.save(target)
        size = target.stat().st_size
        if used + size > QUOTA:
            target.unlink()
            skipped.append(name)
            continue
        used += size
        saved += 1
    if skipped and not saved:
        return err("Kuota penyimpanan penuh.", 413)
    return jsonify(saved=saved, skipped=skipped)


@app.post("/api/mkdir")
@login_required
def mkdir():
    d = request.get_json(silent=True) or {}
    name = clean(d.get("name"))
    if not name:
        return err("Nama folder tidak valid.")
    target = safe_path(d.get("path", "")) / name
    if target.exists():
        return err(f'Nama "{name}" sudah dipakai di folder ini.', 409)
    target.mkdir()
    return jsonify(ok=True)


@app.post("/api/rename")
@login_required
def rename():
    d = request.get_json(silent=True) or {}
    src, name = safe_path(d.get("path", "")), clean(d.get("name"))
    if src == user_root() or not src.exists():
        return err("Item tidak ditemukan.", 404)
    if not name:
        return err("Nama tidak valid.")
    dst = src.with_name(name)
    if dst.exists() and dst != src:
        return err(f'Nama "{name}" sudah dipakai di folder ini.', 409)
    src.rename(dst)
    return jsonify(ok=True)


@app.post("/api/delete")
@login_required
def delete():
    target = safe_path((request.get_json(silent=True) or {}).get("path", ""))
    if target == user_root() or not target.exists():
        return err("Item tidak ditemukan.", 404)
    shutil.rmtree(target) if target.is_dir() else target.unlink()
    return jsonify(ok=True)


@app.get("/api/download")
@login_required
def download():
    f = safe_path(request.args.get("path", ""))
    if not f.is_file():
        return err("File tidak ditemukan.", 404)
    return send_file(f, as_attachment=True, download_name=f.name)


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", 5000)), debug=False)