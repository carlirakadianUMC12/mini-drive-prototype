import secrets
import sqlite3
import sys
from pathlib import Path

from werkzeug.security import generate_password_hash

DB = Path(__file__).parent.resolve() / "drive.db"

if len(sys.argv) < 2:
    raise SystemExit("Pemakaian: python reset_password.py nama_pengguna [kata_sandi_baru]")
if not DB.exists():
    raise SystemExit("drive.db belum ada.")

username = sys.argv[1].strip()
alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
new_pw = sys.argv[2] if len(sys.argv) > 2 else "".join(secrets.choice(alphabet) for _ in range(10))

if len(new_pw) < 6:
    raise SystemExit("Kata sandi minimal 6 karakter.")

conn = sqlite3.connect(DB)
cur = conn.execute("UPDATE users SET password=? WHERE username=?",
                   (generate_password_hash(new_pw), username))
conn.commit()

if cur.rowcount == 0:
    raise SystemExit(f'Pengguna "{username}" tidak ditemukan. Cek ejaan dengan: python lihat_pengguna.py')

print(f'Kata sandi untuk "{username}" sudah diganti.')
print(f"Kata sandi baru: {new_pw}")
print("Kirim lewat pesan pribadi, lalu minta pengguna menyimpannya.")