import sqlite3
from pathlib import Path

BASE = Path(__file__).parent.resolve()
DB = BASE / "drive.db"
STORAGE = BASE / "storage"


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def used(uid):
    folder = STORAGE / str(uid)
    if not folder.exists():
        return 0
    return sum(f.stat().st_size for f in folder.rglob("*") if f.is_file())


if not DB.exists():
    raise SystemExit("drive.db belum ada. Jalankan server dan buat akun dulu.")

conn = sqlite3.connect(DB)
cols = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
created = "created_at" if "created_at" in cols else "NULL"
last = "last_login" if "last_login" in cols else "NULL"
rows = conn.execute(
    f"SELECT id, username, {created}, {last} FROM users ORDER BY id").fetchall()

if not rows:
    raise SystemExit("Belum ada pengguna terdaftar.")

print(f"{'ID':<4} {'Pengguna':<20} {'Dibuat':<20} {'Login terakhir':<20} {'Terpakai':>10}")
print("-" * 78)
for uid, name, c, l in rows:
    print(f"{uid:<4} {name:<20} {(c or '-'):<20} {(l or '-'):<20} {human(used(uid)):>10}")
print(f"\nTotal pengguna: {len(rows)}")