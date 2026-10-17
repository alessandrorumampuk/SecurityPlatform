#!/usr/bin/env python3
"""
VulnLab -- deliberately vulnerable web app for testing VVM.

WARNING: this application is INTENTIONALLY INSECURE. Every vulnerability
below exists on purpose so VVM (and manual testing practice) has a local,
safe target. Never expose it to a network. Run on 127.0.0.1 only.

    cd testing
    python3 app.py            # http://127.0.0.1:8765

Vulnerabilities built in:
    1. Reflected + Stored XSS     /search?q= , /comment
    2. SQL Injection              /product?id=
    3. IDOR                       /profile?id=
    4. Broken Access Control      /admin , /admin/users.json
    5. OTP without rate limit     /otp , /api/verify-otp?code=
    6. Broken Link Hijacking      footer social link -> dead/expired target
    7. Information Disclosure     /.env , /.git/HEAD , /.git/config
    8. CSRF                       /comment (no token/origin check)
"""

import random
import sqlite3

from flask import Flask, jsonify, redirect, request

app = Flask(__name__)
app.secret_key = "vulnlab"  # hardcoded weak secret (intentional)

# ---------------------------------------------------------------- sqlite ---
# In-memory DB seeded at startup. Shared connection is fine for a lab.
con = sqlite3.connect(":memory:", check_same_thread=False)
con.executescript("""
CREATE TABLE users (id INTEGER, username TEXT, password TEXT,
                    email TEXT, nik TEXT, balance INTEGER);
CREATE TABLE products (id INTEGER, name TEXT, price INTEGER, stock INTEGER);
CREATE TABLE comments (id INTEGER PRIMARY KEY, author TEXT, body TEXT);
INSERT INTO users VALUES
 (1,'budi','s3cr3t!','budi@mail.id','3171000000000001', 15250000),
 (2,'sari','pass123','sari@mail.id','3171000000000002',  8400000),
 (3,'admin','Admin#2024','admin@vulnlab.local','3171000000000003',99900000);
INSERT INTO products VALUES
 (1,'Kaos VVM',150000,42),(2,'Sticker Pack',25000,300),(3,'Hoodie',350000,7);
INSERT INTO comments VALUES (1,'admin','Selamat datang di VulnLab.');
""")

OTP_CURRENT = f"{random.randint(0, 9999):04d}"  # regenerated per restart

BASE = """<!doctype html><html><head><meta charset="utf-8">
<title>VulnLab</title><style>
body{font-family:system-ui;max-width:860px;margin:2em auto;padding:0 1em;color:#222}
nav a{margin-right:14px} input,textarea{padding:.5em;margin:.3em 0;width:90%}
table{border-collapse:collapse}td,th{border:1px solid #bbb;padding:.4em .8em}
.warn{background:#ffe9e9;border:1px solid #e44;padding:.6em 1em;border-radius:6px}
</style></head><body>
<nav><a href="/">Home</a><a href="/search">Search</a><a href="/profile?id=1">
Profile</a><a href="/login">Login</a></nav><hr>
{{ body }}<hr>
<footer><small>
Follow us:
<a href="https://twitter.com/vulnlab_id" target="_blank">Twitter</a> ·
<a href="https://www.instagram.com/vulnlab.id" target="_blank">Instagram</a> ·
<a href="https://www.tiktok.com/@vulnlab" target="_blank">TikTok</a> ·
<a href="https://t.me/vulnlab" target="_blank">Telegram</a> ·
<a href="https://twitter.com/vulnlab_official_lama2022" target="_blank">Twitter (lama)</a> ·
<a href="https://promo-vulnlab-2023-nonexistent-domain-987654.com" target="_blank">
Portal Promo 2023</a>
</small></footer></body></html>"""


def page(body):
    return BASE.replace("{{ body }}", body)


# ------------------------------------------------------------- home page ---
@app.route("/")
def home():
    cur = con.execute("SELECT author, body FROM comments")
    comments = "".join(f"<p><b>{a}:</b> {b}</p>" for a, b in cur.fetchall())
    return page(f"""
<h1>VulnLab — Situs Uji Rentan</h1>
<div class="warn">Lab lokal. Sengaja rentan. Jangan pernah deploy.</div>

<h2>Cari</h2>
<form action="/search" method="get">
  <input name="q" placeholder="Cari berita atau produk...">
  <button>Cari</button>
</form>

<h2>Produk</h2>
<ul>
  <li><a href="/product?id=1">Kaos VVM</a></li>
  <li><a href="/product?id=2">Sticker Pack</a></li>
  <li><a href="/product?id=3">Hoodie</a></li>
</ul>

<h2>Pengumuman Internal</h2>
<iframe src="/admin/notice" width="500" height="80"></iframe>

<h2>Komentar</h2>
{comments}
<form action="/comment" method="post">
  <input type="hidden" name="role" value="guest">
  <input name="author" placeholder="Nama"><br>
  <textarea name="body" placeholder="Tulis komentar..."></textarea><br>
  <button>Kirim</button>
</form>""")


# ------------------------------------------------ 1. XSS (reflected+stored)
@app.route("/search")
def search():
    q = request.args.get("q", "")
    return page(f"<h2>Hasil pencarian untuk: {q}</h2>"
                "<p>Tidak ada hasil. Coba kata kunci lain.</p>")
    # VULN: q is rendered unsanitized -> /search?q=<script>alert(1)</script>


@app.route("/comment", methods=["POST"])
def comment():
    # VULN: stored unsanitized + hidden 'role' field trusted blindly
    con.execute("INSERT INTO comments (author, body) VALUES (?, ?)",
                (request.form.get("author", "anon"),
                 request.form.get("body", "")))
    con.commit()
    return redirect("/")


# ------------------------------------------------------------ 2. SQLi ------
@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    try:
        # VULN: f-string concatenation -> id=-1 UNION SELECT ...
        rows = con.execute(
            f"SELECT id,name,price,stock FROM products WHERE id = {pid}"
        ).fetchall()
    except Exception as e:
        return page(f"<h2>Error</h2><p class='warn'>DB error: {e}</p>"), 500
    rows_html = "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td>"
                        f"<td>{r[2]}</td><td>{r[3]}</td></tr>" for r in rows)
    return page("<h2>Detail Produk</h2><table><tr><th>ID</th><th>Nama</th>"
                f"<th>Harga</th><th>Stok</th></tr>{rows_html}</table>")


# -------------------------------------------------------------- 3. IDOR ----
@app.route("/profile")
def profile():
    uid = request.args.get("id", "1")
    # Query itself is parameterized, BUT there is no session/ownership
    # check at all -> any id leaks another user's PII. Classic IDOR.
    row = con.execute(
        "SELECT id,username,email,nik,balance FROM users WHERE id=?",
        (uid,)).fetchone()
    if not row:
        return page("<h2>Profil</h2><p>User tidak ditemukan.</p>")
    return page(f"""<h2>Profil #{row[0]}</h2><table>
<tr><th>Username</th><td>{row[1]}</td></tr>
<tr><th>Email</th><td>{row[2]}</td></tr>
<tr><th>NIK</th><td>{row[3]}</td></tr>
<tr><th>Saldo</th><td>Rp {row[4]:,}</td></tr></table>""")


# ------------------------------------------- 4. Broken Access Control ------
@app.route("/admin")
def admin():
    # VULN: no login check whatsoever -- anyone can open the dashboard
    rows = con.execute("SELECT id,username,email,balance FROM users").fetchall()
    tr = "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td>"
                 f"<td>Rp {r[3]:,}</td></tr>" for r in rows)
    return page(f"""<h2>ADMIN — Internal Dashboard</h2>
<div class="warn">INTERNAL ONLY — halaman ini tidak memeriksa login.</div>
<table><tr><th>ID</th><th>User</th><th>Email</th><th>Saldo</th></tr>
{tr}</table>
<p><a href="/admin/users.json">Export JSON (passwords included)</a></p>""")


@app.route("/admin/users.json")
def admin_users():
    rows = con.execute("SELECT id,username,password,email,nik FROM users")
    return jsonify([dict(id=r[0], username=r[1], password=r[2],
                         email=r[3], nik=r[4]) for r in rows])


@app.route("/admin/notice")
def admin_notice():
    return "<p style='font-family:system-ui'>[internal] rapat security review Jumat 15:00 — <i>rahasia</i></p>"


# ------------------------------------------------- 5. OTP without limit ----
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # 'credentials accepted' -> OTP sent. For the lab the code is
        # shown in the server log only (see console output).
        print(f"[OTP] code for {request.form.get('user')} = {OTP_CURRENT}")
        return redirect("/otp")
    return page("""<h2>Login</h2>
<form method="post">
  <input name="user" placeholder="username"><br>
  <input name="password" type="password" placeholder="password"><br>
  <button>Login</button></form>""")


@app.route("/otp", methods=["GET", "POST"])
def otp():
    # VULN: unlimited attempts, no lockout, no expiry, no throttle ->
    # a 4-digit code falls to a 10 000-try brute force in seconds.
    if request.method == "POST":
        if request.form.get("code") == OTP_CURRENT:
            return page("<h2>Login berhasil.</h2><p>OTP diterima.</p>")
        return page("<h2>OTP salah.</h2><p>Coba lagi.</p>"
                    "<form method='post'><input name='code'>"
                    "<button>Verifikasi</button></form>")
    return page("""<h2>Masukkan OTP</h2><p>Kode 4 digit dikirim.</p>
<form method="post"><input name="code" maxlength="4">
<button>Verifikasi</button></form>""")


@app.route("/api/verify-otp")
def api_verify_otp():
    # JSON variant so brute force is trivially scriptable
    return jsonify(ok=request.args.get("code") == OTP_CURRENT)


# ------------------------------------------ 7. Information Disclosure ------
# VULN: dotfiles/config left web-readable. Real-looking values so the
# disclosure checker can CONFIRM via signature + format + entropy.
@app.route("/.env")
def dotenv():
    return app.response_class(
        "APP_NAME=VulnLab\n"
        "APP_ENV=production\n"
        "APP_KEY=base64:4mHvRkX8pQw2TzN7bYsJ9cL0dFgE6uIaO5xVrM3hK1w=\n"
        "DB_HOST=10.20.30.40\n"
        "DB_DATABASE=vulnlab_prod\n"
        "DB_USERNAME=vulnlab_app\n"
        "DB_PASSWORD=Kx9#mPzQ2$vL8nR5tY7!wB4e\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=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\n"
        "DATABASE_URL=mysql://vulnlab_app:Kx9#mPzQ2$vL8nR5tY7!wB4e"
        "@10.20.30.40:3306/vulnlab_prod\n",
        mimetype="text/plain")


@app.route("/.git/HEAD")
def git_head():
    return app.response_class("ref: refs/heads/main\n",
                              mimetype="text/plain")


@app.route("/.git/config")
def git_config():
    return app.response_class(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
        "[remote \"origin\"]\n\turl = git@github.com:vulnlab/internal.git\n",
        mimetype="text/plain")


@app.route("/health")
def health():
    return "ok"


if __name__ == "__main__":
    print("VulnLab running -> http://127.0.0.1:8765  (local only, do NOT expose)")
    app.run(host="127.0.0.1", port=8765)
