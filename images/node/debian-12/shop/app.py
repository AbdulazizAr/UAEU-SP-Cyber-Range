"""Online shop used as the business application of the live range (recipe flask_shop 0.3.0).

The weaknesses are switched by SHOP_WEAKNESSES, so the planted ones are real and the
others are absent:
- web.sqli_login: login query built by string formatting.
- web.path_traversal: /download joins the file name without containment.
- web.idor_object: /orders/<id> skips the ownership check.
- web.privilege_update: /profile/role lets any user set their own role.
It writes JSON lines to /var/log/shop/app.log (collected by the Wazuh agent).
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import time
from datetime import UTC, datetime
from functools import wraps

import psycopg2
from flask import Flask, abort, g, jsonify, redirect, request, send_file, session
from werkzeug.security import safe_join

WEAK = set(filter(None, os.environ.get("SHOP_WEAKNESSES", "").split(",")))
FILES = "/opt/shop/files"
LOG_PATH = os.environ.get("SHOP_LOG", "/var/log/shop/app.log")
PRODUCTS = [
    ("Desert Lamp", 39.0),
    ("Brass Kettle", 55.5),
    ("Palm Basket", 18.0),
    ("Linen Throw", 64.0),
    ("Cedar Box", 27.5),
    ("Clay Vase", 22.0),
    ("Spice Set", 31.0),
    ("Wool Rug", 149.0),
    ("Glass Lantern", 45.0),
    ("Copper Tray", 38.0),
    ("Date Gift Box", 26.0),
    ("Oud Candle", 19.5),
]

app = Flask(__name__)
app.secret_key = os.environ.get("SHOP_SECRET", "dev") + "-shop"


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def event(kind: str, **fields: object) -> None:
    rec = {"timestamp": _now(), "app": "shop", "event": kind, "src_ip": _client_ip(), **fields}
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def _client_ip() -> str:
    if not request:
        return "-"
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() or (request.remote_addr or "-")


def _dsn() -> str:
    host, port, db, user, password = os.environ["SHOP_DB"].split(":", 4)
    return f"host={host} port={port} dbname={db} user={user} password={password} connect_timeout=3"


def db():
    if "db" not in g:
        g.db = psycopg2.connect(_dsn())
        g.db.autocommit = True
    return g.db


@app.teardown_appcontext
def _close(_exc: BaseException | None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def _md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()  # legacy scheme on purpose (realistic)


def init_schema() -> None:
    conn = psycopg2.connect(_dsn())
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users (id serial PRIMARY KEY, username text UNIQUE NOT NULL,"
        " password text NOT NULL, role text NOT NULL DEFAULT 'customer', email text)"
    )
    cur.execute("CREATE TABLE IF NOT EXISTS products (id serial PRIMARY KEY, name text, price numeric)")
    cur.execute(
        "CREATE TABLE IF NOT EXISTS orders (id serial PRIMARY KEY, user_id int REFERENCES users(id),"
        " product_id int REFERENCES products(id), qty int, address text, created timestamptz DEFAULT now())"
    )
    cur.execute("SELECT count(*) FROM products")
    if cur.fetchone()[0] == 0:
        rng = random.Random(os.environ.get("SHOP_SECRET", "seed"))
        for name, price in PRODUCTS:
            cur.execute("INSERT INTO products (name, price) VALUES (%s, %s)", (name, price))
        cur.execute(
            "INSERT INTO users (username, password, role, email) VALUES (%s, %s, 'admin', %s)",
            ("shopadmin", _md5(os.environ.get("SHOP_SECRET", "x") + "admin"), "admin@shop.example"),
        )
        for i in range(1, 16):
            cur.execute(
                "INSERT INTO users (username, password, email) VALUES (%s, %s, %s) RETURNING id",
                (f"customer{i:02d}", _md5(f"{rng.random()}"), f"customer{i:02d}@mail.example"),
            )
            uid = cur.fetchone()[0]
            for _ in range(rng.randint(1, 4)):
                cur.execute(
                    "INSERT INTO orders (user_id, product_id, qty, address) VALUES (%s, %s, %s, %s)",
                    (
                        uid,
                        rng.randint(1, len(PRODUCTS)),
                        rng.randint(1, 3),
                        f"{rng.randint(1, 99)} Market St",
                    ),
                )
    conn.close()


def login_required(fn):
    @wraps(fn)
    def inner(*a, **kw):
        if "uid" not in session:
            abort(401)
        return fn(*a, **kw)

    return inner


@app.after_request
def _access(resp):
    event("http", method=request.method, path=request.full_path.rstrip("?"), status=resp.status_code,
          user=session.get("user"), ua=request.headers.get("User-Agent", "-"))  # fmt: skip
    return resp


@app.route("/health")
def health():
    try:
        db().cursor().execute("SELECT 1")
        return jsonify(status="ok", db="ok")
    except psycopg2.Error:
        return jsonify(status="degraded", db="down"), 503


@app.route("/")
def index():
    cur = db().cursor()
    cur.execute("SELECT id, name, price FROM products ORDER BY id")
    return jsonify(products=[{"id": i, "name": n, "price": float(p)} for i, n, p in cur.fetchall()])


@app.route("/product/<int:pid>")
def product(pid: int):
    cur = db().cursor()
    cur.execute("SELECT id, name, price FROM products WHERE id = %s", (pid,))
    row = cur.fetchone()
    if not row:
        abort(404)
    return jsonify(id=row[0], name=row[1], price=float(row[2]))


@app.route("/register", methods=["POST"])
def register():
    u, p = request.form.get("username", ""), request.form.get("password", "")
    if not u or not p:
        abort(400)
    try:
        cur = db().cursor()
        cur.execute("INSERT INTO users (username, password) VALUES (%s, %s) RETURNING id", (u, _md5(p)))
        event("register", user=u)
        return jsonify(id=cur.fetchone()[0]), 201
    except psycopg2.IntegrityError:
        return jsonify(error="exists"), 409


@app.route("/login", methods=["POST"])
def login():
    u, p = request.form.get("username", ""), request.form.get("password", "")
    cur = db().cursor()
    try:
        if "web.sqli_login" in WEAK:
            cur.execute(
                f"SELECT id, username, role FROM users WHERE username = '{u}' AND password = md5('{p}')"
            )
        else:
            cur.execute(
                "SELECT id, username, role FROM users WHERE username = %s AND password = md5(%s)", (u, p)
            )
        row = cur.fetchone()
    except psycopg2.Error as exc:
        event("db_error", user=u, error=str(exc).splitlines()[0][:200])
        return jsonify(error="internal error"), 500
    if not row:
        event("login_failure", user=u)
        return jsonify(error="invalid credentials"), 401
    session.update(uid=row[0], user=row[1], role=row[2])
    event("login_success", user=row[1], role=row[2])
    return jsonify(user=row[1], role=row[2])


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/orders")
@login_required
def my_orders():
    cur = db().cursor()
    cur.execute("SELECT id, product_id, qty FROM orders WHERE user_id = %s ORDER BY id", (session["uid"],))
    return jsonify(orders=[{"id": i, "product": p, "qty": q} for i, p, q in cur.fetchall()])


@app.route("/orders", methods=["POST"])
@login_required
def create_order():
    cur = db().cursor()
    cur.execute(
        "INSERT INTO orders (user_id, product_id, qty, address) VALUES (%s, %s, %s, %s) RETURNING id",
        (session["uid"], int(request.form.get("product_id", 1)), int(request.form.get("qty", 1)),
         request.form.get("address", "")),
    )  # fmt: skip
    oid = cur.fetchone()[0]
    event("order_created", user=session["user"], order_id=oid)
    return jsonify(id=oid), 201


@app.route("/orders/<int:oid>")
@login_required
def order(oid: int):
    cur = db().cursor()
    cur.execute("SELECT o.id, o.user_id, u.username, o.product_id, o.qty, o.address FROM orders o"
                " JOIN users u ON u.id = o.user_id WHERE o.id = %s", (oid,))  # fmt: skip
    row = cur.fetchone()
    if not row:
        abort(404)
    if row[1] != session["uid"] and "web.idor_object" not in WEAK:
        event("access_denied", user=session["user"], object=f"order:{oid}")
        abort(403)
    event("order_view", user=session["user"], order_id=oid, owner=row[2])
    return jsonify(id=row[0], owner=row[2], product=row[3], qty=row[4], address=row[5])


@app.route("/download")
def download():
    name = request.args.get("file", "")
    if "web.path_traversal" in WEAK:  # noqa: SIM108 (kept explicit: this is the weakness)
        path = os.path.join(FILES, name)  # no containment check (the weakness)
    else:
        path = safe_join(FILES, name) or ""
    if not path or not os.path.isfile(path):
        abort(404)
    event("download", file=name)
    return send_file(path)


@app.route("/profile/role", methods=["POST"])
@login_required
def set_role():
    role = request.form.get("role", "customer")
    if session.get("role") != "admin" and "web.privilege_update" not in WEAK:
        event("access_denied", user=session["user"], object="role")
        abort(403)
    db().cursor().execute("UPDATE users SET role = %s WHERE id = %s", (role, session["uid"]))
    session["role"] = role
    event("role_change", user=session["user"], role=role)
    return jsonify(role=role)


@app.route("/admin")
@login_required
def admin():
    if session.get("role") != "admin":
        event("access_denied", user=session["user"], object="admin")
        abort(403)
    cur = db().cursor()
    cur.execute("SELECT id, username, role, email FROM users ORDER BY id")
    event("admin_view", user=session["user"])
    return jsonify(
        users=[dict(zip(("id", "username", "role", "email"), r, strict=True)) for r in cur.fetchall()]
    )


_schema_ready = False


@app.before_request
def _ensure_schema() -> None:
    """Create and seed tables on first use (the database host may start after this one)."""
    global _schema_ready
    if not _schema_ready and request.endpoint != "health":
        try:
            init_schema()
            _schema_ready = True
        except psycopg2.Error:
            abort(503)


for _attempt in range(10):  # at start-up, under gunicorn --preload: once, in the master
    try:
        init_schema()
        _schema_ready = True
        break
    except psycopg2.Error:
        time.sleep(2)
