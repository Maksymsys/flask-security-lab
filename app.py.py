import html
import os
import re
import threading
import time
import uuid
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation

import requests
from dotenv import load_dotenv
from flask import Flask, abort, jsonify, render_template_string, request, session
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
# Safety check: the web app must never run with superuser rights
if make_url(DATABASE_URL).username == "postgres":
    raise RuntimeError("The site must not connect to the database as the postgres superuser")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
BAN_SECONDS = 24 * 60 * 60

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.json.ensure_ascii = False
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# Behind a reverse proxy, trust X-Forwarded-For only for this many proxies
trusted_proxies = int(os.getenv("TRUSTED_PROXY_COUNT", "0"))
if trusted_proxies > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=trusted_proxies)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, hide_parameters=True)
SessionFactory = sessionmaker(bind=engine)

redis_client = Redis.from_url(
    REDIS_URL,
    decode_responses=True,
    socket_timeout=0.2,
    socket_connect_timeout=0.2,
)


class BanList:
    """IP ban list stored in Redis, with an in-memory fallback if Redis is down."""

    def __init__(self, client, ttl):
        self.client = client
        self.ttl = ttl
        self.fallback = {}
        self.lock = threading.Lock()

    @staticmethod
    def key(ip):
        return f"banned:{ip}"

    def ban(self, ip, reason):
        try:
            self.client.setex(self.key(ip), self.ttl, reason)
        except RedisError:
            with self.lock:
                self.fallback[ip] = time.time() + self.ttl

    def is_banned(self, ip):
        try:
            return bool(self.client.exists(self.key(ip)))
        except RedisError:
            now = time.time()
            with self.lock:
                # Drop expired local bans, then check the current IP
                for banned_ip in [i for i, until in self.fallback.items() if until <= now]:
                    del self.fallback[banned_ip]
                return ip in self.fallback


bans = BanList(redis_client, BAN_SECONDS)


def send_telegram(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        app.logger.warning("Telegram is not configured: skipping alert")
        return
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"},
            timeout=5,
        )
        if response.status_code != 200:
            app.logger.warning("Telegram API returned status %s", response.status_code)
    except requests.RequestException as error:
        # Log only the error type: the full message can contain the URL with the bot token
        app.logger.warning("Failed to send Telegram alert: %s", type(error).__name__)


def punish(ip, reason, detail):
    """Ban the IP and send an alert in a background thread."""
    detail = detail[:200]
    bans.ban(ip, f"{reason}: {detail}")
    # Everything inserted into the HTML message is escaped
    message = (
        "🚨 <b>SECURITY ALERT</b>\n"
        f"IP <code>{html.escape(ip)}</code> {html.escape(reason)}. "
        "Automatic 24-hour ban.\n"
        f"{html.escape(detail)}"
    )
    threading.Thread(target=send_telegram, args=(message,), daemon=True).start()


def client_ip():
    return request.remote_addr or "unknown"


# Paths that real users never visit, but bots and scanners always probe
HONEY_PATHS = (
    "/wp-admin",
    "/wp-login.php",
    "/.env",
    "/.git",
    "/admin.php",
    "/phpmyadmin",
    "/backup.sql",
)


def is_honey_path(path):
    path = path.lower().rstrip("/") or "/"
    return any(path == honey or path.startswith(honey + "/") for honey in HONEY_PATHS)


@app.before_request
def security_check():
    ip = client_ip()
    # Banned IPs are rejected first, so a banned IP cannot trigger repeated alerts
    if bans.is_banned(ip):
        return jsonify(status="error", message="Access Denied. Your IP is blocked."), 403
    if is_honey_path(request.path):
        punish(ip, "is scanning hidden directories", f"URL: {request.path}")
        abort(404)  # a plain 404, so the bot does not realize this is a trap


@contextmanager
def db_session(user_id=None):
    """Database session. If user_id is given, it is set as the RLS context."""
    db = SessionFactory()
    try:
        if user_id is not None:
            # is_local=true: the setting lives only until the end of this transaction
            db.execute(
                text("SELECT set_config('app.current_user_id', :user_id, true)"),
                {"user_id": str(user_id)},
            )
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

REGISTER_FORM = """
<h2>Registration</h2>
<form method="POST" action="/register">
    <label>Email:</label><br>
    <input type="email" name="email" required><br><br>
    <label>Password:</label><br>
    <input type="password" name="password" minlength="8" required><br><br>
    <!-- Honeypot: hidden from humans with CSS, bots tend to fill it in -->
    <input type="text" name="additional_email" style="display:none;" autocomplete="off" tabindex="-1" aria-hidden="true">
    <button type="submit">Sign up</button>
</form>
"""

LOGIN_FORM = """
<h2>Log in</h2>
<form method="POST" action="/login">
    <label>Email:</label><br>
    <input type="email" name="email" required><br><br>
    <label>Password:</label><br>
    <input type="password" name="password" required><br><br>
    <button type="submit">Log in</button>
</form>
"""


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        # The template is a constant (no user data inside), so there is no SSTI risk
        return render_template_string(REGISTER_FORM)

    # A human never sees this field, so a filled value means a bot
    if request.form.get("additional_email"):
        punish(client_ip(), "filled in a hidden form field (spam attack)", "Form: /register")
        return jsonify(status="error", message="Spam detected."), 400

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    if len(email) > 255 or not EMAIL_RE.fullmatch(email) or len(password) < 8:
        return jsonify(status="error", message="Invalid email or password (minimum 8 characters)."), 400

    try:
        with db_session() as db:
            user_id = db.execute(
                text("INSERT INTO users (email, password_hash) VALUES (:email, :password_hash) RETURNING id"),
                {"email": email, "password_hash": generate_password_hash(password)},
            ).scalar_one()
    except IntegrityError:
        return jsonify(status="error", message="A user with this email already exists."), 409

    return (
        jsonify(
            status="success",
            message=f"User {email} registered successfully!",
            user_id=str(user_id),
        ),
        201,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_FORM)

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    with db_session() as db:
        row = db.execute(
            text("SELECT id, password_hash FROM users WHERE email = :email"),
            {"email": email},
        ).first()

    # The same answer for an unknown email and a wrong password
    if row is None or not check_password_hash(row.password_hash, password):
        return jsonify(status="error", message="Invalid email or password."), 401

    session.clear()  # new session after login (protection against session fixation)
    session["user_id"] = str(row.id)
    return jsonify(status="success", user_id=str(row.id))


@app.post("/logout")
def logout():
    session.clear()
    return jsonify(status="success")


def authenticated_user_id(requested_id=None):
    """Return (user_id, None) for a logged-in user, or (None, error_response).

    If requested_id comes from the URL, it must match the user in the session.
    """
    current = session.get("user_id")
    if not current:
        return None, (jsonify(status="error", message="Authentication required."), 401)
    if requested_id is not None:
        try:
            requested = str(uuid.UUID(requested_id))
        except ValueError:
            abort(404)
        if requested != current:
            return None, (jsonify(status="error", message="Access denied."), 403)
    return current, None


@app.get("/orders")
@app.get("/orders/<user_id>")
def get_orders(user_id=None):
    current, error = authenticated_user_id(user_id)
    if error:
        return error

    # The RLS context comes from the session, never from the URL
    with db_session(current) as db:
        rows = db.execute(
            text("SELECT id, title, amount, created_at FROM orders ORDER BY created_at DESC")
        ).all()

    return jsonify(
        user_id=current,
        orders=[
            {
                "id": str(row.id),
                "title": row.title,
                "amount": float(row.amount),
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ],
    )


@app.post("/orders")
def create_order():
    current, error = authenticated_user_id()
    if error:
        return error

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = request.form
    title = str(data.get("title") or "").strip()
    try:
        amount = Decimal(str(data.get("amount"))).quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        amount = None
    if not title or len(title) > 255 or amount is None or not amount.is_finite() or not 0 <= amount < Decimal("100000000"):
        return jsonify(status="error", message="Invalid order data."), 400

    with db_session(current) as db:
        order_id = db.execute(
            text("INSERT INTO orders (user_id, title, amount) VALUES (:user_id, :title, :amount) RETURNING id"),
            {"user_id": current, "title": title, "amount": amount},
        ).scalar_one()

    return jsonify(status="success", id=str(order_id)), 201


if __name__ == "__main__":
    # debug is enabled only explicitly (FLASK_DEBUG=1), never by default
    app.run(host="127.0.0.1", port=5000, debug=os.getenv("FLASK_DEBUG") == "1")
