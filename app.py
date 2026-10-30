import base64
import os
import re
import sqlite3
import time
from functools import wraps
from io import BytesIO
from pathlib import Path

import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Flask, g, render_template, request,
    redirect, url_for, session, flash
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect


# =========================
# CONFIGURATION
# =========================

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
DATABASE_PATH = INSTANCE_DIR / "securegate.db"

INSTANCE_DIR.mkdir(exist_ok=True)

KEY_PATH = INSTANCE_DIR / "totp.key"

# Preserve the existing key to decrypt previously stored MFA secrets.
if not KEY_PATH.exists():
    KEY_PATH.write_bytes(Fernet.generate_key())

fernet = Fernet(KEY_PATH.read_bytes())


def encrypt_totp_secret(secret):
    return fernet.encrypt(secret.encode()).decode()


def decrypt_totp_secret(encrypted_secret):
    return fernet.decrypt(encrypted_secret.encode()).decode()


app = Flask(__name__)

secret_key = os.environ.get("SECUREGATE_SECRET_KEY")

if not secret_key:
    raise RuntimeError(
        "Set SECUREGATE_SECRET_KEY before starting the application."
    )

app.config.update(
    SECRET_KEY=secret_key,
    DATABASE=str(DATABASE_PATH),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Local HTTP development only
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=16 * 1024,
)

CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

password_hasher = PasswordHasher()


# =========================
# DATABASE
# =========================

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")

    return g.db


def init_db():
    db = get_db()

    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            totp_secret TEXT,
            mfa_enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
                ON DELETE SET NULL
        );
        """
    )

    columns = {
        row["name"]
        for row in db.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    }

    if "pending_totp_secret" not in columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN pending_totp_secret TEXT"
        )

    if "last_totp_step" not in columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN last_totp_step INTEGER"
        )

    db.commit()


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


def record_event(user_id, event_type):
    db = get_db()

    db.execute(
        "INSERT INTO login_events (user_id, event_type) VALUES (?, ?)",
        (user_id, event_type),
    )

    db.commit()


# =========================
# AUTHENTICATION HELPERS
# =========================

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "error")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


def matching_totp_step(secret, code):
    """Return the matching TOTP time step, or None if invalid."""
    totp = pyotp.TOTP(secret)
    current_step = int(time.time() // totp.interval)

    for step in (
        current_step - 1,
        current_step,
        current_step + 1,
    ):
        if step >= 0 and totp.at(
            step * totp.interval
        ) == code:
            return step

    return None


# =========================
# HOME
# =========================

@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# =========================
# REGISTRATION
# =========================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get("password", "")

        if not re.fullmatch(
            r"[A-Za-z0-9_.-]{3,32}", username
        ):
            flash(
                "Username must be 3-32 characters: letters, "
                "numbers, dots, underscores or hyphens.",
                "error",
            )
            return render_template("register.html")

        if len(password) < 12 or len(password) > 128:
            flash(
                "Password must be 12-128 characters.",
                "error",
            )
            return render_template("register.html")

        password_hash = password_hasher.hash(password)
        db = get_db()

        try:
            cursor = db.execute(
                "INSERT INTO users (username, password_hash) "
                "VALUES (?, ?)",
                (username, password_hash),
            )

            db.commit()

            record_event(
                cursor.lastrowid,
                "registration_success",
            )

        except sqlite3.IntegrityError:
            db.rollback()
            flash(
                "That username is already registered.",
                "error",
            )
            return render_template("register.html")

        flash(
            "Account created! Please log in.",
            "success",
        )

        return redirect(url_for("login"))

    return render_template("register.html")


# =========================
# LOGIN
# =========================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get(
        "username", ""
    ).strip()

    password = request.form.get("password", "")
    db = get_db()

    user = db.execute(
        "SELECT id, username, password_hash, mfa_enabled "
        "FROM users WHERE username = ? COLLATE NOCASE",
        (username,),
    ).fetchone()

    if user is None:
        flash(
            "Invalid username or password.",
            "error",
        )

        record_event(None, "login_failure")
        return render_template("login.html")

    try:
        password_hasher.verify(
            user["password_hash"],
            password,
        )

    except (VerifyMismatchError, VerificationError):
        flash(
            "Invalid username or password.",
            "error",
        )

        record_event(user["id"], "login_failure")
        return render_template("login.html")

    if password_hasher.check_needs_rehash(
        user["password_hash"]
    ):
        new_hash = password_hasher.hash(password)

        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, user["id"]),
        )

        db.commit()

    # MFA-enabled accounts require a second verification step.
    if user["mfa_enabled"]:
        session.clear()
        session["pending_mfa_user_id"] = user["id"]
        session.permanent = True

        return redirect(url_for("verify_mfa"))

    # Password-only login for accounts without MFA enabled.
    session.clear()
    session["user_id"] = user["id"]
    session.permanent = True

    record_event(user["id"], "login_success")

    return redirect(url_for("dashboard"))


# =========================
# MFA VERIFICATION
# =========================

@app.route("/verify-mfa", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def verify_mfa():
    pending_id = session.get("pending_mfa_user_id")

    if not pending_id:
        return redirect(url_for("login"))

    db = get_db()

    user = db.execute(
        "SELECT id, totp_secret, mfa_enabled, last_totp_step "
        "FROM users WHERE id = ?",
        (pending_id,),
    ).fetchone()

    if (
        user is None
        or not user["mfa_enabled"]
        or not user["totp_secret"]
    ):
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        if not (
            len(code) == 6
            and code.isascii()
            and code.isdigit()
        ):
            flash(
                "Enter a valid six-digit code.",
                "error",
            )
            return render_template("verify_mfa.html")

        try:
            secret = decrypt_totp_secret(
                user["totp_secret"]
            )

        except InvalidToken:
            session.clear()

            flash(
                "MFA verification is unavailable. "
                "Please contact the administrator.",
                "error",
            )

            return redirect(url_for("login"))

        matched_step = matching_totp_step(secret, code)

        if matched_step is None:
            record_event(
                user["id"],
                "mfa_login_failure",
            )

            flash(
                "Incorrect or expired code.",
                "error",
            )

            return render_template("verify_mfa.html")

        # Atomically accept each TOTP time step only once.
        cursor = db.execute(
            "UPDATE users SET last_totp_step = ? "
            "WHERE id = ? "
            "AND (last_totp_step IS NULL OR last_totp_step < ?)",
            (
                matched_step,
                user["id"],
                matched_step,
            ),
        )

        db.commit()

        if cursor.rowcount != 1:
            record_event(
                user["id"],
                "mfa_replay_rejected",
            )

            flash(
                "That code has already been used. "
                "Wait for a new code.",
                "error",
            )

            return render_template("verify_mfa.html")

        # Establish the authenticated session only after MFA succeeds.
        session.clear()
        session["user_id"] = user["id"]
        session.permanent = True

        record_event(
            user["id"],
            "login_success",
        )

        return redirect(url_for("dashboard"))

    return render_template("verify_mfa.html")


# =========================
# DASHBOARD
# =========================

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()

    user = db.execute(
        "SELECT username, mfa_enabled "
        "FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    events = db.execute(
        "SELECT event_type, created_at "
        "FROM login_events "
        "WHERE user_id = ? "
        "ORDER BY id DESC LIMIT 10",
        (session["user_id"],),
    ).fetchall()

    return render_template(
        "dashboard.html",
        user=user,
        events=events,
    )


# =========================
# MFA SETUP
# =========================

@app.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def setup_mfa():
    db = get_db()

    user = db.execute(
        "SELECT id, username, mfa_enabled, pending_totp_secret "
        "FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    if user["mfa_enabled"]:
        flash(
            "MFA is already enabled.",
            "success",
        )

        return redirect(url_for("dashboard"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        if not (
            len(code) == 6
            and code.isascii()
            and code.isdigit()
        ):
            flash(
                "Enter a valid six-digit code.",
                "error",
            )

            return redirect(url_for("setup_mfa"))

        if not user["pending_totp_secret"]:
            flash(
                "Please reload the setup page and try again.",
                "error",
            )

            return redirect(url_for("setup_mfa"))

        try:
            secret = decrypt_totp_secret(
                user["pending_totp_secret"]
            )

        except InvalidToken:
            flash(
                "MFA setup could not be verified. Try again.",
                "error",
            )

            return redirect(url_for("setup_mfa"))

        if not pyotp.TOTP(secret).verify(
            code,
            valid_window=1,
        ):
            record_event(
                user["id"],
                "mfa_enrollment_failure",
            )

            flash(
                "Incorrect or expired code. Try again.",
                "error",
            )

            return redirect(url_for("setup_mfa"))

        db.execute(
            "UPDATE users SET "
            "totp_secret = ?, "
            "pending_totp_secret = NULL, "
            "mfa_enabled = 1, "
            "last_totp_step = NULL "
            "WHERE id = ?",
            (
                encrypt_totp_secret(secret),
                user["id"],
            ),
        )

        db.commit()

        record_event(
            user["id"],
            "mfa_enabled",
        )

        flash(
            "MFA enabled successfully!",
            "success",
        )

        return redirect(url_for("dashboard"))

    if user["pending_totp_secret"]:
        try:
            secret = decrypt_totp_secret(
                user["pending_totp_secret"]
            )

        except InvalidToken:
            secret = pyotp.random_base32()

            db.execute(
                "UPDATE users SET pending_totp_secret = ? "
                "WHERE id = ?",
                (
                    encrypt_totp_secret(secret),
                    user["id"],
                ),
            )

            db.commit()

    else:
        secret = pyotp.random_base32()

        db.execute(
            "UPDATE users SET pending_totp_secret = ? "
            "WHERE id = ?",
            (
                encrypt_totp_secret(secret),
                user["id"],
            ),
        )

        db.commit()

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=user["username"],
        issuer_name="SecureGate",
    )

    image = qrcode.make(uri)
    buffer = BytesIO()

    image.save(buffer, format="PNG")

    qr_image = base64.b64encode(
        buffer.getvalue()
    ).decode("ascii")

    return render_template(
        "setup_mfa.html",
        qr_image=qr_image,
    )


# =========================
# LOGOUT
# =========================

@app.route("/logout", methods=["POST"])
def logout():
    user_id = session.get("user_id")

    if user_id is not None:
        record_event(
            user_id,
            "logout",
        )

    session.clear()

    flash(
        "You have logged out.",
        "success",
    )

    return redirect(url_for("login"))


# =========================
# INITIALIZE DATABASE
# =========================

with app.app_context():
    init_db()


# =========================
# RUN APPLICATION
# =========================

if __name__ == "__main__":
    app.run(debug=True)