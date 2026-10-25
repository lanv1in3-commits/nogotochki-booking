from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
from datetime import date, datetime, timedelta
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlencode
from urllib.request import Request, urlopen
from wsgiref.simple_server import make_server

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DATABASE_PATH", ROOT / "data" / "booking.sqlite"))
DATABASE_URL = os.getenv("DATABASE_URL", "")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")
YANDEX_CLIENT_ID = os.getenv("YANDEX_CLIENT_ID", "")
YANDEX_CLIENT_SECRET = os.getenv("YANDEX_CLIENT_SECRET", "")
SLOT_STEP_MINUTES = 30
DEFAULT_SERVICES = (
    ("gel", "Маникюр с покрытием", 120, 2400),
    ("brows", "Коррекция и окрашивание бровей", 60, 1200),
    ("lamination", "Ламинирование бровей", 60, 1800),
)
DEFAULT_MASTERS = ((1, "Анна Власова"), (2, "Мария Белова"), (3, "София Ли"))


def password_hash(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 180_000)
    return salt, base64.b64encode(digest).decode()


class Connection:
    def __init__(self):
        self.postgres = bool(DATABASE_URL)
        if self.postgres:
            import psycopg
            from psycopg.rows import dict_row

            # Supabase transaction pooler can reuse a backend connection that
            # already has psycopg-generated prepared statement names.
            self.raw = psycopg.connect(DATABASE_URL, row_factory=dict_row, prepare_threshold=None)
        else:
            DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            self.raw = sqlite3.connect(DB_PATH)
            self.raw.row_factory = sqlite3.Row
            self.raw.execute("PRAGMA foreign_keys=ON")

    def execute(self, sql, params=()):
        return self.raw.execute(sql.replace("?", "%s") if self.postgres else sql, params)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.raw.commit() if exc_type is None else self.raw.rollback()
        self.raw.close()


def db() -> Connection:
    return Connection()


def insert_id(conn: Connection, sql: str, params: tuple) -> int:
    if conn.postgres:
        return conn.execute(sql + " RETURNING id", params).fetchone()["id"]
    return conn.execute(sql, params).lastrowid


def table_columns(conn: Connection, table: str) -> set[str]:
    if conn.postgres:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=?",
            (table,),
        ).fetchall()
        return {row["column_name"] for row in rows}
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def add_column(conn: Connection, table: str, name: str, definition: str) -> None:
    if name not in table_columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def drop_legacy_slot_constraint(conn: Connection) -> None:
    """Remove a legacy hard uniqueness rule so cancelled slots can be reused."""
    if not conn.postgres:
        return
    rows = conn.execute(
        """SELECT conname, pg_get_constraintdef(oid) AS definition
        FROM pg_constraint
        WHERE conrelid='booking_appointments'::regclass AND contype='u'"""
    ).fetchall()
    legacy_columns = ("master_id", "appointment_date", "start_time")
    for row in rows:
        definition = row["definition"].lower()
        if all(column in definition for column in legacy_columns):
            constraint = row["conname"].replace('"', '""')
            conn.execute(f'ALTER TABLE booking_appointments DROP CONSTRAINT "{constraint}"')


def init_db() -> None:
    with db() as conn:
        if conn.postgres:
            conn.execute("SELECT pg_advisory_xact_lock(hashtext('nogotochki_schema_v3'))")
        serial = "BIGSERIAL PRIMARY KEY" if conn.postgres else "INTEGER PRIMARY KEY"
        integer = "BIGINT" if conn.postgres else "INTEGER"
        for statement in (
            f"""CREATE TABLE IF NOT EXISTS booking_users(id {serial},email TEXT NOT NULL UNIQUE,full_name TEXT NOT NULL,phone TEXT,password_salt TEXT,password_hash TEXT,role TEXT NOT NULL DEFAULT 'client' CHECK(role IN ('client','admin')),provider TEXT,provider_user_id TEXT,UNIQUE(provider,provider_user_id))""",
            f"""CREATE TABLE IF NOT EXISTS booking_sessions(token_hash TEXT PRIMARY KEY,user_id {integer} NOT NULL REFERENCES booking_users(id) ON DELETE CASCADE,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
            "CREATE TABLE IF NOT EXISTS booking_oauth_states(state_hash TEXT PRIMARY KEY,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)",
            "CREATE TABLE IF NOT EXISTS booking_services(code TEXT PRIMARY KEY,name TEXT NOT NULL,duration_minutes INTEGER NOT NULL,price INTEGER NOT NULL,active INTEGER NOT NULL DEFAULT 1)",
            f"CREATE TABLE IF NOT EXISTS booking_masters(id {serial},name TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1)",
            f"CREATE TABLE IF NOT EXISTS booking_schedules(id {serial},master_id {integer} NOT NULL REFERENCES booking_masters(id),weekday INTEGER NOT NULL,work_start TEXT NOT NULL,work_end TEXT NOT NULL,UNIQUE(master_id,weekday))",
            f"CREATE TABLE IF NOT EXISTS booking_blocks(id {serial},master_id {integer} NOT NULL REFERENCES booking_masters(id),block_date TEXT NOT NULL,start_time TEXT NOT NULL,end_time TEXT NOT NULL,reason TEXT NOT NULL DEFAULT '')",
            f"""CREATE TABLE IF NOT EXISTS booking_appointments(id {serial},user_id {integer} NOT NULL REFERENCES booking_users(id),service_code TEXT NOT NULL,master_id {integer} NOT NULL,appointment_date TEXT NOT NULL,start_time TEXT NOT NULL,duration_minutes INTEGER,service_name TEXT,master_name TEXT,status TEXT NOT NULL DEFAULT 'active',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
        ):
            conn.execute(statement)

        # Migrate the earlier publication-homework database without deleting data.
        add_column(conn, "booking_appointments", "duration_minutes", "INTEGER")
        add_column(conn, "booking_appointments", "service_name", "TEXT")
        add_column(conn, "booking_appointments", "master_name", "TEXT")
        add_column(conn, "booking_appointments", "updated_at", "TEXT")
        drop_legacy_slot_constraint(conn)
        for code, name, duration, price in DEFAULT_SERVICES:
            if not conn.execute("SELECT code FROM booking_services WHERE code=?", (code,)).fetchone():
                conn.execute("INSERT INTO booking_services(code,name,duration_minutes,price,active) VALUES(?,?,?,?,1)", (code, name, duration, price))
        for master_id, name in DEFAULT_MASTERS:
            if not conn.execute("SELECT id FROM booking_masters WHERE id=?", (master_id,)).fetchone():
                conn.execute("INSERT INTO booking_masters(id,name,active) VALUES(?,?,1)", (master_id, name))
            for weekday in range(6):
                if not conn.execute("SELECT id FROM booking_schedules WHERE master_id=? AND weekday=?", (master_id, weekday)).fetchone():
                    conn.execute("INSERT INTO booking_schedules(master_id,weekday,work_start,work_end) VALUES(?,?,?,?)", (master_id, weekday, "10:00", "19:00"))
        if conn.postgres:
            conn.execute("SELECT setval(pg_get_serial_sequence('booking_masters','id'),COALESCE((SELECT MAX(id) FROM booking_masters),1),true)")
        conn.execute("UPDATE booking_appointments SET duration_minutes=COALESCE(duration_minutes,(SELECT duration_minutes FROM booking_services WHERE booking_services.code=booking_appointments.service_code),60)")
        conn.execute("UPDATE booking_appointments SET service_name=COALESCE(service_name,(SELECT name FROM booking_services WHERE booking_services.code=booking_appointments.service_code),service_code)")
        conn.execute("UPDATE booking_appointments SET master_name=COALESCE(master_name,(SELECT name FROM booking_masters WHERE booking_masters.id=booking_appointments.master_id),'Мастер')")
        current_time_text = "CURRENT_TIMESTAMP::text" if conn.postgres else "CURRENT_TIMESTAMP"
        conn.execute(f"UPDATE booking_appointments SET updated_at=COALESCE(updated_at,created_at,{current_time_text})")
        admin_email, admin_password = os.getenv("ADMIN_EMAIL", "").strip().lower(), os.getenv("ADMIN_PASSWORD", "")
        if admin_email and admin_password:
            row = conn.execute("SELECT id FROM booking_users WHERE email=?", (admin_email,)).fetchone()
            if row:
                conn.execute("UPDATE booking_users SET role='admin' WHERE id=?", (row["id"],))
            else:
                salt, digest = password_hash(admin_password)
                conn.execute("INSERT INTO booking_users(email,full_name,password_salt,password_hash,role) VALUES(?,?,?,?, 'admin')", (admin_email, "Администратор", salt, digest))


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


STYLE = """
*{box-sizing:border-box}body{margin:0;background:#fffaf7;color:#2e2435;font:16px/1.5 Inter,system-ui,sans-serif}a{color:#52367f}.wrap{width:min(1120px,calc(100% - 32px));margin:auto}.top{display:flex;justify-content:space-between;align-items:center;padding:22px 0}.brand{font-size:21px;font-weight:800}.notice{background:#fff0c7;border:1px solid #ecd17b;padding:12px 16px;border-radius:12px;margin-bottom:22px}.panel{background:#fff;border:1px solid #e9dfe7;border-radius:22px;padding:28px;box-shadow:0 12px 35px #4b316414;margin:22px 0}h1{font-size:42px;line-height:1.05}h2{margin-top:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.card{border:1px solid #e9dfe7;border-radius:16px;padding:18px}.button,button{display:inline-block;border:0;border-radius:12px;padding:11px 16px;background:#7051a8;color:#fff;text-decoration:none;font-weight:700;cursor:pointer}.secondary{background:#fff;color:#52367f;border:1px solid #d7cadc}.danger{background:#a33145}.inline{display:inline}.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;align-items:end}label{display:block;font-weight:700;margin:12px 0 5px}input,select{width:100%;padding:10px;border:1px solid #d7cadc;border-radius:10px;font:inherit}.error{color:#9f2635}.success{color:#176f46}.meta{color:#766b79;font-size:14px}.status{font-weight:700}table{width:100%;border-collapse:collapse}th,td{padding:10px;border-bottom:1px solid #e9dfe7;text-align:left;vertical-align:top}.nav a{margin-left:14px}.muted{opacity:.58}@media(max-width:700px){h1{font-size:34px}.top{align-items:flex-start}.nav a{display:block;margin:3px 0}table{display:block;overflow:auto}}
"""


def page(title: str, body: str, user=None, status: str = "200 OK"):
    nav = '<a href="/">Главная</a>'
    if user:
        nav += ' <a href="/book">Записаться</a> <a href="/cabinet">Мои записи</a>'
        if user["role"] == "admin":
            nav += ' <a href="/admin">Админка</a> <a href="/admin/catalog">Услуги и мастера</a>'
        nav += ' <a href="/logout">Выйти</a>'
    else:
        nav += ' <a href="/login">Войти</a> <a href="/register">Регистрация</a>'
    document = f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} — Ноготочки</title><style>{STYLE}</style></head><body><div class="wrap"><header class="top"><div class="brand">✦ Ноготочки</div><nav class="nav">{nav}</nav></header>{body}</div></body></html>'''
    return status, [("Content-Type", "text/html; charset=utf-8")], document.encode()


def redirect(location: str, cookie: str | None = None):
    headers = [("Location", location), ("Content-Length", "0")]
    if cookie:
        headers.append(("Set-Cookie", cookie))
    return "303 See Other", headers, b""


def form_data(environ) -> dict[str, str]:
    raw = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0)).decode()
    return {key: values[0] for key, values in parse_qs(raw).items()}


def query_data(environ) -> dict[str, str]:
    return {key: values[0] for key, values in parse_qs(environ.get("QUERY_STRING", "")).items()}


def current_user(environ):
    token = SimpleCookie(environ.get("HTTP_COOKIE", "")).get("session")
    if not token:
        return None
    with db() as conn:
        return conn.execute("SELECT u.* FROM booking_sessions s JOIN booking_users u ON u.id=s.user_id WHERE s.token_hash=?", (hashlib.sha256(token.value.encode()).hexdigest(),)).fetchone()


def issue_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute("INSERT INTO booking_sessions(token_hash,user_id) VALUES(?,?)", (hashlib.sha256(token.encode()).hexdigest(), user_id))
    return f"session={token}; Path=/; HttpOnly; SameSite=Lax{'; Secure' if BASE_URL.startswith('https://') else ''}"


def parse_clock(value: str) -> datetime:
    return datetime.combine(date(2000, 1, 1), datetime.strptime(value, "%H:%M").time())


def overlaps(start_a: str, duration_a: int, start_b: str, duration_b: int) -> bool:
    a0, b0 = parse_clock(start_a), parse_clock(start_b)
    return a0 < b0 + timedelta(minutes=duration_b) and b0 < a0 + timedelta(minutes=duration_a)


def active_catalog(conn: Connection):
    return (
        conn.execute("SELECT * FROM booking_services WHERE active=1 ORDER BY name").fetchall(),
        conn.execute("SELECT * FROM booking_masters WHERE active=1 ORDER BY name").fetchall(),
    )


def available_slots(conn: Connection, service_code: str, master_id: int, day: str, exclude_id: int = 0) -> list[str]:
    service = conn.execute("SELECT * FROM booking_services WHERE code=? AND active=1", (service_code,)).fetchone()
    master = conn.execute("SELECT * FROM booking_masters WHERE id=? AND active=1", (master_id,)).fetchone()
    try:
        booking_day = datetime.strptime(day, "%Y-%m-%d").date()
    except ValueError:
        return []
    if not service or not master or booking_day < date.today():
        return []
    schedule = conn.execute("SELECT * FROM booking_schedules WHERE master_id=? AND weekday=?", (master_id, booking_day.weekday())).fetchone()
    if not schedule:
        return []
    duration = int(service["duration_minutes"])
    appointments = conn.execute("SELECT id,start_time,duration_minutes FROM booking_appointments WHERE master_id=? AND appointment_date=? AND status='active'", (master_id, day)).fetchall()
    blocks = conn.execute("SELECT start_time,end_time FROM booking_blocks WHERE master_id=? AND block_date=?", (master_id, day)).fetchall()
    cursor, work_end, slots = parse_clock(schedule["work_start"]), parse_clock(schedule["work_end"]), []
    while cursor + timedelta(minutes=duration) <= work_end:
        start = cursor.strftime("%H:%M")
        busy = any(row["id"] != exclude_id and overlaps(start, duration, row["start_time"], int(row["duration_minutes"] or 60)) for row in appointments)
        blocked = any(parse_clock(start) < parse_clock(row["end_time"]) and parse_clock(row["start_time"]) < parse_clock(start) + timedelta(minutes=duration) for row in blocks)
        if not busy and not blocked:
            slots.append(start)
        cursor += timedelta(minutes=SLOT_STEP_MINUTES)
    return slots


def lock_booking_day(conn: Connection, master_id: int, day: str) -> None:
    if conn.postgres:
        conn.execute("SELECT pg_advisory_xact_lock(hashtext(?))", (f"booking:{master_id}:{day}",))


def render_home(user):
    with db() as conn:
        services = conn.execute("SELECT * FROM booking_services WHERE active=1 ORDER BY name").fetchall()
    cards = "".join(f'<article class="card"><h3>{esc(row["name"])}</h3><p>{row["duration_minutes"]} минут</p><b>{int(row["price"]):,} ₽</b></article>'.replace(",", " ") for row in services)
    body = f'''<div class="notice"><b>Учебный проект.</b> Не вводите настоящие персональные данные. Для проверки используйте вымышленные имя, телефон и почту.</div><section class="panel"><div class="meta">Студия маникюра и бровей в Москве</div><h1>Красивые ногти — в удобное время</h1><p>Выберите услугу, мастера и реальное свободное время. Запись сохранится в личном кабинете.</p><a class="button" href="/book">Записаться онлайн →</a></section><section class="grid">{cards}</section>'''
    return page("Главная", body, user)


def render_auth(kind: str, error: str = ""):
    register = kind == "register"
    fields = '<label>Имя</label><input name="full_name" required><label>Телефон</label><input name="phone" placeholder="+7 000 000-00-00" required>' if register else ""
    fields += '<label>Email</label><input type="email" name="email" required><label>Пароль</label><input type="password" name="password" minlength="8" required>'
    label = "Зарегистрироваться" if register else "Войти"
    return page(label, f'<section class="panel"><h2>{label}</h2>{f"<p class=error>{esc(error)}</p>" if error else ""}<form method="post">{fields}<p><button>{label}</button></p></form><p><a class="button secondary" href="/auth/yandex">Войти через Яндекс</a></p></section>')


def render_book(user, values=None, error=""):
    values = values or {}
    with db() as conn:
        services, masters = active_catalog(conn)
        service_code = values.get("service_code") or (services[0]["code"] if services else "")
        master_id = int(values.get("master_id") or (masters[0]["id"] if masters else 0))
        day = values.get("appointment_date") or (date.today() + timedelta(days=1)).isoformat()
        slots = available_slots(conn, service_code, master_id, day) if master_id else []
    service_options = "".join(f'<option value="{esc(row["code"])}" {"selected" if row["code"] == service_code else ""}>{esc(row["name"])} — {row["duration_minutes"]} мин — {int(row["price"]):,} ₽</option>'.replace(",", " ") for row in services)
    master_options = "".join(f'<option value="{row["id"]}" {"selected" if row["id"] == master_id else ""}>{esc(row["name"])}</option>' for row in masters)
    slot_options = "".join(f'<option>{slot}</option>' for slot in slots) or '<option value="">Нет свободных слотов</option>'
    body = f'''<section class="panel"><h2>Запись в студию</h2>{f'<p class="error">{esc(error)}</p>' if error else ''}<form method="get" class="row"><div><label>Услуга</label><select name="service_code">{service_options}</select></div><div><label>Мастер</label><select name="master_id">{master_options}</select></div><div><label>Дата</label><input type="date" name="appointment_date" min="{date.today().isoformat()}" value="{esc(day)}" required></div><div><button>Показать свободное время</button></div></form><form method="post"><input type="hidden" name="service_code" value="{esc(service_code)}"><input type="hidden" name="master_id" value="{master_id}"><input type="hidden" name="appointment_date" value="{esc(day)}"><label>Свободное время</label><select name="start_time" required>{slot_options}</select><p><button>Подтвердить запись →</button></p></form></section>'''
    return page("Запись", body, user)


def appointment_rows(rows, admin=False) -> str:
    if not rows:
        return '<tr><td colspan="6">Записей пока нет</td></tr>'
    result = ""
    for row in rows:
        actions = f'''<td><form class="inline" method="post" action="/admin/appointment"><input type="hidden" name="id" value="{row["id"]}"><input type="hidden" name="action" value="cancel"><button class="danger">Отменить</button></form> <a class="button secondary" href="/admin/appointment?id={row["id"]}">Перенести</a></td>''' if admin else ""
        status = "Активна" if row["status"] == "active" else "Отменена"
        result += f'<tr class="{"muted" if row["status"] != "active" else ""}"><td>№{row["id"]}</td><td>{esc(row["service_name"])}</td><td>{esc(row["master_name"])}</td><td>{esc(row["appointment_date"])}, {esc(row["start_time"])}</td><td>{status}</td>{actions}</tr>'
    return result


def exchange_yandex(code: str) -> dict:
    payload = urlencode({"grant_type": "authorization_code", "code": code, "client_id": YANDEX_CLIENT_ID, "client_secret": YANDEX_CLIENT_SECRET}).encode()
    with urlopen(Request("https://oauth.yandex.ru/token", data=payload, headers={"Content-Type": "application/x-www-form-urlencoded"}), timeout=15) as response:
        token = json.load(response)["access_token"]
    with urlopen(Request("https://login.yandex.ru/info?format=json", headers={"Authorization": f"OAuth {token}"}), timeout=15) as response:
        return json.load(response)


def require_admin(user):
    if not user or user["role"] != "admin":
        return page("Доступ закрыт", '<section class="panel"><h2>Раздел доступен только сотрудникам студии</h2><p>У вашей учётной записи нет прав администратора.</p></section>', user, "403 Forbidden")
    return None


def application(environ, start_response: Callable):
    init_db()
    method, path = environ.get("REQUEST_METHOD", "GET"), environ.get("PATH_INFO", "/")
    user = current_user(environ)
    try:
        if path == "/" and method == "GET":
            result = render_home(user)
        elif path == "/register":
            if method == "GET":
                result = render_auth("register")
            else:
                data = form_data(environ); email, password = data.get("email", "").strip().lower(), data.get("password", "")
                if "@" not in email or len(password) < 8 or not data.get("full_name", "").strip():
                    result = render_auth("register", "Заполните имя, email и пароль не короче 8 символов")
                else:
                    salt, digest = password_hash(password)
                    try:
                        with db() as conn:
                            user_id = insert_id(conn, "INSERT INTO booking_users(email,full_name,phone,password_salt,password_hash) VALUES(?,?,?,?,?)", (email, data["full_name"].strip(), data.get("phone", ""), salt, digest))
                        result = redirect("/book", issue_session(user_id))
                    except Exception as exc:
                        if "unique" not in str(exc).lower(): raise
                        result = render_auth("register", "Пользователь с таким email уже существует")
        elif path == "/login":
            if method == "GET": result = render_auth("login")
            else:
                data = form_data(environ)
                with db() as conn: found = conn.execute("SELECT * FROM booking_users WHERE email=?", (data.get("email", "").strip().lower(),)).fetchone()
                ok = bool(found and found["password_hash"] and hmac.compare_digest(password_hash(data.get("password", ""), found["password_salt"])[1], found["password_hash"]))
                result = redirect("/admin" if ok and found["role"] == "admin" else "/cabinet", issue_session(found["id"])) if ok else render_auth("login", "Неверный email или пароль")
        elif path == "/logout":
            result = redirect("/", "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
        elif path == "/book":
            if not user: result = redirect("/login")
            elif method == "GET": result = render_book(user, query_data(environ))
            else:
                data = form_data(environ)
                try: master_id = int(data.get("master_id", "0"))
                except ValueError: master_id = 0
                code, day, start = data.get("service_code", ""), data.get("appointment_date", ""), data.get("start_time", "")
                with db() as conn:
                    lock_booking_day(conn, master_id, day)
                    service = conn.execute("SELECT * FROM booking_services WHERE code=? AND active=1", (code,)).fetchone()
                    master = conn.execute("SELECT * FROM booking_masters WHERE id=? AND active=1", (master_id,)).fetchone()
                    if not service or not master or start not in available_slots(conn, code, master_id, day): raise ValueError("Этот слот уже занят или недоступен. Выберите другое время.")
                    appointment_id = insert_id(conn, "INSERT INTO booking_appointments(user_id,service_code,master_id,appointment_date,start_time,duration_minutes,service_name,master_name,status,updated_at) VALUES(?,?,?,?,?,?,?,?,'active',CURRENT_TIMESTAMP)", (user["id"], code, master_id, day, start, service["duration_minutes"], service["name"], master["name"]))
                result = redirect(f"/confirmation?id={appointment_id}")
        elif path == "/confirmation":
            if not user: result = redirect("/login")
            else:
                appointment_id = int(query_data(environ).get("id", "0"))
                with db() as conn: row = conn.execute("SELECT * FROM booking_appointments WHERE id=? AND user_id=?", (appointment_id, user["id"])).fetchone()
                result = page("Подтверждение", f'<section class="panel"><h2>Вы записаны!</h2><p>Ждём вас в студии.</p><h3>Детали вашей записи</h3><p>Услуга: {esc(row["service_name"])}<br>Мастер: {esc(row["master_name"])}<br>Когда: {esc(row["appointment_date"])}, {esc(row["start_time"])}</p><a class="button secondary" href="/cabinet">Открыть кабинет</a></section>', user) if row else page("Не найдено", '<section class="panel"><h2>Запись не найдена</h2></section>', user, "404 Not Found")
        elif path == "/appointment":
            if not user: result = redirect("/login")
            else:
                appointment_id = int(query_data(environ).get("id", "0"))
                with db() as conn: row = conn.execute("SELECT * FROM booking_appointments WHERE id=? AND user_id=?", (appointment_id, user["id"])).fetchone()
                result = page("Запись", f'<section class="panel"><h2>Запись №{row["id"]}</h2><p>{esc(row["service_name"])} · {esc(row["master_name"])} · {esc(row["appointment_date"])}, {esc(row["start_time"])} · {esc(row["status"])}</p></section>', user) if row else page("Не найдено", '<section class="panel"><h2>Запись не найдена</h2></section>', user, "404 Not Found")
        elif path == "/cabinet":
            if not user: result = redirect("/login")
            else:
                with db() as conn: rows = conn.execute("SELECT * FROM booking_appointments WHERE user_id=? ORDER BY appointment_date,start_time", (user["id"],)).fetchall()
                result = page("Мои записи", f'<section class="panel"><h2>Мои записи</h2><table><tr><th>Номер</th><th>Услуга</th><th>Мастер</th><th>Дата и время</th><th>Статус</th></tr>{appointment_rows(rows)}</table></section>', user)
        elif path == "/admin":
            denied = require_admin(user)
            if denied: result = denied
            else:
                with db() as conn:
                    rows = conn.execute("SELECT a.*,u.full_name,u.email FROM booking_appointments a JOIN booking_users u ON u.id=a.user_id ORDER BY appointment_date,start_time").fetchall()
                    blocks = conn.execute("SELECT b.*,m.name master_name FROM booking_blocks b JOIN booking_masters m ON m.id=b.master_id ORDER BY block_date,start_time").fetchall()
                    masters = conn.execute("SELECT * FROM booking_masters WHERE active=1 ORDER BY name").fetchall()
                options = "".join(f'<option value="{row["id"]}">{esc(row["name"])}</option>' for row in masters)
                block_rows = "".join(f'<li>{esc(row["block_date"])}, {esc(row["start_time"])}–{esc(row["end_time"])} · {esc(row["master_name"])} · {esc(row["reason"])}</li>' for row in blocks) or "<li>Блокировок нет</li>"
                body = f'''<section class="panel"><h2>Все записи</h2><table><tr><th>Номер</th><th>Услуга</th><th>Мастер</th><th>Дата и время</th><th>Статус</th><th>Действия</th></tr>{appointment_rows(rows, True)}</table></section><section class="panel"><h2>Заблокировать время</h2><form method="post" action="/admin/block" class="row"><div><label>Мастер</label><select name="master_id">{options}</select></div><div><label>Дата</label><input type="date" name="block_date" required></div><div><label>Начало</label><input type="time" name="start_time" required></div><div><label>Конец</label><input type="time" name="end_time" required></div><div><label>Причина</label><input name="reason" value="Перерыв"></div><div><button>Заблокировать</button></div></form><ul>{block_rows}</ul></section>'''
                result = page("Админка", body, user)
        elif path == "/admin/appointment":
            denied = require_admin(user)
            if denied: result = denied
            elif method == "GET":
                appointment_id = int(query_data(environ).get("id", "0"))
                with db() as conn:
                    row = conn.execute("SELECT * FROM booking_appointments WHERE id=?", (appointment_id,)).fetchone(); services, masters = active_catalog(conn)
                if not row: result = page("Не найдено", '<section class="panel"><h2>Запись не найдена</h2></section>', user, "404 Not Found")
                else:
                    service_options = "".join(f'<option value="{esc(x["code"])}" {"selected" if x["code"] == row["service_code"] else ""}>{esc(x["name"])}</option>' for x in services)
                    master_options = "".join(f'<option value="{x["id"]}" {"selected" if x["id"] == row["master_id"] else ""}>{esc(x["name"])}</option>' for x in masters)
                    result = page("Перенос", f'''<section class="panel"><h2>Перенести запись №{row["id"]}</h2><form method="post"><input type="hidden" name="id" value="{row["id"]}"><input type="hidden" name="action" value="move"><label>Услуга</label><select name="service_code">{service_options}</select><label>Мастер</label><select name="master_id">{master_options}</select><label>Дата</label><input type="date" name="appointment_date" value="{esc(row["appointment_date"])}" required><label>Время</label><input type="time" name="start_time" value="{esc(row["start_time"])}" required><p><button>Сохранить перенос</button></p></form></section>''', user)
            else:
                data = form_data(environ); appointment_id = int(data.get("id", "0"))
                if data.get("action") == "cancel":
                    with db() as conn: conn.execute("UPDATE booking_appointments SET status='cancelled',updated_at=CURRENT_TIMESTAMP WHERE id=?", (appointment_id,))
                else:
                    master_id, code, day, start = int(data.get("master_id", "0")), data.get("service_code", ""), data.get("appointment_date", ""), data.get("start_time", "")
                    with db() as conn:
                        lock_booking_day(conn, master_id, day)
                        row = conn.execute("SELECT * FROM booking_appointments WHERE id=?", (appointment_id,)).fetchone(); service = conn.execute("SELECT * FROM booking_services WHERE code=? AND active=1", (code,)).fetchone(); master = conn.execute("SELECT * FROM booking_masters WHERE id=? AND active=1", (master_id,)).fetchone()
                        if not row or not service or not master or start not in available_slots(conn, code, master_id, day, appointment_id): raise ValueError("Новое время недоступно")
                        conn.execute("UPDATE booking_appointments SET service_code=?,master_id=?,appointment_date=?,start_time=?,duration_minutes=?,service_name=?,master_name=?,status='active',updated_at=CURRENT_TIMESTAMP WHERE id=?", (code, master_id, day, start, service["duration_minutes"], service["name"], master["name"], appointment_id))
                result = redirect("/admin")
        elif path == "/admin/block" and method == "POST":
            denied = require_admin(user)
            if denied: result = denied
            else:
                data = form_data(environ)
                if parse_clock(data["start_time"]) >= parse_clock(data["end_time"]): raise ValueError("Время окончания должно быть позже начала")
                with db() as conn: conn.execute("INSERT INTO booking_blocks(master_id,block_date,start_time,end_time,reason) VALUES(?,?,?,?,?)", (int(data["master_id"]), data["block_date"], data["start_time"], data["end_time"], data.get("reason", "")))
                result = redirect("/admin")
        elif path == "/admin/catalog":
            denied = require_admin(user)
            if denied: result = denied
            elif method == "POST":
                data = form_data(environ)
                with db() as conn:
                    if data.get("entity") == "service":
                        code = data.get("code", "").strip().lower(); existing = conn.execute("SELECT code FROM booking_services WHERE code=?", (code,)).fetchone()
                        if existing: conn.execute("UPDATE booking_services SET name=?,duration_minutes=?,price=?,active=? WHERE code=?", (data["name"], int(data["duration_minutes"]), int(data["price"]), int(data.get("active", "0")), code))
                        else: conn.execute("INSERT INTO booking_services(code,name,duration_minutes,price,active) VALUES(?,?,?,?,1)", (code, data["name"], int(data["duration_minutes"]), int(data["price"])))
                    else:
                        master_id = int(data.get("id", "0"))
                        if master_id: conn.execute("UPDATE booking_masters SET name=?,active=? WHERE id=?", (data["name"], int(data.get("active", "0")), master_id))
                        else:
                            new_id = insert_id(conn, "INSERT INTO booking_masters(name,active) VALUES(?,1)", (data["name"],))
                            for weekday in range(6): conn.execute("INSERT INTO booking_schedules(master_id,weekday,work_start,work_end) VALUES(?,?,?,?)", (new_id, weekday, "10:00", "19:00"))
                result = redirect("/admin/catalog")
            else:
                with db() as conn: services = conn.execute("SELECT * FROM booking_services ORDER BY name").fetchall(); masters = conn.execute("SELECT * FROM booking_masters ORDER BY name").fetchall()
                service_cards = "".join(f'''<form method="post" class="card"><input type="hidden" name="entity" value="service"><label>Код</label><input name="code" value="{esc(row["code"])}" readonly><label>Название</label><input name="name" value="{esc(row["name"])}"><label>Длительность, мин</label><input type="number" name="duration_minutes" value="{row["duration_minutes"]}"><label>Цена, ₽</label><input type="number" name="price" value="{row["price"]}"><label><input type="checkbox" name="active" value="1" {"checked" if row["active"] else ""}> Активна</label><button>Сохранить</button></form>''' for row in services)
                master_cards = "".join(f'''<form method="post" class="card"><input type="hidden" name="entity" value="master"><input type="hidden" name="id" value="{row["id"]}"><label>Имя</label><input name="name" value="{esc(row["name"])}"><label><input type="checkbox" name="active" value="1" {"checked" if row["active"] else ""}> Активен</label><button>Сохранить</button></form>''' for row in masters)
                body = f'''<section class="panel"><h2>Услуги</h2><div class="grid">{service_cards}</div><h3>Добавить услугу</h3><form method="post" class="row"><input type="hidden" name="entity" value="service"><div><label>Код</label><input name="code" required></div><div><label>Название</label><input name="name" required></div><div><label>Минут</label><input type="number" name="duration_minutes" required></div><div><label>Цена</label><input type="number" name="price" required></div><div><button>Добавить</button></div></form></section><section class="panel"><h2>Мастера</h2><div class="grid">{master_cards}</div><h3>Добавить мастера</h3><form method="post" class="row"><input type="hidden" name="entity" value="master"><div><label>Имя</label><input name="name" required></div><div><button>Добавить</button></div></form></section>'''
                result = page("Услуги и мастера", body, user)
        elif path == "/auth/yandex":
            if not YANDEX_CLIENT_ID or not YANDEX_CLIENT_SECRET: result = page("Яндекс", '<section class="panel"><h2>Вход через Яндекс пока не настроен</h2></section>', user, "503 Service Unavailable")
            else:
                state = secrets.token_urlsafe(24)
                with db() as conn: conn.execute("INSERT INTO booking_oauth_states(state_hash) VALUES(?)", (hashlib.sha256(state.encode()).hexdigest(),))
                result = redirect("https://oauth.yandex.ru/authorize?" + urlencode({"response_type": "code", "client_id": YANDEX_CLIENT_ID, "redirect_uri": f"{BASE_URL}/auth/yandex/callback", "state": state}))
        elif path == "/auth/yandex/callback":
            params = query_data(environ); state_hash = hashlib.sha256(params.get("state", "").encode()).hexdigest()
            with db() as conn:
                state_row = conn.execute("SELECT state_hash FROM booking_oauth_states WHERE state_hash=?", (state_hash,)).fetchone()
                if state_row: conn.execute("DELETE FROM booking_oauth_states WHERE state_hash=?", (state_hash,))
            if not state_row or not params.get("code"): result = page("Ошибка входа", '<section class="panel"><h2>Не удалось проверить вход через Яндекс</h2></section>', None, "400 Bad Request")
            else:
                info = exchange_yandex(params["code"]); provider_id = str(info["id"]); email = (info.get("default_email") or f'{info.get("login", provider_id)}@yandex.local').lower(); name = info.get("real_name") or info.get("display_name") or info.get("login") or "Пользователь Яндекса"
                with db() as conn:
                    found = conn.execute("SELECT * FROM booking_users WHERE provider='yandex' AND provider_user_id=?", (provider_id,)).fetchone()
                    if not found:
                        found = conn.execute("SELECT * FROM booking_users WHERE email=?", (email,)).fetchone()
                        if found: conn.execute("UPDATE booking_users SET provider='yandex',provider_user_id=? WHERE id=?", (provider_id, found["id"]))
                        else:
                            user_id = insert_id(conn, "INSERT INTO booking_users(email,full_name,role,provider,provider_user_id) VALUES(?,?,'client','yandex',?)", (email, name, provider_id)); found = conn.execute("SELECT * FROM booking_users WHERE id=?", (user_id,)).fetchone()
                result = redirect("/cabinet", issue_session(found["id"]))
        else:
            result = page("Не найдено", '<section class="panel"><h2>Страница не найдена</h2></section>', user, "404 Not Found")
    except ValueError as exc:
        result = page("Некорректные данные", f'<section class="panel"><h2>Не удалось выполнить действие</h2><p>{esc(exc)}</p></section>', user, "400 Bad Request")
    except Exception:
        if os.getenv("APP_DEBUG") == "1": raise
        result = page("Ошибка", '<section class="panel"><h2>Сервис временно недоступен</h2><p>Попробуйте ещё раз или сообщите администратору.</p></section>', user, "500 Internal Server Error")
    status, headers, body = result
    headers.append(("Content-Length", str(len(body))))
    start_response(status, headers)
    return [body]


if __name__ == "__main__":
    init_db()
    print("http://127.0.0.1:8000")
    make_server("127.0.0.1", 8000, application).serve_forever()

app = application
