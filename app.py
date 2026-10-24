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

SERVICES = {
    "gel": ("Маникюр с покрытием", 120, 2400),
    "brows": ("Коррекция и окрашивание бровей", 60, 1200),
    "lamination": ("Ламинирование бровей", 60, 1800),
}
MASTERS = {1: "Анна Власова", 2: "Мария Белова", 3: "София Ли"}


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
            self.raw = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        else:
            DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            self.raw = sqlite3.connect(DB_PATH)
            self.raw.row_factory = sqlite3.Row
            self.raw.execute("PRAGMA foreign_keys=ON")

    def execute(self, sql, params=()):
        if self.postgres:
            sql = sql.replace("?", "%s")
        return self.raw.execute(sql, params)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.raw.commit()
        else:
            self.raw.rollback()
        self.raw.close()


def db() -> Connection:
    return Connection()


def insert_id(conn: Connection, sql: str, params: tuple) -> int:
    if conn.postgres:
        return conn.execute(sql + " RETURNING id", params).fetchone()["id"]
    return conn.execute(sql, params).lastrowid


def init_db() -> None:
    with db() as conn:
        id_type = "BIGSERIAL PRIMARY KEY" if conn.postgres else "INTEGER PRIMARY KEY"
        user_id_type = "BIGINT" if conn.postgres else "INTEGER"
        statements = [f"""CREATE TABLE IF NOT EXISTS users(
          id {id_type}, email TEXT NOT NULL UNIQUE, full_name TEXT NOT NULL,
          phone TEXT, password_salt TEXT, password_hash TEXT,
          role TEXT NOT NULL DEFAULT 'client' CHECK(role IN ('client','admin')),
          provider TEXT, provider_user_id TEXT,
          UNIQUE(provider, provider_user_id)
        )""", f"""CREATE TABLE IF NOT EXISTS sessions(
          token_hash TEXT PRIMARY KEY, user_id {user_id_type} NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""", """CREATE TABLE IF NOT EXISTS oauth_states(
          state_hash TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""", f"""CREATE TABLE IF NOT EXISTS appointments(
          id {id_type}, user_id {user_id_type} NOT NULL REFERENCES users(id),
          service_code TEXT NOT NULL, master_id INTEGER NOT NULL,
          appointment_date TEXT NOT NULL, start_time TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(master_id, appointment_date, start_time)
        )"""]
        for statement in statements:
            conn.execute(statement)
        admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
        admin_password = os.getenv("ADMIN_PASSWORD", "")
        if admin_email and admin_password:
            row = conn.execute("SELECT id FROM users WHERE email=?", (admin_email,)).fetchone()
            if row:
                conn.execute("UPDATE users SET role='admin' WHERE id=?", (row["id"],))
            else:
                salt, digest = password_hash(admin_password)
                conn.execute("INSERT INTO users(email,full_name,password_salt,password_hash,role) VALUES(?,?,?,?, 'admin')",
                             (admin_email, "Администратор", salt, digest))


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


STYLE = """
*{box-sizing:border-box}body{margin:0;background:#fffaf7;color:#2e2435;font:16px/1.5 Inter,system-ui,sans-serif}
a{color:#52367f}.wrap{width:min(980px,calc(100% - 32px));margin:auto}.top{display:flex;justify-content:space-between;align-items:center;padding:22px 0}.brand{font-size:21px;font-weight:800}.notice{background:#fff0c7;border:1px solid #ecd17b;padding:12px 16px;border-radius:12px;margin-bottom:22px}.panel{background:#fff;border:1px solid #e9dfe7;border-radius:22px;padding:28px;box-shadow:0 12px 35px #4b316414;margin:22px 0}h1{font-size:42px;line-height:1.05}h2{margin-top:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}.card{border:1px solid #e9dfe7;border-radius:16px;padding:18px}.button,button{display:inline-block;border:0;border-radius:12px;padding:12px 18px;background:#7051a8;color:#fff;text-decoration:none;font-weight:700;cursor:pointer}.secondary{background:#fff;color:#52367f;border:1px solid #d7cadc}label{display:block;font-weight:700;margin:14px 0 5px}input,select{width:100%;padding:11px;border:1px solid #d7cadc;border-radius:10px;font:inherit}.error{color:#9f2635}.success{color:#176f46}.meta{color:#766b79;font-size:14px}table{width:100%;border-collapse:collapse}th,td{padding:11px;border-bottom:1px solid #e9dfe7;text-align:left}.nav a{margin-left:14px}@media(max-width:600px){h1{font-size:34px}.top{align-items:flex-start}.nav a{display:block;margin:3px 0}}
"""


def page(title: str, body: str, user: sqlite3.Row | None = None, status: str = "200 OK"):
    nav = '<a href="/">Главная</a>'
    if user:
        nav += ' <a href="/book">Записаться</a> <a href="/cabinet">Мои записи</a>'
        if user["role"] == "admin": nav += ' <a href="/admin">Админка</a>'
        nav += ' <a href="/logout">Выйти</a>'
    else:
        nav += ' <a href="/login">Войти</a> <a href="/register">Регистрация</a>'
    doc = f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} — Ноготочки</title><style>{STYLE}</style></head><body><div class="wrap"><header class="top"><div class="brand">✦ Ноготочки</div><nav class="nav">{nav}</nav></header>{body}</div></body></html>'''
    return status, [("Content-Type", "text/html; charset=utf-8")], doc.encode()


def redirect(location: str, cookie: str | None = None):
    headers = [("Location", location), ("Content-Length", "0")]
    if cookie: headers.append(("Set-Cookie", cookie))
    return "303 See Other", headers, b""


def form_data(environ) -> dict[str, str]:
    raw = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0)).decode()
    return {k: v[0] for k, v in parse_qs(raw).items()}


def query_data(environ) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(environ.get("QUERY_STRING", "")).items()}


def current_user(environ) -> sqlite3.Row | None:
    cookies = SimpleCookie(environ.get("HTTP_COOKIE", ""))
    token = cookies.get("session")
    if not token: return None
    token_hash = hashlib.sha256(token.value.encode()).hexdigest()
    with db() as conn:
        return conn.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?", (token_hash,)).fetchone()


def issue_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute("INSERT INTO sessions(token_hash,user_id) VALUES(?,?)", (hashlib.sha256(token.encode()).hexdigest(), user_id))
    secure = "; Secure" if BASE_URL.startswith("https://") else ""
    return f"session={token}; Path=/; HttpOnly; SameSite=Lax{secure}"


def render_home(user):
    body = '''<div class="notice"><b>Учебный проект.</b> Не вводите настоящие персональные данные. Для проверки используйте вымышленные имя, телефон и почту.</div><section class="panel"><div class="meta">Маникюрная студия в Москве</div><h1>Красивые ногти — в удобное время</h1><p>Зарегистрируйтесь, выберите услугу, мастера и свободное время. Запись сохранится в личном кабинете.</p><a class="button" href="/book">Записаться онлайн →</a></section><section class="grid">'''
    for code, (name, duration, price) in SERVICES.items():
        body += f'<article class="card"><h3>{esc(name)}</h3><p>{duration} минут</p><b>{price:,} ₽</b></article>'.replace(",", " ")
    body += "</section>"
    return page("Главная", body, user)


def render_auth(kind: str, error: str = ""):
    is_register = kind == "register"
    fields = ''
    if is_register:
        fields += '<label>Имя</label><input name="full_name" required><label>Телефон</label><input name="phone" placeholder="+7 000 000-00-00" required>'
    fields += '<label>Email</label><input type="email" name="email" required><label>Пароль</label><input type="password" name="password" minlength="8" required>'
    label = "Зарегистрироваться" if is_register else "Войти"
    body = f'<section class="panel"><h2>{label}</h2>{f"<p class=error>{esc(error)}</p>" if error else ""}<form method="post">{fields}<p><button>{label}</button></p></form><p><a class="button secondary" href="/auth/yandex">Войти через Яндекс</a></p></section>'
    return page(label, body)


def render_book(user, error=""):
    services = "".join(f'<option value="{code}">{esc(name)} — {price} ₽</option>' for code, (name, _, price) in SERVICES.items())
    masters = "".join(f'<option value="{mid}">{esc(name)}</option>' for mid, name in MASTERS.items())
    tomorrow = (date.today() + timedelta(days=1)).isoformat()
    body = f'''<section class="panel"><h2>Запись в студию</h2>{f'<p class="error">{esc(error)}</p>' if error else ''}<form method="post"><label>Услуга</label><select name="service_code">{services}</select><label>Мастер</label><select name="master_id">{masters}</select><label>Дата</label><input type="date" name="appointment_date" min="{tomorrow}" required><label>Время</label><select name="start_time"><option>10:00</option><option>12:30</option><option>15:00</option><option>17:30</option></select><p><button>Подтвердить запись →</button></p></form></section>'''
    return page("Запись", body, user)


def appointment_rows(rows) -> str:
    result = ""
    for row in rows:
        service = SERVICES[row["service_code"]][0]
        result += f'<tr><td>№{row["id"]}</td><td>{esc(service)}</td><td>{esc(MASTERS[row["master_id"]])}</td><td>{esc(row["appointment_date"])}, {esc(row["start_time"])}</td></tr>'
    return result or '<tr><td colspan="4">Записей пока нет</td></tr>'


def exchange_yandex(code: str) -> dict:
    token_payload = urlencode({"grant_type": "authorization_code", "code": code, "client_id": YANDEX_CLIENT_ID, "client_secret": YANDEX_CLIENT_SECRET}).encode()
    token_req = Request("https://oauth.yandex.ru/token", data=token_payload, headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urlopen(token_req, timeout=15) as response:
        token = json.load(response)["access_token"]
    info_req = Request("https://login.yandex.ru/info?format=json", headers={"Authorization": f"OAuth {token}"})
    with urlopen(info_req, timeout=15) as response:
        return json.load(response)


def application(environ, start_response: Callable):
    init_db()
    method, path = environ.get("REQUEST_METHOD", "GET"), environ.get("PATH_INFO", "/")
    user = current_user(environ)
    try:
        if path == "/" and method == "GET": result = render_home(user)
        elif path == "/register":
            if method == "GET": result = render_auth("register")
            else:
                data = form_data(environ); email = data.get("email", "").strip().lower(); password = data.get("password", "")
                if "@" not in email or len(password) < 8 or not data.get("full_name", "").strip(): result = render_auth("register", "Заполните имя, email и пароль не короче 8 символов")
                else:
                    salt, digest = password_hash(password)
                    try:
                        with db() as conn:
                            user_id = insert_id(conn, "INSERT INTO users(email,full_name,phone,password_salt,password_hash) VALUES(?,?,?,?,?)", (email, data["full_name"].strip(), data.get("phone", ""), salt, digest))
                        result = redirect("/book", issue_session(user_id))
                    except Exception as exc:
                        if "unique" not in str(exc).lower(): raise
                        result = render_auth("register", "Пользователь с таким email уже существует")
        elif path == "/login":
            if method == "GET": result = render_auth("login")
            else:
                data = form_data(environ)
                with db() as conn: found = conn.execute("SELECT * FROM users WHERE email=?", (data.get("email", "").strip().lower(),)).fetchone()
                ok = bool(found and found["password_hash"] and hmac.compare_digest(password_hash(data.get("password", ""), found["password_salt"])[1], found["password_hash"]))
                result = redirect("/cabinet", issue_session(found["id"])) if ok else render_auth("login", "Неверный email или пароль")
        elif path == "/logout": result = redirect("/", "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
        elif path == "/book":
            if not user: result = redirect("/login")
            elif method == "GET": result = render_book(user)
            else:
                data = form_data(environ); code = data.get("service_code", ""); mid = int(data.get("master_id", "0")); day = data.get("appointment_date", ""); start = data.get("start_time", "")
                if code not in SERVICES or mid not in MASTERS or start not in {"10:00","12:30","15:00","17:30"}: result = render_book(user, "Некорректные данные записи")
                else:
                    try:
                        datetime.strptime(day, "%Y-%m-%d")
                        with db() as conn: appointment_id = insert_id(conn, "INSERT INTO appointments(user_id,service_code,master_id,appointment_date,start_time) VALUES(?,?,?,?,?)", (user["id"], code, mid, day, start))
                        result = redirect(f"/confirmation?id={appointment_id}")
                    except Exception as exc:
                        if not isinstance(exc, ValueError) and "unique" not in str(exc).lower(): raise
                        result = render_book(user, "Это время уже занято или дата указана неверно")
        elif path == "/confirmation":
            if not user: result = redirect("/login")
            else:
                appointment_id = int(query_data(environ).get("id", "0"))
                with db() as conn: row = conn.execute("SELECT * FROM appointments WHERE id=? AND user_id=?", (appointment_id, user["id"])).fetchone()
                if not row: result = page("Не найдено", '<section class="panel"><h2>Запись не найдена</h2></section>', user, "404 Not Found")
                else:
                    service = SERVICES[row["service_code"]]
                    text = f'''<section class="panel"><h2>Вы записаны!</h2><p>Ждём вас в студии.</p><h3>Детали вашей записи</h3><p>Услуга: {esc(service[0])}<br>Стоимость: {service[2]:,} ₽<br>Мастер: {esc(MASTERS[row["master_id"]])}<br>Когда: {esc(row["appointment_date"])}, {esc(row["start_time"])}</p><a class="button secondary" href="/cabinet">Открыть кабинет</a></section>'''.replace(",", " ")
                    result = page("Подтверждение", text, user)
        elif path == "/cabinet":
            if not user: result = redirect("/login")
            else:
                with db() as conn: rows = conn.execute("SELECT * FROM appointments WHERE user_id=? ORDER BY appointment_date,start_time", (user["id"],)).fetchall()
                result = page("Мои записи", f'<section class="panel"><h2>Мои записи</h2><table><tr><th>Номер</th><th>Услуга</th><th>Мастер</th><th>Дата и время</th></tr>{appointment_rows(rows)}</table></section>', user)
        elif path == "/admin":
            if not user: result = page("Доступ закрыт", '<section class="panel"><h2>Раздел доступен только сотрудникам студии</h2><p>Войдите с учётной записью администратора.</p></section>', None, "403 Forbidden")
            elif user["role"] != "admin": result = page("Доступ закрыт", '<section class="panel"><h2>Раздел доступен только сотрудникам студии</h2><p>У вашей учётной записи нет прав администратора.</p></section>', user, "403 Forbidden")
            else:
                with db() as conn: rows = conn.execute("SELECT a.*,u.full_name,u.email FROM appointments a JOIN users u ON u.id=a.user_id ORDER BY appointment_date,start_time").fetchall()
                result = page("Админка", f'<section class="panel"><h2>Все записи</h2><table><tr><th>Номер</th><th>Услуга</th><th>Мастер</th><th>Дата и время</th></tr>{appointment_rows(rows)}</table></section>', user)
        elif path == "/auth/yandex":
            if not YANDEX_CLIENT_ID or not YANDEX_CLIENT_SECRET: result = page("Яндекс", '<section class="panel"><h2>Вход через Яндекс пока не настроен</h2><p>Добавьте YANDEX_CLIENT_ID и YANDEX_CLIENT_SECRET в переменные окружения.</p></section>', user, "503 Service Unavailable")
            else:
                state = secrets.token_urlsafe(24)
                with db() as conn: conn.execute("INSERT INTO oauth_states(state_hash) VALUES(?)", (hashlib.sha256(state.encode()).hexdigest(),))
                params = urlencode({"response_type":"code","client_id":YANDEX_CLIENT_ID,"redirect_uri":f"{BASE_URL}/auth/yandex/callback","state":state})
                result = redirect(f"https://oauth.yandex.ru/authorize?{params}")
        elif path == "/auth/yandex/callback":
            params = query_data(environ); state_hash = hashlib.sha256(params.get("state", "").encode()).hexdigest()
            with db() as conn:
                state_row = conn.execute("SELECT state_hash FROM oauth_states WHERE state_hash=?", (state_hash,)).fetchone()
                if state_row: conn.execute("DELETE FROM oauth_states WHERE state_hash=?", (state_hash,))
            if not state_row or not params.get("code"): result = page("Ошибка входа", '<section class="panel"><h2>Не удалось проверить вход через Яндекс</h2></section>', None, "400 Bad Request")
            else:
                info = exchange_yandex(params["code"]); provider_id = str(info["id"]); email = (info.get("default_email") or f'{info.get("login", provider_id)}@yandex.local').lower(); name = info.get("real_name") or info.get("display_name") or info.get("login") or "Пользователь Яндекса"
                with db() as conn:
                    found = conn.execute("SELECT * FROM users WHERE provider='yandex' AND provider_user_id=?", (provider_id,)).fetchone()
                    if not found:
                        found = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                        if found: conn.execute("UPDATE users SET provider='yandex',provider_user_id=? WHERE id=?", (provider_id, found["id"]))
                        else:
                            user_id = insert_id(conn, "INSERT INTO users(email,full_name,role,provider,provider_user_id) VALUES(?,?,'client','yandex',?)", (email, name, provider_id)); found = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
                result = redirect("/cabinet", issue_session(found["id"]))
        else: result = page("Не найдено", '<section class="panel"><h2>Страница не найдена</h2></section>', user, "404 Not Found")
    except Exception as exc:
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

# Vercel looks for a top-level WSGI callable named `app`.
app = application
