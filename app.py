"""Мини-сервис для проверки экранов: python app.py"""
from __future__ import annotations
import base64, hashlib, hmac, json, os, secrets, sqlite3
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from wsgiref.simple_server import make_server

ROOT = Path(__file__).parent
DB = ROOT / "service.sqlite"
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY", "")

def phash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    value = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 180000)
    return salt, base64.b64encode(value).decode()

def conn():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init():
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,salt TEXT NOT NULL,password_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY,name TEXT NOT NULL,description TEXT NOT NULL,duration_minutes INTEGER NOT NULL,price INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS appointments(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),service_id INTEGER NOT NULL REFERENCES services(id),master_name TEXT NOT NULL,appointment_date TEXT NOT NULL,start_time TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Подтверждена');
        CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,text TEXT NOT NULL);
        CREATE UNIQUE INDEX IF NOT EXISTS one_slot ON appointments(master_name,appointment_date,start_time) WHERE status='Подтверждена';
        """)
        if not c.execute("SELECT 1 FROM users WHERE email='demo@nogotochki.ru'").fetchone():
            salt, digest = phash("demo-pass")
            c.execute("INSERT INTO users(email,name,salt,password_hash) VALUES(?,?,?,?)", ("demo@nogotochki.ru","Наталья Демонстрационная",salt,digest))
            c.execute("INSERT INTO services(id,name,description,duration_minutes,price) VALUES(1,'Маникюр с покрытием','Форма, уход и стойкое покрытие',120,2400)")
            c.execute("INSERT INTO services(id,name,description,duration_minutes,price) VALUES(2,'Педикюр express','Быстрый уход и покрытие',90,2100)")
            c.execute("INSERT INTO services(id,name,description,duration_minutes,price) VALUES(3,'Укрепление ногтей','Укрепление и выравнивание',60,1300)")
            user_id = c.execute("SELECT id FROM users WHERE email='demo@nogotochki.ru'").fetchone()[0]
            c.execute("INSERT INTO appointments(user_id,service_id,master_name,appointment_date,start_time) VALUES(?,?,?,?,?)", (user_id,1,'Анна Власова','31 октября 2026','15:00'))
        if not c.execute("SELECT 1 FROM users WHERE email='admin@nogotochki.ru'").fetchone():
            salt,digest=phash('admin-pass');c.execute("INSERT INTO users(email,name,salt,password_hash) VALUES(?,?,?,?)",('admin@nogotochki.ru','Администратор',salt,digest))

def reply(start, code, data, content_type="application/json; charset=utf-8"):
    raw = json.dumps(data,ensure_ascii=False).encode() if isinstance(data,(dict,list)) else data
    start(code,[("Content-Type",content_type),("Content-Length",str(len(raw)))])
    return [raw]

def body(env):
    raw=env['wsgi.input'].read(int(env.get('CONTENT_LENGTH') or 0))
    return json.loads(raw or b'{}')

def current(env,c):
    h=env.get('HTTP_AUTHORIZATION','')
    if not h.startswith('Bearer '): return None
    return c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",(hashlib.sha256(h[7:].encode()).hexdigest(),)).fetchone()

def supabase(method, table, query=None, payload=None):
    """Минимальный клиент Supabase REST. Используется только на сервере Vercel."""
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        raise RuntimeError("Не настроено подключение к Supabase.")
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    if query:
        url += "?" + urlencode(query, doseq=True)
    raw = None if payload is None else json.dumps(payload, ensure_ascii=False).encode()
    request = Request(url, data=raw, method=method, headers={
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    })
    try:
        with urlopen(request, timeout=12) as response:
            return response.status, json.loads(response.read() or b"[]")
    except HTTPError as error:
        try: data = json.loads(error.read() or b"{}")
        except json.JSONDecodeError: data = {}
        return error.code, data

def cloud_user(env):
    header = env.get("HTTP_AUTHORIZATION", "")
    if not header.startswith("Bearer "): return None
    token_hash = hashlib.sha256(header[7:].encode()).hexdigest()
    _, sessions = supabase("GET", "sessions", {"select": "user_id", "token_hash": f"eq.{token_hash}"})
    if not sessions: return None
    _, users = supabase("GET", "users", {"select": "*", "id": f"eq.{sessions[0]['user_id']}"})
    return users[0] if users else None

def cloud_app(env, start):
    path, method = env["PATH_INFO"], env["REQUEST_METHOD"]
    try:
        if method == "GET" and path == "/api/services":
            _, rows = supabase("GET", "services", {"select": "id,name,description,duration_minutes,price", "order": "id"})
            return reply(start, "200 OK", rows)
        if method == "POST" and path == "/api/auth/register":
            d = body(env); email = d.get("email", "").strip().lower(); name = d.get("name", "").strip(); password = d.get("password", "")
            if "@" not in email or not name or not 8 <= len(password) <= 128:
                return reply(start, "400 Bad Request", {"error": "Введите имя, корректный email и пароль не короче 8 символов."})
            salt, digest = phash(password); status, _ = supabase("POST", "users", payload={"email": email, "name": name, "salt": salt, "password_hash": digest})
            return reply(start, "201 Created" if status < 300 else "409 Conflict", {"message": "Аккаунт создан."} if status < 300 else {"error": "Пользователь с таким email уже существует."})
        if method == "POST" and path == "/api/auth/login":
            d = body(env); _, users = supabase("GET", "users", {"select": "*", "email": f"eq.{str(d.get('email', '')).lower()}"})
            if not users: return reply(start, "401 Unauthorized", {"error": "Неверный email или пароль."})
            user = users[0]; _, digest = phash(str(d.get("password", "")), user["salt"])
            if not hmac.compare_digest(digest, user["password_hash"]): return reply(start, "401 Unauthorized", {"error": "Неверный email или пароль."})
            token = secrets.token_urlsafe(24); supabase("POST", "sessions", payload={"token_hash": hashlib.sha256(token.encode()).hexdigest(), "user_id": user["id"]})
            return reply(start, "200 OK", {"token": token, "name": user["name"]})
        if method == "GET" and path == "/api/cabinet/appointments":
            user = cloud_user(env)
            if not user: return reply(start, "401 Unauthorized", {"error": "Нужно войти в аккаунт."})
            _, rows = supabase("GET", "appointments", {"select": "id,service_id,master_name,appointment_date,start_time,status", "user_id": f"eq.{user['id']}", "order": "id"})
            _, services = supabase("GET", "services", {"select": "id,name,price"}); lookup = {x["id"]: x for x in services}
            for row in rows: row.update({"service_name": lookup[row["service_id"]]["name"], "price": lookup[row["service_id"]]["price"]})
            _, notes = supabase("GET", "notifications", {"select": "text", "user_id": f"eq.{user['id']}"})
            return reply(start, "200 OK", {"client": user["name"], "appointments": rows, "notifications": [x["text"] for x in notes]})
        if method == "POST" and path == "/api/appointments":
            user = cloud_user(env)
            if not user: return reply(start, "401 Unauthorized", {"error": "Нужно войти в аккаунт."})
            d = body(env); status, _ = supabase("POST", "appointments", payload={"user_id": user["id"], "service_id": 1, "master_name": "Анна Власова", "appointment_date": d.get("date", ""), "start_time": d.get("time", "")})
            return reply(start, "201 Created" if status < 300 else "409 Conflict", {"message": "Запись создана."} if status < 300 else {"error": "Этот слот уже занят. Выберите другое время."})
        if method == "GET" and path == "/api/admin/appointments":
            user = cloud_user(env)
            if not user or user["email"] != "admin@nogotochki.ru": return reply(start, "403 Forbidden", {"error": "Доступ только администратору."})
            _, rows = supabase("GET", "appointments", {"select": "*", "status": "eq.Подтверждена"})
            return reply(start, "200 OK", rows)
        if method == "GET" and (path.endswith(".html") or path.endswith(".css")):
            file = ROOT / "web" / path.lstrip("/")
            if file.is_file(): return reply(start, "200 OK", file.read_bytes(), "text/css; charset=utf-8" if path.endswith(".css") else "text/html; charset=utf-8")
        if method == "GET" and path == "/":
            return reply(start, "200 OK", (ROOT / "web/services.html").read_bytes(), "text/html; charset=utf-8")
        return reply(start, "404 Not Found", {"error": "Не найдено"})
    except (ValueError, json.JSONDecodeError, RuntimeError):
        return reply(start, "500 Internal Server Error", {"error": "Сервис временно недоступен."})

def app(env,start):
    if SUPABASE_URL and SUPABASE_SECRET_KEY:
      return cloud_app(env, start)
    path, method=env['PATH_INFO'],env['REQUEST_METHOD']
    try:
      if method=='GET' and path=='/api/services':
        with conn() as c: rows=[dict(x) for x in c.execute("SELECT id,name,description,duration_minutes,price FROM services ORDER BY id")]
        return reply(start,'200 OK',rows)
      if method=='POST' and path=='/api/auth/register':
        d=body(env); email=d.get('email','').strip().lower(); password=d.get('password',''); name=d.get('name','').strip()
        if '@' not in email or not name or not 8<=len(password)<=128: return reply(start,'400 Bad Request',{'error':'Введите имя, корректный email и пароль не короче 8 символов.'})
        salt,digest=phash(password)
        try:
          with conn() as c: c.execute("INSERT INTO users(email,name,salt,password_hash) VALUES(?,?,?,?)",(email,name,salt,digest))
        except sqlite3.IntegrityError: return reply(start,'409 Conflict',{'error':'Пользователь с таким email уже существует.'})
        return reply(start,'201 Created',{'message':'Аккаунт создан.'})
      if method=='POST' and path=='/api/auth/login':
        d=body(env)
        with conn() as c:
          user=c.execute("SELECT * FROM users WHERE email=?",(str(d.get('email','')).lower(),)).fetchone()
          if not user: return reply(start,'401 Unauthorized',{'error':'Неверный email или пароль.'})
          _,digest=phash(str(d.get('password','')),user['salt'])
          if not hmac.compare_digest(digest,user['password_hash']): return reply(start,'401 Unauthorized',{'error':'Неверный email или пароль.'})
          token=secrets.token_urlsafe(24); c.execute("INSERT INTO sessions(token_hash,user_id) VALUES(?,?)",(hashlib.sha256(token.encode()).hexdigest(),user['id']))
        return reply(start,'200 OK',{'token':token,'name':user['name']})
      if method=='GET' and path=='/api/cabinet/appointments':
        with conn() as c:
          user=current(env,c)
          if not user: return reply(start,'401 Unauthorized',{'error':'Нужно войти в аккаунт.'})
          rows=[dict(x) for x in c.execute("SELECT a.id,s.name AS service_name,s.price,a.master_name,a.appointment_date,a.start_time,a.status FROM appointments a JOIN services s ON s.id=a.service_id WHERE a.user_id=? ORDER BY a.id",(user['id'],))]
          notes=[x[0] for x in c.execute("SELECT text FROM notifications WHERE user_id=?",(user['id'],))]
        return reply(start,'200 OK',{'client':user['name'],'appointments':rows,'notifications':notes})
      if method=='POST' and path=='/api/appointments':
        d=body(env)
        with conn() as c:
          user=current(env,c)
          if not user:return reply(start,'401 Unauthorized',{'error':'Нужно войти в аккаунт.'})
          try:c.execute("INSERT INTO appointments(user_id,service_id,master_name,appointment_date,start_time) VALUES(?,?,?,?,?)",(user['id'],1,'Анна Власова',d['date'],d['time']))
          except sqlite3.IntegrityError:return reply(start,'409 Conflict',{'error':'Этот слот уже занят. Выберите другое время.'})
        return reply(start,'201 Created',{'message':'Запись создана.'})
      if method=='GET' and path=='/api/admin/appointments':
        with conn() as c:
          user=current(env,c)
          if not user or user['email']!='admin@nogotochki.ru':return reply(start,'403 Forbidden',{'error':'Доступ только администратору.'})
          rows=[dict(x) for x in c.execute("SELECT a.id,u.name,s.name service,a.master_name,a.appointment_date,a.start_time FROM appointments a JOIN users u ON u.id=a.user_id JOIN services s ON s.id=a.service_id WHERE a.status='Подтверждена'")]
        return reply(start,'200 OK',rows)
      if method=='POST' and path.startswith('/api/admin/cancel/'):
        ident=int(path.rsplit('/',1)[-1])
        with conn() as c:
          user=current(env,c)
          if not user or user['email']!='admin@nogotochki.ru':return reply(start,'403 Forbidden',{'error':'Доступ только администратору.'})
          a=c.execute("SELECT * FROM appointments WHERE id=?",(ident,)).fetchone()
          if not a:return reply(start,'404 Not Found',{'error':'Запись не найдена.'})
          c.execute("UPDATE appointments SET status='Отменена администратором' WHERE id=?",(ident,));c.execute("INSERT INTO notifications(user_id,text) VALUES(?,?)",(a['user_id'],f"Запись на {a['appointment_date']} в {a['start_time']} к мастеру {a['master_name']} отменена администратором."))
        return reply(start,'200 OK',{'message':'Запись отменена.'})
      if method=='GET' and (path.endswith('.html') or path.endswith('.css')):
        file=ROOT/'web'/path.lstrip('/')
        if file.is_file(): return reply(start,'200 OK',file.read_bytes(),'text/css; charset=utf-8' if path.endswith('.css') else 'text/html; charset=utf-8')
      if method=='GET' and path=='/':
        return reply(start,'302 Found',b'', 'text/plain')
      return reply(start,'404 Not Found',{'error':'Не найдено'})
    except (ValueError,json.JSONDecodeError): return reply(start,'400 Bad Request',{'error':'Некорректный запрос.'})

if __name__=='__main__':
    init(); print('http://127.0.0.1:8767/services.html'); make_server('127.0.0.1',8767,app).serve_forever()
