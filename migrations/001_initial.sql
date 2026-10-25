-- Исходная миграция: пользователи, сессии и записи.
-- Выполняется идемпотентно функцией init_db в app.py.
CREATE TABLE IF NOT EXISTS users (id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'client');
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS appointments (id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id), service_code TEXT NOT NULL, master_id BIGINT NOT NULL, appointment_date TEXT NOT NULL, start_time TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active');
