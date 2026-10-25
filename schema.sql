-- Актуальная схема данных сервиса «Ноготочки».
-- Применяется автоматически при запуске app.py; файл приложен для проверки проекта.
CREATE TABLE users (id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL, phone TEXT, password_salt TEXT, password_hash TEXT, role TEXT NOT NULL, provider TEXT, provider_user_id TEXT);
CREATE TABLE booking_services (code TEXT PRIMARY KEY, name TEXT NOT NULL, duration_minutes INTEGER NOT NULL, price INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE booking_masters (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE booking_schedules (id BIGSERIAL PRIMARY KEY, master_id BIGINT NOT NULL REFERENCES booking_masters(id), weekday INTEGER NOT NULL, work_start TEXT NOT NULL, work_end TEXT NOT NULL, UNIQUE(master_id, weekday));
CREATE TABLE booking_blocks (id BIGSERIAL PRIMARY KEY, master_id BIGINT NOT NULL REFERENCES booking_masters(id), block_date TEXT NOT NULL, start_time TEXT NOT NULL, end_time TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '');
CREATE TABLE appointments (id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id), service_code TEXT NOT NULL, master_id BIGINT NOT NULL, appointment_date TEXT NOT NULL, start_time TEXT NOT NULL, duration_minutes INTEGER NOT NULL, service_name TEXT NOT NULL, master_name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE oauth_states (state_hash TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
