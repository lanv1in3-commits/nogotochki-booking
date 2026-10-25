-- Расширение для проектной работы: каталог, расписание, блокировки и снимки записи.
CREATE TABLE IF NOT EXISTS booking_services (code TEXT PRIMARY KEY, name TEXT NOT NULL, duration_minutes INTEGER NOT NULL, price INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS booking_masters (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS booking_schedules (id BIGSERIAL PRIMARY KEY, master_id BIGINT NOT NULL REFERENCES booking_masters(id), weekday INTEGER NOT NULL, work_start TEXT NOT NULL, work_end TEXT NOT NULL, UNIQUE(master_id, weekday));
CREATE TABLE IF NOT EXISTS booking_blocks (id BIGSERIAL PRIMARY KEY, master_id BIGINT NOT NULL REFERENCES booking_masters(id), block_date TEXT NOT NULL, start_time TEXT NOT NULL, end_time TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '');
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS duration_minutes INTEGER;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS service_name TEXT;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS master_name TEXT;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS updated_at TEXT;
