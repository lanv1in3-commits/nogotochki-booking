import io
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlencode

import app


class Client:
    def __init__(self):
        self.cookie = ""

    def request(self, method, path, data=None):
        status = []
        headers = []
        body = urlencode(data or {}).encode()
        base, _, query = path.partition("?")
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": base,
            "QUERY_STRING": query,
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "HTTP_COOKIE": self.cookie,
            "wsgi.input": io.BytesIO(body),
        }
        raw = b"".join(app.application(env, lambda s, h: (status.append(s), headers.extend(h))))
        for key, value in headers:
            if key.lower() == "set-cookie": self.cookie = value.split(";", 1)[0]
        return int(status[0].split()[0]), dict(headers), raw.decode()


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        app.DB_PATH = Path(self.tmp.name) / "booking.sqlite"
        app.YANDEX_CLIENT_ID = ""
        app.YANDEX_CLIENT_SECRET = ""
        app.init_db()
        self.client = Client()

    def future_day(self, weekday=0):
        day = date.today() + timedelta(days=1)
        while day.weekday() != weekday:
            day += timedelta(days=1)
        return day.isoformat()

    def tearDown(self):
        self.tmp.cleanup()

    def register(self, email="client@example.com"):
        code, _, _ = self.client.request("POST", "/register", {
            "full_name": "Анна Тестова", "phone": "+70000000000",
            "email": email, "password": "correct-pass",
        })
        self.assertEqual(303, code)

    def login_admin(self):
        with app.db() as conn:
            salt, digest = app.password_hash("admin-pass")
            user_id = app.insert_id(conn, "INSERT INTO users(email,full_name,password_salt,password_hash,role) VALUES(?,?,?,?, 'admin')", (f"admin-{id(self)}@example.com", "Администратор", salt, digest))
        self.client.cookie = app.issue_session(user_id).split(";", 1)[0]

    def test_home_has_training_notice(self):
        code, _, body = self.client.request("GET", "/")
        self.assertEqual(200, code)
        self.assertIn("Учебный проект", body)
        self.assertIn("Не вводите настоящие персональные данные", body)

    def test_client_booking_persists_and_admin_is_forbidden(self):
        self.register()
        code, headers, _ = self.client.request("POST", "/book", {
            "service_code": "gel", "master_id": "1",
            "appointment_date": "2026-11-05", "start_time": "12:30",
        })
        self.assertEqual(303, code)
        confirmation = self.client.request("GET", headers["Location"])[2]
        self.assertIn("Вы записаны!", confirmation)
        self.assertIn("2026-11-05", confirmation)
        self.assertIn("12:30", confirmation)
        cabinet = self.client.request("GET", "/cabinet")[2]
        self.assertIn("2026-11-05", cabinet)
        self.assertIn("12:30", cabinet)
        code, _, admin = self.client.request("GET", "/admin")
        self.assertEqual(403, code)
        self.assertIn("Раздел доступен только сотрудникам студии", admin)

    def test_admin_sees_same_booking_time(self):
        self.register()
        self.client.request("POST", "/book", {"service_code":"brows","master_id":"2","appointment_date":"2026-11-06","start_time":"15:00"})
        with app.db() as conn:
            salt, digest = app.password_hash("admin-pass")
            cur = conn.execute("INSERT INTO users(email,full_name,password_salt,password_hash,role) VALUES(?,?,?,?, 'admin')", ("admin@example.com","Администратор",salt,digest))
        self.client.cookie = app.issue_session(cur.lastrowid).split(";", 1)[0]
        code, _, body = self.client.request("GET", "/admin")
        self.assertEqual(200, code)
        self.assertIn("2026-11-06", body)
        self.assertIn("15:00", body)

    def test_duplicate_slot_is_rejected(self):
        self.register()
        payload = {"service_code":"gel","master_id":"1","appointment_date":self.future_day(0),"start_time":"10:00"}
        self.assertEqual(303, self.client.request("POST", "/book", payload)[0])
        code, _, body = self.client.request("POST", "/book", payload)
        self.assertEqual(400, code)
        self.assertIn("занят", body)

    def test_long_service_hides_overlapping_slots_and_end_of_day(self):
        self.register()
        day = self.future_day(1)
        self.client.request("POST", "/book", {"service_code":"gel","master_id":"1","appointment_date":day,"start_time":"10:00"})
        with app.db() as conn:
            slots = app.available_slots(conn, "brows", 1, day)
            gel_slots = app.available_slots(conn, "gel", 2, day)
        self.assertNotIn("10:30", slots)
        self.assertNotIn("11:30", slots)
        self.assertIn("12:00", slots)
        self.assertNotIn("17:30", gel_slots)

    def test_other_client_cannot_open_booking_or_admin(self):
        self.register("owner@example.com")
        day = self.future_day(2)
        _, headers, _ = self.client.request("POST", "/book", {"service_code":"brows","master_id":"2","appointment_date":day,"start_time":"10:00"})
        appointment_id = headers["Location"].split("=")[1]
        outsider = Client()
        self.client = outsider
        self.register("outsider@example.com")
        code, _, body = outsider.request("GET", f"/appointment?id={appointment_id}")
        self.assertEqual(404, code)
        self.assertIn("Запись не найдена", body)
        code, _, body = outsider.request("GET", "/admin")
        self.assertEqual(403, code)
        self.assertIn("только сотрудникам", body)

    def test_cancel_frees_slot_and_move_keeps_same_id(self):
        self.register()
        day = self.future_day(3)
        _, headers, _ = self.client.request("POST", "/book", {"service_code":"brows","master_id":"1","appointment_date":day,"start_time":"10:00"})
        appointment_id = int(headers["Location"].split("=")[1])
        self.login_admin()
        code, _, _ = self.client.request("POST", "/admin/appointment", {"id":str(appointment_id),"action":"move","service_code":"brows","master_id":"1","appointment_date":day,"start_time":"12:00"})
        self.assertEqual(303, code)
        with app.db() as conn:
            rows = conn.execute("SELECT * FROM appointments WHERE id=?", (appointment_id,)).fetchall()
        self.assertEqual(1, len(rows))
        self.assertEqual("12:00", rows[0]["start_time"])
        self.client.request("POST", "/admin/appointment", {"id":str(appointment_id),"action":"cancel"})
        with app.db() as conn:
            row = conn.execute("SELECT status FROM appointments WHERE id=?", (appointment_id,)).fetchone()
            slots = app.available_slots(conn, "brows", 1, day)
        self.assertEqual("cancelled", row["status"])
        self.assertIn("12:00", slots)

    def test_block_and_disabled_catalog_are_respected(self):
        self.register()
        day = self.future_day(4)
        with app.db() as conn:
            conn.execute("INSERT INTO blocks(master_id,block_date,start_time,end_time,reason) VALUES(?,?,?,?,?)", (1, day, "12:00", "14:00", "Обед"))
            slots = app.available_slots(conn, "brows", 1, day)
            conn.execute("UPDATE services SET active=0 WHERE code='gel'")
        self.assertNotIn("12:00", slots)
        self.assertNotIn("13:30", slots)
        code, _, body = self.client.request("GET", "/book")
        self.assertEqual(200, code)
        self.assertNotIn("Маникюр с покрытием", body)

    def test_yandex_user_has_no_password_and_is_reused(self):
        app.YANDEX_CLIENT_ID = "client-id"
        app.YANDEX_CLIENT_SECRET = "client-secret"
        original = app.exchange_yandex
        app.exchange_yandex = lambda code: {"id":"ya-1","default_email":"tester@yandex.ru","real_name":"Яндекс Тест"}
        try:
            for state in ("one", "two"):
                with app.db() as conn:
                    conn.execute("INSERT INTO oauth_states(state_hash) VALUES(?)", (app.hashlib.sha256(state.encode()).hexdigest(),))
                self.assertEqual(303, self.client.request("GET", f"/auth/yandex/callback?code=x&state={state}")[0])
            with app.db() as conn:
                rows = conn.execute("SELECT role,password_hash,provider FROM users WHERE email='tester@yandex.ru'").fetchall()
            self.assertEqual(1, len(rows))
            self.assertEqual("client", rows[0]["role"])
            self.assertIsNone(rows[0]["password_hash"])
            self.assertEqual("yandex", rows[0]["provider"])
        finally:
            app.exchange_yandex = original


if __name__ == "__main__":
    unittest.main()
