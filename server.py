#!/usr/bin/env python3
"""Silver Fangs: dependency-free local web application, Python 3.12+."""
import argparse
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import threading
import time
import zipfile
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
SITE = ROOT / 'site'
DATA = Path(os.environ.get('SILVER_FANGS_DATA', ROOT / 'data'))
DB = DATA / 'clan.sqlite3'
ADMIN_FILE = Path(os.environ.get('SILVER_FANGS_ADMIN_FILE', ROOT / '.local-admin.txt'))
MAX_UPLOAD = 5 * 1024 * 1024
ROLES = {'member': 'Участник', 'veteran': 'Ветеран', 'command': 'Командование'}
CATEGORIES = [
    ('contacts', 'Архив контактов', 'Контакты и сведения о взаимодействии.'),
    ('internal', 'Внутренняя справка', 'Правила, инструкции и рабочие материалы клана.'),
    ('subjects', 'Справочник субъектов', 'Информация о группах, подразделениях и участниках.'),
    ('materials', 'Архивные материалы', 'Дополнительные документы и история проекта.'),
]
RATE_LOCK = threading.Lock()
RATE = {}


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def connect():
    db = sqlite3.connect(DB, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1).hex()
    return salt + ':' + digest


def password_matches(password, stored):
    salt = stored.split(':')[0]
    return hmac.compare_digest(password_hash(password, salt), stored)


def initialize():
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    (DATA / 'uploads').mkdir(exist_ok=True, mode=0o700)
    with connect() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            callsign TEXT NOT NULL, password TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0,
            approved INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL, PRIMARY KEY (user_id, role));
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            csrf TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
            contact TEXT NOT NULL, message TEXT NOT NULL, filename TEXT NOT NULL,
            storage_name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            review_note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, reviewed_at TEXT);
        CREATE TABLE IF NOT EXISTS categories (
            slug TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS category_roles (
            category TEXT REFERENCES categories(slug), role TEXT NOT NULL,
            PRIMARY KEY(category,role));
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY, category TEXT NOT NULL REFERENCES categories(slug),
            title TEXT NOT NULL, summary TEXT NOT NULL, body TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        ''')
        defaults = {
            'home_description': '«Серебряные клыки» — сообщество игроков Arma Reforger. Нас объединяют командная игра, интерес к тактике и уважение к тем, кто рядом. Здесь каждый становится частью общего дела.',
            'program_title': 'Второй шанс',
            'program_description': 'Программа вступления в «Серебряные клыки». Познакомься с проектом, расскажи о себе в заявке и дождись решения администратора. После одобрения тебе станут доступны внутренние разделы сообщества.',
            'application_template': 'ЗАЯВКА В «СЕРЕБРЯНЫЕ КЛЫКИ»\nПрограмма «Второй шанс» · Arma Reforger\n\nПозывной:\nВозраст (по желанию):\nЧасовой пояс:\nКонтакт для связи (Discord / Telegram):\nОпыт в Arma Reforger:\nПочему хотите присоединиться:\nПредпочитаемая роль в команде:\nУдобное время для игры:\nЧто ещё хотите рассказать о себе:\n\nЭто стартовый образец заявки. Администратор может изменить его на сайте.\n',
        }
        for k, v in defaults.items():
            db.execute('INSERT OR IGNORE INTO settings VALUES (?,?)', (k, v))
        for slug, title, description in CATEGORIES:
            db.execute('INSERT OR IGNORE INTO categories VALUES (?,?,?)', (slug, title, description))
        if not db.execute('SELECT 1 FROM settings WHERE key=?', ('category_roles_initialized',)).fetchone():
            for slug, _, _ in CATEGORIES:
                for role in ROLES:
                    if slug == 'contacts' and role == 'member':
                        continue
                    db.execute('INSERT OR IGNORE INTO category_roles VALUES (?,?)', (slug, role))
            db.execute('INSERT INTO settings VALUES (?,?)', ('category_roles_initialized', '1'))
        if not db.execute('SELECT 1 FROM users WHERE is_admin=1').fetchone():
            password = secrets.token_urlsafe(18)
            db.execute('INSERT INTO users (username,callsign,password,is_admin,approved,created_at) VALUES (?,?,?,1,1,?)', ('admin', 'Администратор', password_hash(password), now()))
            credential_file = ADMIN_FILE
            fd = os.open(credential_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(f'Вход: /account\nЛогин: admin\nПароль: {password}\n\nПосле первого входа смените пароль в личном кабинете.\n')
            print(f'Initial admin credentials saved privately to {credential_file}', flush=True)


class ApiError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


class Handler(BaseHTTPRequestHandler):
    server_version = 'SilverFangs'

    def log_message(self, fmt, *args):
        # Do not log URLs containing passwords, cookies, request bodies or session tokens.
        print(f'{self.address_string()} {self.command} {urlparse(self.path).path} {args[1] if len(args)>1 else ""}', flush=True)

    def finish_response(self, status, content_type, body, extra=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
        self.send_header('Cache-Control', 'no-store' if self.path.startswith('/api/') else 'no-cache')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def json(self, obj, status=200, extra=None):
        self.finish_response(status, 'application/json; charset=utf-8', json.dumps(obj, ensure_ascii=False).encode(), extra)

    def session(self, db):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie', ''))
        except Exception:
            return None
        token = cookie.get('sf_session')
        if not token:
            return None
        return db.execute('SELECT u.*,s.csrf FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?', (hashlib.sha256(token.value.encode()).hexdigest(), int(time.time()))).fetchone()

    def need_user(self, db, admin=False, approved=False):
        user = self.session(db)
        if not user:
            raise ApiError(401, 'Сначала войдите в свой аккаунт.')
        if admin and not user['is_admin']:
            raise ApiError(403, 'Этот раздел доступен только администратору.')
        if approved and not user['approved']:
            raise ApiError(403, 'Доступ к архиву откроется после одобрения заявки.')
        return user

    def csrf(self, user):
        if not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), user['csrf']):
            raise ApiError(403, 'Сессия обновилась. Перезагрузите страницу и повторите действие.')

    def body(self, limit=256*1024):
        try:
            n = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            raise ApiError(400, 'Некорректный размер запроса.')
        if n <= 0 or n > limit:
            raise ApiError(413, 'Файл слишком большой. Максимум — 5 МБ.' if limit > 100000 else 'Запрос слишком большой или пустой.')
        return self.rfile.read(n)

    def read_json(self):
        if 'application/json' not in self.headers.get('Content-Type', ''):
            raise ApiError(415, 'Ожидается запрос в формате JSON.')
        try:
            data = json.loads(self.body())
        except (ValueError, UnicodeError):
            raise ApiError(400, 'Некорректный запрос.')
        if not isinstance(data, dict):
            raise ApiError(400, 'Некорректный запрос.')
        return data

    def field(self, data, key, maximum, minimum=0):
        value = data.get(key, '')
        if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
            raise ApiError(400, f'Проверьте поле «{key}»: длина от {minimum} до {maximum} символов.')
        return value.strip()

    def roles(self, db, uid):
        return [r['role'] for r in db.execute('SELECT role FROM user_roles WHERE user_id=? ORDER BY role', (uid,))]

    def validate_roles(self, data):
        roles = data.get('roles', [])
        if not isinstance(roles, list) or any(not isinstance(r, str) or r not in ROLES for r in roles):
            raise ApiError(400, 'Неизвестная категория пользователя.')
        return sorted(set(roles))

    def public_user(self, db, user):
        if not user:
            return None
        return {**{k: user[k] for k in ('id', 'username', 'callsign', 'is_admin', 'approved')}, 'roles': self.roles(db, user['id'])}

    def new_session(self, db, uid):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        db.execute('DELETE FROM sessions WHERE expires<?', (int(time.time()),))
        db.execute('INSERT INTO sessions VALUES (?,?,?,?)', (hashlib.sha256(token.encode()).hexdigest(), uid, csrf, int(time.time())+604800))
        cookie = f'sf_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800'
        if os.environ.get('SILVER_FANGS_SECURE_COOKIE') == '1':
            cookie += '; Secure'
        user = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
        return {'user': self.public_user(db, user), 'csrf': csrf}, {'Set-Cookie': cookie}

    def can_category(self, db, user, category):
        if user['is_admin']:
            return True
        return bool(db.execute('SELECT 1 FROM category_roles c JOIN user_roles u ON u.role=c.role WHERE c.category=? AND u.user_id=?', (category, user['id'])).fetchone())

    def categories(self, db, user=None, admin=False):
        rows = []
        for r in db.execute('SELECT * FROM categories ORDER BY rowid'):
            if not admin and (not user or not self.can_category(db, user, r['slug'])):
                continue
            item = dict(r)
            item['count'] = db.execute('SELECT count(*) FROM articles WHERE category=?', (r['slug'],)).fetchone()[0]
            if admin:
                item['roles'] = [x[0] for x in db.execute('SELECT role FROM category_roles WHERE category=?', (r['slug'],))]
            rows.append(item)
        return rows

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if path.startswith('/api/'):
                with connect() as db:
                    return self.get_api(db, path)
            if path == '/health':
                return self.json({'status': 'ok'})
            if path in ('/', '/program', '/apply', '/archive', '/account', '/admin') or re.fullmatch(r'/archive/\d+', path):
                file = SITE / 'index.html'
            elif path in ('/app.js', '/style.css') or re.fullmatch(r'/assets/[A-Za-z0-9_.-]+', path):
                file = SITE / path.lstrip('/')
            else:
                return self.finish_response(404, 'text/plain; charset=utf-8', 'Страница не найдена'.encode())
            if not file.is_file():
                return self.finish_response(404, 'text/plain; charset=utf-8', 'Файл не найден'.encode())
            content_type = mimetypes.guess_type(file.name)[0] or 'application/octet-stream'
            if content_type.startswith('text/') or content_type in ('application/javascript', 'image/svg+xml'):
                content_type += '; charset=utf-8'
            self.finish_response(200, content_type, file.read_bytes())
        except ApiError as e:
            self.json({'error': e.message}, e.status)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            print('GET error:',type(e).__name__,flush=True)
            self.json({'error': 'Ошибка сервера. Попробуйте ещё раз.'}, 500)

    def get_api(self, db, path):
        if path == '/api/public':
            settings = dict(db.execute('SELECT key,value FROM settings WHERE key IN (?,?,?)', ('home_description','program_title','program_description')).fetchall())
            return self.json({'settings': settings, 'roles': ROLES})
        if path == '/api/me':
            user = self.session(db)
            application = None
            if user:
                row = db.execute('SELECT id,filename,status,review_note,created_at,reviewed_at FROM applications WHERE user_id=? ORDER BY id DESC LIMIT 1', (user['id'],)).fetchone()
                application = dict(row) if row else None
            return self.json({'user': self.public_user(db, user), 'csrf': user['csrf'] if user else None, 'application': application})
        if path == '/api/template':
            template = db.execute('SELECT value FROM settings WHERE key=?', ('application_template',)).fetchone()[0]
            return self.finish_response(200, 'text/plain; charset=utf-8', ('\ufeff'+template).encode(), {'Content-Disposition': 'attachment; filename="silver-fangs-application.txt"'})
        if path == '/api/archive':
            user = self.need_user(db, approved=True)
            categories = self.categories(db, user)
            allowed = {c['slug'] for c in categories}
            articles = [dict(r) for r in db.execute('SELECT id,category,title,summary,updated_at FROM articles ORDER BY updated_at DESC,id DESC') if r['category'] in allowed]
            return self.json({'categories': categories, 'articles': articles})
        match = re.fullmatch(r'/api/archive/(\d+)', path)
        if match:
            user = self.need_user(db, approved=True)
            article = db.execute('SELECT * FROM articles WHERE id=?', (match[1],)).fetchone()
            if not article or not self.can_category(db, user, article['category']):
                raise ApiError(404, 'Материал не найден или недоступен для вашей категории.')
            return self.json({'article': dict(article)})
        if path == '/api/admin':
            self.need_user(db, admin=True)
            users = []
            for row in db.execute('SELECT * FROM users ORDER BY id DESC'):
                users.append(self.public_user(db, row))
            applications = [dict(r) for r in db.execute('SELECT a.id,a.user_id,a.contact,a.message,a.filename,a.status,a.review_note,a.created_at,a.reviewed_at,u.callsign,u.username FROM applications a JOIN users u ON u.id=a.user_id ORDER BY a.id DESC')]
            return self.json({'users': users, 'applications': applications, 'categories': self.categories(db, admin=True), 'articles': [dict(r) for r in db.execute('SELECT * FROM articles ORDER BY id DESC')], 'settings': dict(db.execute('SELECT key,value FROM settings WHERE key!=?', ('category_roles_initialized',)).fetchall()), 'roles': ROLES})
        match = re.fullmatch(r'/api/admin/applications/(\d+)/file', path)
        if match:
            self.need_user(db, admin=True)
            row = db.execute('SELECT filename,storage_name FROM applications WHERE id=?', (match[1],)).fetchone()
            if not row:
                raise ApiError(404, 'Заявка не найдена.')
            file = DATA / 'uploads' / row['storage_name']
            if not file.is_file():
                raise ApiError(404, 'Файл заявки не найден.')
            from urllib.parse import quote
            return self.finish_response(200, 'application/octet-stream', file.read_bytes(), {'Content-Disposition': "attachment; filename=application"+Path(row['filename']).suffix+"; filename*=UTF-8''"+quote(row['filename'])})
        raise ApiError(404, 'Раздел не найден.')

    def do_POST(self):
        try:
            # Origin checks also protect login/registration; all mutations require JSON or CSRF.
            origin = self.headers.get('Origin')
            if origin and urlparse(origin).netloc != self.headers.get('Host'):
                raise ApiError(403, 'Недопустимый источник запроса.')
            with connect() as db:
                result = self.post_api(db, urlparse(self.path).path)
            if result is not None:
                payload, status, headers = result
                self.json(payload, status, headers)
        except ApiError as e:
            self.json({'error': e.message}, e.status)
        except sqlite3.IntegrityError:
            self.json({'error': 'Такой логин уже занят или запись больше не существует.'}, 409)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            print('POST error:',type(e).__name__,flush=True)
            self.json({'error': 'Ошибка сервера. Попробуйте ещё раз.'}, 500)

    def post_api(self, db, path):
        if path in ('/api/login', '/api/register'):
            data = self.read_json()
            ip = self.client_address[0]
            stamp = time.time()
            with RATE_LOCK:
                for old_ip in list(RATE):
                    RATE[old_ip] = [t for t in RATE[old_ip] if t > stamp-300]
                    if not RATE[old_ip]:
                        del RATE[old_ip]
                attempts = RATE.setdefault(ip, [])
                if len(attempts) >= 25:
                    raise ApiError(429, 'Слишком много попыток входа. Повторите через 5 минут.')
                attempts.append(stamp)
            username = self.field(data, 'username', 40, 3)
            password = self.field(data, 'password', 128, 8)
            if not re.fullmatch(r'[A-Za-z0-9_.-]{3,40}', username):
                raise ApiError(400, 'Логин: 3–40 латинских букв, цифр, точек, дефисов или подчёркиваний.')
            if path == '/api/register':
                callsign = self.field(data, 'callsign', 50, 2)
                if db.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
                    raise ApiError(409, 'Такой логин уже занят.')
                cur = db.execute('INSERT INTO users(username,callsign,password,created_at) VALUES (?,?,?,?)', (username, callsign, password_hash(password), now()))
                uid = cur.lastrowid
            else:
                user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
                # Hash even when username is missing, to reduce timing differences.
                stored = user['password'] if user else '0'*32 + ':' + '0'*128
                if not password_matches(password, stored) or not user:
                    raise ApiError(401, 'Неверный логин или пароль.')
                uid = user['id']
                with RATE_LOCK:
                    RATE.pop(ip, None)
            payload, headers = self.new_session(db, uid)
            return payload, 201 if path.endswith('register') else 200, headers
        user = self.need_user(db, admin=path.startswith('/api/admin/'))
        self.csrf(user)
        if path == '/api/logout':
            db.execute('DELETE FROM sessions WHERE csrf=? AND user_id=?', (user['csrf'], user['id']))
            return {'ok': True}, 200, {'Set-Cookie':'sf_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'}
        if path == '/api/password':
            data = self.read_json()
            old, new = self.field(data, 'current_password', 128, 8), self.field(data, 'new_password', 128, 8)
            if not password_matches(old, user['password']):
                raise ApiError(400, 'Текущий пароль неверен.')
            db.execute('UPDATE users SET password=? WHERE id=?', (password_hash(new), user['id']))
            db.execute('DELETE FROM sessions WHERE user_id=? AND csrf!=?', (user['id'], user['csrf']))
            return {'ok': True}, 200, None
        if path == '/api/applications':
            if user['approved']:
                raise ApiError(409, 'Вы уже участник сообщества.')
            if db.execute('SELECT 1 FROM applications WHERE user_id=? AND status=?', (user['id'], 'pending')).fetchone():
                raise ApiError(409, 'Ваша заявка уже на рассмотрении.')
            content_type = self.headers.get('Content-Type', '')
            if not content_type.startswith('multipart/form-data;'):
                raise ApiError(415, 'Загрузите файл через форму заявки.')
            raw = self.body(MAX_UPLOAD + 16384)
            msg = BytesParser(policy=default).parsebytes(('Content-Type: '+content_type+'\r\nMIME-Version: 1.0\r\n\r\n').encode()+raw)
            fields, file_data, filename = {}, None, None
            if not msg.is_multipart():
                raise ApiError(400, 'Некорректная форма.')
            for part in msg.iter_parts():
                name = part.get_param('name', header='content-disposition')
                if name == 'file' and part.get_filename():
                    if file_data is not None:
                        raise ApiError(400, 'Приложите один файл.')
                    filename = Path(part.get_filename().replace('\\', '/')).name
                    file_data = part.get_payload(decode=True)
                elif name in ('contact','message','consent'):
                    fields[name] = part.get_payload(decode=True).decode('utf-8', errors='replace')
            contact = self.field(fields, 'contact', 200, 3)
            message = self.field(fields, 'message', 3000)
            if fields.get('consent') != 'yes':
                raise ApiError(400, 'Подтвердите передачу заявки администратору.')
            if not filename or not file_data or len(file_data)>MAX_UPLOAD or len(filename)>150:
                raise ApiError(400, 'Прикрепите непустой файл размером до 5 МБ.')
            extension = Path(filename).suffix.lower()
            if extension not in ('.txt','.md','.pdf','.docx'):
                raise ApiError(400, 'Допустимые форматы: TXT, MD, PDF, DOCX.')
            if extension == '.pdf' and not file_data.startswith(b'%PDF-'):
                raise ApiError(400, 'Файл не является PDF.')
            if extension == '.docx':
                try:
                    with zipfile.ZipFile(BytesIO(file_data)) as z:
                        if '[Content_Types].xml' not in z.namelist() or 'word/document.xml' not in z.namelist():
                            raise ValueError()
                except (zipfile.BadZipFile, ValueError):
                    raise ApiError(400, 'Файл не является документом DOCX.')
            if extension in ('.txt','.md') and b'\x00' in file_data:
                raise ApiError(400, 'Ожидается текстовый документ.')
            storage_name = secrets.token_hex(24) + extension
            file = DATA / 'uploads' / storage_name
            fd = os.open(file, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd,'wb') as f:
                    f.write(file_data)
                cur = db.execute('INSERT INTO applications(user_id,contact,message,filename,storage_name,created_at) VALUES (?,?,?,?,?,?)', (user['id'],contact,message,filename,storage_name,now()))
            except Exception:
                file.unlink(missing_ok=True)
                raise
            return {'ok': True, 'id': cur.lastrowid}, 201, None
        if path == '/api/admin/review':
            data = self.read_json()
            app = db.execute('SELECT * FROM applications WHERE id=?', (data.get('id'),)).fetchone()
            if not app or app['status'] != 'pending':
                raise ApiError(409, 'Заявка уже обработана или не найдена.')
            status = data.get('status')
            if status not in ('approved','rejected'):
                raise ApiError(400, 'Выберите решение по заявке.')
            roles = self.validate_roles(data)
            if status == 'approved' and not roles:
                raise ApiError(400, 'Назначьте хотя бы одну категорию пользователя.')
            note = self.field(data,'review_note',2000)
            db.execute('UPDATE applications SET status=?,review_note=?,reviewed_at=? WHERE id=?', (status,note,now(),app['id']))
            if status == 'approved':
                db.execute('UPDATE users SET approved=1 WHERE id=?', (app['user_id'],))
                db.execute('DELETE FROM user_roles WHERE user_id=?', (app['user_id'],))
                db.executemany('INSERT INTO user_roles VALUES (?,?)', [(app['user_id'],r) for r in roles])
            return {'ok':True},200,None
        if path == '/api/admin/user':
            data = self.read_json()
            target = db.execute('SELECT * FROM users WHERE id=?', (data.get('id'),)).fetchone()
            if not target or target['is_admin']:
                raise ApiError(400,'Учётную запись администратора нельзя изменить здесь.')
            roles = self.validate_roles(data)
            approved = bool(data.get('approved'))
            if approved and not roles:
                raise ApiError(400,'Назначьте хотя бы одну категорию пользователя.')
            db.execute('UPDATE users SET approved=? WHERE id=?',(int(approved),target['id']))
            db.execute('DELETE FROM user_roles WHERE user_id=?',(target['id'],))
            if approved:
                db.executemany('INSERT INTO user_roles VALUES (?,?)',[(target['id'],r) for r in roles])
            return {'ok':True},200,None
        if path == '/api/admin/article':
            data = self.read_json()
            category = self.field(data,'category',50,1)
            if not db.execute('SELECT 1 FROM categories WHERE slug=?',(category,)).fetchone():
                raise ApiError(400,'Выберите раздел архива.')
            title,summary,body = self.field(data,'title',200,3),self.field(data,'summary',500),self.field(data,'body',40000,1)
            article_id = data.get('id')
            if article_id:
                if not db.execute('SELECT 1 FROM articles WHERE id=?',(article_id,)).fetchone():
                    raise ApiError(404,'Материал не найден.')
                db.execute('UPDATE articles SET category=?,title=?,summary=?,body=?,updated_at=? WHERE id=?',(category,title,summary,body,now(),article_id))
            else:
                article_id = db.execute('INSERT INTO articles(category,title,summary,body,created_at,updated_at) VALUES (?,?,?,?,?,?)',(category,title,summary,body,now(),now())).lastrowid
            return {'ok':True,'id':article_id},200,None
        if path == '/api/admin/article/delete':
            data = self.read_json()
            db.execute('DELETE FROM articles WHERE id=?',(data.get('id'),))
            return {'ok':True},200,None
        if path == '/api/admin/category':
            data = self.read_json()
            slug = self.field(data,'slug',50,1)
            if not db.execute('SELECT 1 FROM categories WHERE slug=?',(slug,)).fetchone():
                raise ApiError(404,'Раздел не найден.')
            roles = self.validate_roles(data)
            title, description = self.field(data,'title',100,2),self.field(data,'description',500)
            db.execute('UPDATE categories SET title=?,description=? WHERE slug=?',(title,description,slug))
            db.execute('DELETE FROM category_roles WHERE category=?',(slug,))
            db.executemany('INSERT INTO category_roles VALUES (?,?)',[(slug,r) for r in roles])
            return {'ok':True},200,None
        if path == '/api/admin/settings':
            data = self.read_json()
            for key,maximum in [('home_description',3000),('program_title',100),('program_description',10000),('application_template',20000)]:
                value = self.field(data,key,maximum,1)
                db.execute('UPDATE settings SET value=? WHERE key=?',(value,key))
            return {'ok':True},200,None
        raise ApiError(404,'Действие не найдено.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port',type=int,default=8088)
    parser.add_argument('--host',default='0.0.0.0')
    args=parser.parse_args()
    initialize()
    server=ThreadingHTTPServer((args.host,args.port),Handler)
    server.daemon_threads=True
    print(f'Silver Fangs ready at http://{args.host}:{args.port}',flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__=='__main__':
    main()
