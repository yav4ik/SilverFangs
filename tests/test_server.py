import http.cookiejar
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server


class Client:
    def __init__(self, base):
        self.base = base
        self.csrf = None
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, data=None, body=None, headers=None):
        headers = dict(headers or {})
        if data is not None:
            body=json.dumps(data).encode()
            headers['Content-Type']='application/json'
        if self.csrf:
            headers.setdefault('X-CSRF-Token', self.csrf)
        req=urllib.request.Request(self.base+path,data=body,headers=headers)
        try:
            with self.opener.open(req,timeout=15) as r:
                raw=r.read()
                obj=json.loads(raw) if 'application/json' in r.headers.get('Content-Type','') else raw
                return r.status,obj
        except urllib.error.HTTPError as r:
            raw=r.read()
            try: obj=json.loads(raw)
            except ValueError: obj=raw
            return r.code,obj

    def login(self, username, password):
        status,result=self.request('/api/login',{'username':username,'password':password})
        if status==200:self.csrf=result['csrf']
        return status,result

    def register(self, username):
        status,result=self.request('/api/register',{'username':username,'callsign':'Тестовый боец','password':'ExamplePassword123!','is_admin':True,'approved':True})
        if status==201:self.csrf=result['csrf']
        return status,result

    def upload(self, filename='application.txt', content=b'Callsign: Test', contact='discord:test'):
        boundary='SilverFangsTestBoundary'
        body=b''
        for key,value in [('contact',contact),('message','Test application'),('consent','yes')]:
            body+=f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode()
        body+=f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()+content+f'\r\n--{boundary}--\r\n'.encode()
        return self.request('/api/applications',body=body,headers={'Content-Type':f'multipart/form-data; boundary={boundary}'})


class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='silver-fangs-tests-')
        server.DATA=Path(cls.tmp.name)
        server.DB=server.DATA/'test.sqlite3'
        server.ADMIN_FILE=server.DATA/'admin.txt'
        server.initialize()
        cls.password=server.ADMIN_FILE.read_text().split('Пароль: ')[1].splitlines()[0]
        cls.http=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        cls.thread=threading.Thread(target=cls.http.serve_forever,daemon=True)
        cls.thread.start()
        cls.base=f'http://127.0.0.1:{cls.http.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown();cls.http.server_close();cls.tmp.cleanup()

    def test_01_public_routes_and_private_files(self):
        c=Client(self.base)
        for path in ['/','/program','/apply','/archive','/account','/admin','/assets/wolf.svg','/assets/forest.jpg','/app.js','/style.css','/health']:
            self.assertEqual(c.request(path)[0],200,path)
        for path in ['/.local-admin.txt','/server.py','/data/clan.sqlite3','/../server.py']:
            self.assertEqual(c.request(path)[0],404,path)
        self.assertEqual(c.request('/api/archive')[0],401)
        self.assertEqual(c.request('/api/admin')[0],401)
        self.assertIn('ЗАЯВКА'.encode(),c.request('/api/template')[1])

    def test_02_complete_application_and_category_permissions(self):
        admin=Client(self.base)
        self.assertEqual(admin.login('admin',self.password)[0],200)
        member=Client(self.base)
        status,user=member.register('member')
        self.assertEqual(status,201)
        uid=user['user']['id']
        self.assertFalse(user['user']['is_admin'])
        self.assertFalse(user['user']['approved'])
        self.assertEqual(member.request('/api/admin')[0],403)
        self.assertEqual(member.request('/api/archive')[0],403)
        self.assertEqual(member.request('/api/password',{'current_password':'ExamplePassword123!','new_password':'changedPassword123'},headers={'X-CSRF-Token':'wrong'})[0],403)
        self.assertEqual(member.upload('malware.html',b'<html>bad</html>')[0],400)
        self.assertEqual(member.upload('fake.pdf',b'not a pdf')[0],400)
        self.assertEqual(member.upload('fake.docx',b'not a zip')[0],400)
        status,app=member.upload(content='Позывной: Тест'.encode())
        self.assertEqual(status,201)
        self.assertEqual(member.upload()[0],409)
        app_id=app['id']
        self.assertEqual(member.request(f'/api/admin/applications/{app_id}/file')[0],403)
        self.assertEqual(admin.request(f'/api/admin/applications/{app_id}/file')[1],'Позывной: Тест'.encode())
        ids={}
        for cat in ['internal','contacts']:
            status,article=admin.request('/api/admin/article',{'category':cat,'title':f'Article {cat}','summary':'Summary','body':'Restricted archive text'})
            self.assertEqual(status,200)
            ids[cat]=article['id']
        status,_=admin.request('/api/admin/review',{'id':app_id,'status':'approved','roles':['member'],'review_note':'Добро пожаловать!'})
        self.assertEqual(status,200)
        status,archive=member.request('/api/archive')
        self.assertEqual(status,200)
        self.assertIn('internal',[c['slug'] for c in archive['categories']])
        self.assertNotIn('contacts',[c['slug'] for c in archive['categories']])
        self.assertEqual([a['id'] for a in archive['articles']],[ids['internal']])
        self.assertEqual(member.request(f'/api/archive/{ids["contacts"]}')[0],404)
        self.assertEqual(member.request(f'/api/archive/{ids["internal"]}')[0],200)
        self.assertEqual(admin.request('/api/admin/user',{'id':uid,'approved':True,'roles':['veteran']})[0],200)
        self.assertEqual(member.request(f'/api/archive/{ids["contacts"]}')[0],200)
        self.assertEqual(admin.request('/api/admin/category',{'slug':'contacts','title':'Контакты командования','description':'Only command','roles':['command']})[0],200)
        self.assertEqual(member.request(f'/api/archive/{ids["contacts"]}')[0],404)
        self.assertEqual(admin.request('/api/admin/user',{'id':uid,'approved':False,'roles':[]})[0],200)
        self.assertEqual(member.request('/api/archive')[0],403)
        self.assertEqual(member.request(f'/api/archive/{ids["internal"]}')[0],403)
        self.assertEqual(member.request('/api/me')[1]['application']['review_note'],'Добро пожаловать!')
        with server.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM applications').fetchone()[0],1)
            stored=db.execute('SELECT password FROM users WHERE id=?',(uid,)).fetchone()[0]
            self.assertNotIn('ExamplePassword123',stored)

    def test_03_rejection_resubmit_and_session_revocation(self):
        admin=Client(self.base);admin.login('admin',self.password)
        c=Client(self.base);c.register('resubmit')
        status,app=c.upload()
        self.assertEqual(status,201)
        self.assertEqual(admin.request('/api/admin/review',{'id':app['id'],'status':'rejected','roles':[],'review_note':'Уточните контакт'})[0],200)
        self.assertEqual(c.request('/api/me')[1]['application']['status'],'rejected')
        self.assertEqual(c.upload()[0],201)
        other=Client(self.base);other.login('resubmit','ExamplePassword123!')
        self.assertEqual(c.request('/api/password',{'current_password':'ExamplePassword123!','new_password':'BetterPassword456!'})[0],200)
        self.assertIsNone(other.request('/api/me')[1]['user'])
        self.assertEqual(c.request('/api/logout',{})[0],200)
        self.assertIsNone(c.request('/api/me')[1]['user'])
        self.assertEqual(c.login('resubmit','ExamplePassword123!')[0],401)
        self.assertEqual(c.login('resubmit','BetterPassword456!')[0],200)
        self.assertEqual(c.request('/api/login',{'username':'resubmit','password':'BetterPassword456!'},headers={'Origin':'https://untrusted.example'})[0],403)


if __name__=='__main__':
    unittest.main()
