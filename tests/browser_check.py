"""UI end-to-end checks in a temporary database; requires Playwright + Chromium."""
from pathlib import Path
import sys
import tempfile
import threading
from playwright.sync_api import sync_playwright, expect

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import server


def main():
    with tempfile.TemporaryDirectory(prefix='silver-fangs-browser-') as temp:
        server.DATA=Path(temp)
        server.DB=server.DATA/'test.sqlite3'
        server.ADMIN_FILE=server.DATA/'admin.txt'
        server.initialize()
        password=server.ADMIN_FILE.read_text().split('Пароль: ')[1].splitlines()[0]
        http=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        threading.Thread(target=http.serve_forever,daemon=True).start()
        base=f'http://127.0.0.1:{http.server_port}'
        try:
            with sync_playwright() as p:
                browser=p.chromium.launch(headless=True,args=['--no-sandbox','--disable-dev-shm-usage'])
                context=browser.new_context(viewport={'width':1440,'height':1000})
                page=context.new_page()
                errors=[]
                page.on('pageerror',lambda error:errors.append(str(error)))
                page.goto(base,wait_until='networkidle')
                expect(page.locator('h1')).to_contain_text('СЕРЕБРЯНЫЕ')
                assert not page.evaluate('document.documentElement.scrollWidth > innerWidth')
                page.get_by_role('link',name='Программа',exact=True).click()
                expect(page.locator('h1')).to_have_text('Второй шанс')
                page.get_by_role('link',name='Подать заявку',exact=False).first.click()
                page.get_by_role('button',name='Зарегистрироваться',exact=True).click()
                page.locator('#auth-callsign').fill('Тестовый волк')
                page.locator('#auth-username').fill('browserwolf')
                page.locator('#auth-password').fill('BrowserPassword123!')
                page.locator('#auth-form button[type=submit]').click()
                expect(page.locator('#auth-dialog')).not_to_be_visible()
                expect(page.locator('#application-form')).to_be_visible()
                page.locator('#contact').fill('discord:browserwolf')
                page.locator('#application-file').set_input_files({'name':'анкета.txt','mimeType':'text/plain','buffer':'Позывной: Тестовый волк'.encode()})
                page.locator('input[name=consent]').check()
                page.locator('#application-form button[type=submit]').click()
                expect(page.get_by_role('heading',name='Заявка отправлена',exact=True)).to_be_visible()
                page.reload(wait_until='networkidle')
                expect(page.get_by_role('heading',name='Заявка отправлена',exact=True)).to_be_visible()

                admin_context=browser.new_context(viewport={'width':1440,'height':1000})
                admin=admin_context.new_page()
                admin.on('pageerror',lambda error:errors.append(str(error)))
                admin.goto(base+'/admin',wait_until='networkidle')
                admin.locator('main [data-auth=login]').click()
                admin.locator('#auth-username').fill('admin')
                admin.locator('#auth-password').fill(password)
                admin.locator('#auth-form button[type=submit]').click()
                expect(admin.locator('.review-form')).to_be_visible()
                admin.locator('.review-form textarea').fill('Добро пожаловать!')
                admin.get_by_role('button',name='Одобрить заявку',exact=True).click()
                expect(admin.get_by_role('heading',name='Новых заявок пока нет',exact=True)).to_be_visible()
                admin.get_by_role('tab',name='Материалы',exact=True).click()
                admin.get_by_role('button',name='Добавить материал',exact=False).click()
                admin.locator('#article-title').fill('Первая внутренняя статья')
                admin.locator('#article-category').select_option('internal')
                admin.locator('#article-summary').fill('Материал для участников')
                admin.locator('#article-body').fill('Это текст статьи.\n<script>window.injected=true</script>')
                admin.get_by_role('button',name='Опубликовать материал',exact=True).click()
                expect(admin.get_by_role('heading',name='Первая внутренняя статья',exact=True)).to_be_visible()

                page.goto(base+'/archive',wait_until='networkidle')
                expect(page.get_by_role('link',name='Первая внутренняя статья',exact=False)).to_be_visible()
                expect(page.get_by_role('button',name='Архив контактов',exact=False)).not_to_be_visible()
                page.locator('#archive-search').fill('несуществующая статья')
                expect(page.get_by_role('heading',name='Ничего не найдено')).to_be_visible()
                page.locator('#archive-search').fill('внутренняя')
                page.get_by_role('link',name='Первая внутренняя статья',exact=False).click()
                expect(page.locator('.article-body')).to_contain_text('<script>window.injected=true</script>')
                assert page.evaluate('window.injected') is None

                mobile=context.new_page()
                mobile.set_viewport_size({'width':390,'height':844})
                mobile.on('pageerror',lambda error:errors.append(str(error)))
                for route in ['/','/program','/apply','/account','/archive']:
                    mobile.goto(base+route,wait_until='networkidle')
                    assert not mobile.evaluate('document.documentElement.scrollWidth > innerWidth'),route
                mobile.goto(base,wait_until='networkidle')
                mobile.get_by_role('button',name='Открыть меню',exact=True).click()
                expect(mobile.locator('#navigation')).to_be_visible()
                mobile.get_by_role('link',name='Программа',exact=True).click()
                expect(mobile.locator('h1')).to_have_text('Второй шанс')
                mobile.set_viewport_size({'width':320,'height':720})
                for route in ['/','/program','/apply','/account','/archive']:
                    mobile.goto(base+route,wait_until='networkidle')
                    assert not mobile.evaluate('document.documentElement.scrollWidth > innerWidth'), '320px: '+route
                    assert not mobile.locator('h1').evaluate('(el)=>el.scrollWidth>el.clientWidth'), 'Heading clipped: '+route
                assert not errors,errors
                browser.close()
                print('PASS: registration, upload, status persistence, admin review, archive publication, search, XSS escaping and 390px mobile navigation; no JS errors.')
        finally:
            http.shutdown()
            http.server_close()


if __name__=='__main__':
    main()
