# -*- coding: utf-8 -*-
"""Временный тест новых возможностей api_checker.py (извлечение ключей, прокси).

Запуск:  python _test_features.py
После проверки файл можно удалить.
"""
import io
import sys
import threading
import time
from http.server import ThreadingHTTPServer

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import requests as rq

import api_checker as ac
from _mock_dashscope import MOCK_PORT, MockHandler

FAILURES = []


def check(name, cond, detail=""):
    print("[{}] {}".format("PASS" if cond else "FAIL", name))
    if not cond:
        FAILURES.append(name)
        if detail:
            print("       detail: {}".format(detail))


# ---------- unit: extract_keys ----------
junk = [
    "2026-10-01 | token: sk-DEADBEEFDEADBEEFDEADBEEFDEADBEEF | paid",
    "no keys here at all",
    '{"keys": ["sk-CAFEBABECAFEBABECAFEBABECAFEBABE", "not-a-key"]}',
    "backup=sk-0123456789ABCDEF0123456789ABCDEF; done",
    "sk-DEADBEEFDEADBEEFDEADBEEFDEADBEEF",  # дубликат
    "sk-ok1",                                # короткий тестовый ключ (fallback)
    "",
    "   ",
    "multi word junk sk-123",                # короткий ключ внутри фразы — не извлекается
]
keys = ac.extract_keys(junk)
check("extract_keys: 4 ключа из мусора", len(keys) == 4, repr(keys))
check("extract_keys: порядок и дедуп", keys == [
    "sk-DEADBEEFDEADBEEFDEADBEEFDEADBEEF",
    "sk-CAFEBABECAFEBABECAFEBABECAFEBABE",
    "sk-0123456789ABCDEF0123456789ABCDEF",
    "sk-ok1",
], repr(keys))
check("extract_keys: идемпотентность", ac.extract_keys(keys) == keys)
stats = {}
k2 = ac.extract_keys(["sk-DEADBEEFDEADBEEFDEADBEEFDEADBEEF",
                      "x sk-DEADBEEFDEADBEEFDEADBEEFDEADBEEF y"], stats)
check("extract_keys: stats считает дубликаты",
      stats == {"total": 2, "duplicates": 1} and len(k2) == 1, repr(stats))

# ---------- unit: normalize_proxy / mask_proxy ----------
check("proxy: host:port -> http", ac.normalize_proxy("1.2.3.4:8080") == "http://1.2.3.4:8080")
check("proxy: http с авторизацией", ac.normalize_proxy("http://user:pass@1.2.3.4:8080") == "http://user:pass@1.2.3.4:8080")
check("proxy: user:pass@host:port без схемы", ac.normalize_proxy("user:pass@1.2.3.4:8080") == "http://user:pass@1.2.3.4:8080")
check("proxy: socks5", ac.normalize_proxy("socks5://1.2.3.4:1080") == "socks5://1.2.3.4:1080")
check("proxy: socks5h", ac.normalize_proxy("socks5h://1.2.3.4:1080") == "socks5h://1.2.3.4:1080")
check("proxy: комментарий -> None", ac.normalize_proxy("# comment") is None)
check("proxy: пусто -> None", ac.normalize_proxy("   ") is None)
check("proxy: без порта -> None", ac.normalize_proxy("http://1.2.3.4") is None)
check("proxy: мусор -> None", ac.normalize_proxy("not a proxy") is None)
check("proxy: чужая схема -> None", ac.normalize_proxy("ftp://1.2.3.4:21") is None)
check("mask_proxy: пароль скрыт", ac.mask_proxy("http://user:secret@1.2.3.4:8080") == "http://user:***@1.2.3.4:8080")
check("mask_proxy: без пароля — без изменений", ac.mask_proxy("socks5://1.2.3.4:1080") == "socks5://1.2.3.4:1080")

# ---------- интеграция с мок-сервером ----------
srv = ThreadingHTTPServer(("127.0.0.1", MOCK_PORT), MockHandler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.3)
ENDPOINT = "http://127.0.0.1:{}/v1".format(MOCK_PORT)


def run_session(payload):
    events = []
    ac.run_check_session(payload, events.append, threading.Event())
    return events


# 1) без прокси
ev = run_session({"endpoint": ENDPOINT, "keys": ["sk-ok1", "sk-bad1"],
                  "models": ["qwen-test"], "delay": 0})
start = next(e for e in ev if e["type"] == "start")
check("сессия: total=2", start["total"] == 2)
check("сессия: прокси=0", start["proxies_total"] == 0 and start["proxies_invalid"] == 0)
by_key = {e["key_index"]: e for e in ev if e["type"] == "result"}
check("сессия: sk-ok1 -> 200", by_key[0]["success"] and by_key[0]["http_status"] == 200)
check("сессия: sk-bad1 -> 401", not by_key[1]["success"] and by_key[1]["http_status"] == 401)
check("сессия: proxy=None в результате", by_key[0]["proxy"] is None)
done = next(e for e in ev if e["type"] == "done")
check("сессия: working_keys=1", done["working_keys"] == 1)

# 1b) одинаковые ключи удаляются при старте — чекается только уникальный
ev = run_session({"endpoint": ENDPOINT, "keys": ["sk-ok1", "sk-ok1", "sk-ok1"],
                  "models": ["qwen-test"], "delay": 0})
start = next(e for e in ev if e["type"] == "start")
check("сессия: duplicates_removed=2, total=1",
      start["duplicates_removed"] == 2 and start["total"] == 1 and len(start["keys"]) == 1, repr(start))
res = [e for e in ev if e["type"] == "result"]
check("сессия: уникальный ключ проверен один раз", len(res) == 1 and res[0]["success"], repr(res))

# 2) невалидные строки прокси игнорируются, работа напрямую
ev = run_session({"endpoint": ENDPOINT, "keys": ["sk-ok1"], "models": ["qwen-test"],
                  "proxies": ["", "# comment", "garbage line"], "delay": 0})
start = next(e for e in ev if e["type"] == "start")
check("сессия: невалидный прокси учтён", start["proxies_invalid"] == 1 and start["proxies_total"] == 0, repr(start))
res = [e for e in ev if e["type"] == "result"]
check("сессия: без валидных прокси работает напрямую", res[0]["success"])

# 3) мёртвый HTTP-прокси -> понятная ошибка с пометкой via
ev = run_session({"endpoint": ENDPOINT, "keys": ["sk-ok1"], "models": ["qwen-test"],
                  "proxies": ["127.0.0.1:9"], "delay": 0})
res = [e for e in ev if e["type"] == "result"]
check("сессия: мёртвый прокси -> fail", not res[0]["success"])
check("сессия: в сообщении есть via", "via http://127.0.0.1:9" in res[0]["message"], res[0]["message"])
check("сессия: поле proxy заполнено", res[0]["proxy"] == "http://127.0.0.1:9")

# 4) текст без извлекаемых ключей -> error-событие
ev = run_session({"endpoint": ENDPOINT, "keys": ["just some words"],
                  "models": ["qwen-test"], "delay": 0})
check("сессия: нет ключей -> error", ev and ev[0]["type"] == "error", repr(ev))

# 5) ротация между двумя прокси
ev = run_session({"endpoint": ENDPOINT, "keys": ["sk-ok1", "sk-bad1"], "models": ["m1", "m2"],
                  "proxies": ["127.0.0.1:9", "127.0.0.1:8"], "delay": 0})
used = {e["proxy"] for e in ev if e["type"] == "result"}
check("сессия: ротация прокси", used == {"http://127.0.0.1:9", "http://127.0.0.1:8"}, repr(used))

# 6) SOCKS5: с PySocks — корректный fail, без PySocks — подсказка об установке
try:
    import socks  # noqa: F401
    have_socks = True
except ImportError:
    have_socks = False
ev = run_session({"endpoint": ENDPOINT, "keys": ["sk-ok1"], "models": ["qwen-test"],
                  "proxies": ["socks5://127.0.0.1:9"], "delay": 0})
if have_socks:
    res = [e for e in ev if e["type"] == "result"]
    check("сессия: мёртвый socks5 -> fail без падения", bool(res) and not res[0]["success"], repr(ev))
else:
    check("сессия: socks5 без PySocks -> подсказка", ev and ev[0]["type"] == "error" and "PySocks" in ev[0]["message"], repr(ev))

srv.shutdown()
srv.server_close()

# 7) веб-страница отдаётся и содержит новую разметку
port = ac.find_free_port()
httpd = ThreadingHTTPServer(("127.0.0.1", port), ac.Handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
time.sleep(0.2)
page = rq.get("http://127.0.0.1:{}/".format(port), timeout=5).text
for marker in ["keysFileLink", "proxiesFileLink", "extractKeys", "extractKeysWithStats",
               'id="proxies"', "bindFileLink", "'proxies'", "keysFileInfo", "proxiesInfo",
               "duplicates_removed", "Удалено дубликатов",
               "neon-divider", "#c5ff4a"]:
    check("страница содержит {}".format(marker), marker in page)
check("страница: старая тема-переключатель убрана", "themeBtn" not in page)
check("страница: верхняя панель, герой и навигация удалены",
      "topnav" not in page and 'class="hero"' not in page and "nav-links" not in page
      and "Ключи. Прокси." not in page and ">Operator</a>" not in page)
check("страница: вайфу-механика полностью удалена",
      "waifuPanel" not in page and "waifuImg" not in page and "loadWaifu" not in page)

# /api/waifu удалён вместе с механикой: эндпоинт отвечает 404
r = rq.get("http://127.0.0.1:{}/api/waifu".format(port), timeout=10)
check("/api/waifu удалён -> 404", r.status_code == 404, str(r.status_code))

httpd.shutdown()
httpd.server_close()

print()
if FAILURES:
    print("FAILED {}: {}".format(len(FAILURES), FAILURES))
    sys.exit(1)
print("ALL TESTS PASSED")
