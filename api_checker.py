#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DashScope API Key Checker — локальный веб-апп (один файл).

Запуск:
    python api_checker.py

Открывает браузер на http://127.0.0.1:<порт>/.

Возможности:
  - проверка ключей по списку моделей (параллельно, с настраиваемой задержкой);
  - ключи можно загружать из текстового файла: из «мусорного» текста
    автоматически извлекаются только ключи вида sk-XXXX..., дубликаты удаляются
    (кнопка «[ 📁 ИЗ ФАЙЛА ]»);
  - поддержка HTTP и SOCKS4/5 прокси (поле «Прокси», загрузка списком из файла,
    ротация по кругу); если список прокси пуст — работа напрямую.

Дизайн: тёмная тема в стиле zkPass — «шифрованный терминал»: почти чёрный
холст #060606, единственный акцент — сигнальный лайм #c5ff4a, дисплейный
PT Serif 300, UI — Inter Tight, моноширинный JetBrains Mono, hairline-
границы вместо теней, острые углы.

Зависимости: requests[socks]  (pip install -r requirements.txt;
             PySocks нужен только для SOCKS-прокси)
Выход: Ctrl+C в консоли.
"""

import concurrent.futures
import itertools
import json
import re
import socket
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import requests

# Параметры тестового промпта
TEST_PROMPT = "Say only 'ok'"
REQUEST_TIMEOUT = 30
# Пресет моделей: фиксированный список рабочих моделей эндпоинта
# https://dashscope.aliyuncs.com/compatible-mode/v1
MODEL_PRESET = [
    "ZHIPU/GLM-5.3",
    "ZHIPU/GLM-5.3-Flash",
    "ZHIPU/GLM-5.3-FlashX",
    "deepseek-v4-pro",
    "glm-5.3",
    "glm-5.3-prime",
    "kimi-k3",
    "kimi/kimi-k3",
    "qwen3.8-max",
    "qwen3.8-flash",
]

# Регулярка извлечения ключей из произвольного текста:
# sk- плюс 16 и более букв/цифр (стандартный ключ DashScope: sk- + 32 hex-символа).
KEY_RE = re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9]{16,}")
# Запасной вариант для коротких/нестандартных ключей (например тестовых sk-ok1):
# строка целиком — один токен, начинающийся с sk-.
LOOSE_KEY_RE = re.compile(r"^sk-\S+$")

# Допустимые схемы прокси (socks5h — SOCKS5 с разрешением DNS на стороне прокси).
PROXY_SCHEMES = ("http", "https", "socks4", "socks4h", "socks5", "socks5h")


def mask_key(key):
    """Скрывает часть ключа для безопасного вывода."""
    if len(key) <= 12:
        return key
    return f"{key[:8]}...{key[-4:]}"


def extract_keys(raw_items, stats=None):
    """Извлекает API-ключи из произвольных строк текста.

    Ищет вхождения вида sk-XXXX... (16+ букв/цифр) вперемешку с мусором.
    Строка, не содержащая таких вхождений, но целиком являющаяся токеном
    sk-..., сохраняется как есть (поддержка коротких/тестовых ключей).
    Дубликаты удаляются, порядок первого вхождения сохраняется.

    Если передан stats (dict), записывает в него {"total": сколько всего
    вхождений найдено, "duplicates": сколько из них — дубликаты}.
    """
    keys = []
    seen = set()
    total = 0
    for item in raw_items:
        line = str(item).strip()
        if not line:
            continue
        found = KEY_RE.findall(line)
        if not found:
            parts = line.split()
            if len(parts) == 1 and LOOSE_KEY_RE.match(parts[0]):
                found = parts
        for k in found:
            total += 1
            if k not in seen:
                seen.add(k)
                keys.append(k)
    if stats is not None:
        stats["total"] = total
        stats["duplicates"] = total - len(keys)
    return keys


def normalize_proxy(line):
    """Приводит строку прокси к URL со схемой. None — строка не является прокси.

    Поддерживает http/https/socks4/socks5 (и варианты с h), с логином/паролем
    или без. Строка без схемы считается HTTP-прокси. Пустые строки и
    комментарии (#) игнорируются.
    """
    p = str(line).strip()
    if not p or p.startswith("#"):
        return None
    if "://" not in p:
        p = "http://" + p
    parsed = urlparse(p)
    try:
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme not in PROXY_SCHEMES or not parsed.hostname or not port:
        return None
    return p


def mask_proxy(url):
    """Скрывает пароль прокси для безопасного вывода."""
    parsed = urlparse(url)
    if parsed.password:
        user = parsed.username or ""
        return f"{parsed.scheme}://{user}:***@{parsed.hostname}:{parsed.port}"
    return url


def check_one(key, model, endpoint, max_tokens, proxy=None):
    """Проверяет одну пару (ключ, модель), опционально через прокси.

    Возвращает (success, message, http_status).
    """
    url = f"{endpoint.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": TEST_PROMPT}],
        "max_tokens": max_tokens,
    }
    proxies = {"http": proxy, "https": proxy} if proxy else None
    via = f" · via {mask_proxy(proxy)}" if proxy else ""
    try:
        response = requests.post(url, headers=headers, json=payload,
                                 timeout=REQUEST_TIMEOUT, proxies=proxies)
        if response.status_code == 200:
            try:
                data = response.json()
            except Exception:
                data = {}
            choices = data.get("choices") or [{}]
            content = (choices[0].get("message") or {}).get("content", "") if choices else ""
            return True, f"HTTP 200 -> {str(content)[:60].strip()!r}{via}", 200
        else:
            try:
                err = response.json()
                err_str = str(err)[:120]
            except Exception:
                err_str = response.text[:120]
            return False, f"HTTP {response.status_code} -> {err_str}{via}", response.status_code
    except requests.exceptions.Timeout:
        return False, f"TIMEOUT{via}", None
    except requests.exceptions.ProxyError as e:
        return False, f"PROXY ERROR: {e}{via}", None
    except requests.exceptions.RequestException as e:
        return False, f"REQUEST ERROR: {e}{via}", None


def _interruptible_sleep(stop_event, seconds):
    """Спит seconds, но выходит раньше, если установлен stop_event (отзывчивая отмена)."""
    end = time.time() + seconds
    while not stop_event.is_set():
        remaining = end - time.time()
        if remaining <= 0:
            break
        time.sleep(min(0.1, remaining))


def run_check_session(payload, send_event, stop_event):
    """Оркестрация проверки: пул ключей concurrently, модели в ключе последовательно."""
    endpoint = (payload.get("endpoint") or "").strip()
    key_stats = {}
    keys = extract_keys(payload.get("keys") or [], key_stats)
    models = [m.strip() for m in payload.get("models", []) if m.strip()]
    try:
        delay = float(payload.get("delay", 0.5))
    except (TypeError, ValueError):
        delay = 0.5
    try:
        max_tokens = int(payload.get("max_tokens", 5))
    except (TypeError, ValueError):
        max_tokens = 5
    try:
        max_concurrency = max(1, int(payload.get("max_concurrency", 5)))
    except (TypeError, ValueError):
        max_concurrency = 5

    if not endpoint or not keys or not models:
        if not keys and payload.get("keys"):
            message = "В переданном тексте не найдено ни одного ключа вида sk-..."
        else:
            message = "Не заполнены endpoint, ключи или модели."
        send_event({"type": "error", "message": message})
        return

    parsed = urlparse(endpoint)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        send_event({"type": "error", "message": "Невалидный endpoint URL."})
        return

    # Прокси: нормализуем и отбрасываем невалидные строки. Пустой список = работа напрямую.
    proxies = []
    proxies_invalid = 0
    for line in (payload.get("proxies") or []):
        proxy = normalize_proxy(line)
        if proxy is None:
            if str(line).strip() and not str(line).strip().startswith("#"):
                proxies_invalid += 1
        elif proxy not in proxies:
            proxies.append(proxy)

    if any(urlparse(p).scheme.startswith("socks") for p in proxies):
        try:
            import socks  # noqa: F401  (PySocks — зависимость requests для SOCKS)
        except ImportError:
            send_event({"type": "error",
                        "message": 'Для SOCKS-прокси нужен PySocks: pip install "requests[socks]"'})
            return

    proxy_lock = threading.Lock()
    proxy_counter = itertools.count()

    def next_proxy():
        """Ротация прокси по кругу: каждый следующий запрос идёт через следующий прокси."""
        if not proxies:
            return None
        with proxy_lock:
            return proxies[next(proxy_counter) % len(proxies)]

    # Событие start: фронтенд сразу рисует карточки и чипы.
    send_event({
        "type": "start",
        "total": len(keys) * len(models),
        "keys": [{"index": i, "masked": mask_key(k)} for i, k in enumerate(keys)],
        "models": models,
        "proxies_total": len(proxies),
        "proxies_invalid": proxies_invalid,
        "duplicates_removed": key_stats.get("duplicates", 0),
    })

    t0 = time.time()
    results = [None] * len(keys)
    results_lock = threading.Lock()

    def check_key(key_index):
        if stop_event.is_set():
            return
        key = keys[key_index]
        per = []
        for model in models:
            if stop_event.is_set():
                break
            proxy = next_proxy()
            success, msg, status = check_one(key, model, endpoint, max_tokens, proxy)
            per.append((model, success))
            send_event({
                "type": "result",
                "key_index": key_index,
                "model": model,
                "success": success,
                "message": msg,
                "http_status": status,
                "proxy": mask_proxy(proxy) if proxy else None,
            })
            if stop_event.is_set():
                break
            if delay > 0:
                _interruptible_sleep(stop_event, delay)
        with results_lock:
            results[key_index] = per

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrency) as ex:
        futs = [ex.submit(check_key, i) for i in range(len(keys))]
        for _ in concurrent.futures.as_completed(futs):
            if stop_event.is_set():
                # Не отменяем запущенные, но не ждём хвост — stop уже зафиксирован.
                break

    working_keys_count = 0
    total_success = 0
    for per in results:
        if not per:
            continue
        ok = [s for _, s in per if s]
        if ok:
            working_keys_count += 1
            total_success += len(ok)

    send_event({
        "type": "done",
        "working_keys": working_keys_count,
        "total_success": total_success,
        "total": len(keys) * len(models),
        "elapsed_sec": round(time.time() - t0, 2),
        "stopped": stop_event.is_set(),
    })


# ---------------------------------------------------------------- HTML PAGE
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DashScope Key Checker · Terminal</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter+Tight:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --void:#000000; --carbon:#060606; --graphite:#252525; --onyx:#1f1f1f; --iron:#313131;
  --slate:#3d3d3d; --fog:#525252; --ash:#7a7a7a; --smoke:#8a8a8a; --pearl:#c5c5c5;
  --bone:#e5e5e5; --chalk:#ffffff; --lime:#c5ff4a; --olive:#597321; --moss:#314013;
  --muted:#7a7a8a;
  --font-ui:'Inter Tight',ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  --font-mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;
  --glow:0 0 8px 0 rgba(197,255,74,.45);
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--carbon);color:var(--bone);
  font-family:var(--font-ui);font-size:14px;line-height:1.55}
::selection{background:var(--lime);color:#000}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:var(--carbon)}
::-webkit-scrollbar-thumb{background:var(--iron);border:2px solid var(--carbon)}
::-webkit-scrollbar-thumb:hover{background:var(--olive)}

/* неоновый разделитель — верхний акцент страницы */
.neon-divider{height:6px;background:var(--lime);box-shadow:var(--glow)}

/* ---------- раскладка ---------- */
.wrap{display:grid;grid-template-columns:400px 1fr;gap:16px;padding:24px;
  max-width:1280px;margin:0 auto;align-items:start}
.col-left{display:flex;flex-direction:column;gap:16px;position:sticky;top:16px}
@media(max-width:1000px){.wrap{grid-template-columns:1fr}.col-left{position:static}}

.panel{background:var(--onyx);border:1px solid var(--graphite);border-radius:0;padding:28px}
.panel-head{display:flex;justify-content:space-between;align-items:baseline;gap:10px;
  margin-bottom:20px;border-bottom:1px solid var(--graphite);padding-bottom:12px}
.panel-head h2{margin:0;font-size:11px;font-weight:500;text-transform:uppercase;
  letter-spacing:.22em;color:var(--muted)}
.panel-head .idx{font-family:var(--font-mono);font-size:11px;letter-spacing:.22em;
  color:var(--muted)}

/* ---------- поля ввода ---------- */
.field{margin-bottom:16px}
.field:last-child{margin-bottom:0}
label{display:block;font-size:11px;color:var(--ash);margin-bottom:6px;font-weight:500;
  text-transform:uppercase;letter-spacing:.18em}
label .hint{text-transform:none;letter-spacing:.01em;font-weight:400;color:var(--fog);
  font-size:11px}
input[type=text],input[type=number],textarea{width:100%;background:var(--void);
  border:1px solid var(--graphite);border-radius:4px;padding:10px 12px;color:var(--chalk);
  font-size:13px;font-family:var(--font-mono);transition:border-color .15s,box-shadow .15s}
input::placeholder,textarea::placeholder{color:var(--fog)}
input:focus,textarea:focus{outline:none;border-color:var(--lime);box-shadow:var(--glow)}
textarea{resize:vertical;line-height:1.55;font-size:12.5px}
.settings-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
.preset-link{font-size:11px;color:var(--lime);cursor:pointer;text-decoration:none;
  margin-left:8px;user-select:none;text-transform:uppercase;letter-spacing:.08em}
.preset-link:hover{text-decoration:underline;box-shadow:none}
.file-info{display:block;font-family:var(--font-mono);font-size:11px;color:var(--smoke);
  margin-top:6px;min-height:15px;letter-spacing:.02em}

/* ---------- кнопки ---------- */
.btns{display:flex;gap:10px;margin-top:22px;flex-wrap:wrap}
button.act{flex:1;border-radius:4px;padding:13px 16px;font-family:var(--font-ui);
  font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;
  cursor:pointer;transition:filter .15s,box-shadow .15s,transform .05s}
button.run{background:var(--lime);border:1px solid var(--lime);color:#000;box-shadow:var(--glow)}
button.run:hover{filter:brightness(1.1)}
button.stop{background:transparent;border:1px solid var(--lime);color:var(--lime)}
button.stop:hover{box-shadow:var(--glow)}
button.ghost{background:transparent;border:1px solid var(--slate);color:var(--pearl)}
button.ghost:hover{border-color:var(--fog);color:var(--chalk)}
button:disabled{opacity:.4;cursor:not-allowed;box-shadow:none}
button:active{transform:translateY(1px)}

/* ---------- результаты ---------- */
.results-header{display:flex;justify-content:space-between;align-items:center;
  margin-bottom:10px;gap:10px;flex-wrap:wrap}
.stats{font-family:var(--font-mono);font-size:12px;letter-spacing:.06em;color:var(--smoke);
  text-transform:uppercase}
.stats b{color:var(--chalk)}
.progress{height:4px;background:var(--graphite);overflow:hidden;margin:10px 0 16px}
.progress > div{height:100%;width:0;background:var(--lime);box-shadow:var(--glow);
  transition:width .25s ease}
.empty{color:var(--fog);text-align:center;padding:48px 12px;font-family:var(--font-mono);
  font-size:12px;letter-spacing:.12em;text-transform:uppercase}
.card{background:var(--graphite);border:1px solid var(--iron);padding:16px;margin-bottom:12px;
  transition:border-color .15s}
.card:hover{border-color:var(--fog)}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:10px}
.key-display{font-family:var(--font-mono);font-size:12.5px;font-weight:500;color:var(--chalk);
  word-break:break-all;letter-spacing:.02em}
.key-display.masked{color:var(--smoke)}
.badge{font-size:11px;padding:4px 10px;border-radius:9999px;font-weight:500;
  text-transform:uppercase;letter-spacing:.06em;white-space:nowrap;border:1px solid}
.badge.ok{border-color:var(--lime);color:var(--lime);box-shadow:var(--glow)}
.badge.some{border-color:var(--olive);color:var(--lime)}
.badge.none{border-color:var(--fog);color:var(--ash)}
.badge.pending{border-color:var(--slate);color:var(--smoke)}
.reveal{font-family:var(--font-ui);font-size:10px;text-transform:uppercase;letter-spacing:.12em;
  background:none;border:1px solid var(--slate);color:var(--smoke);border-radius:2px;
  padding:4px 8px;cursor:pointer;transition:color .15s,border-color .15s}
.reveal:hover{color:var(--lime);border-color:var(--lime)}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{font-size:11px;padding:4px 9px;border-radius:2px;font-weight:500;display:inline-flex;
  align-items:center;gap:5px;font-family:var(--font-mono);letter-spacing:.04em;border:1px solid}
.chip.ok{border-color:var(--lime);color:var(--lime)}
.chip.fail{border-color:var(--iron);color:var(--fog);text-decoration:line-through}
.chip.pending{border-color:var(--slate);color:var(--smoke)}
.chip.checking{border-color:var(--olive);color:var(--lime)}
.chip.checking::after{content:'';display:inline-block;width:8px;height:8px;
  border:2px solid currentColor;border-top-color:transparent;border-radius:50%;
  animation:spin .6s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.error-banner{border:1px solid var(--lime);background:rgba(197,255,74,.06);color:var(--bone);
  padding:12px 14px;font-family:var(--font-mono);font-size:12px;letter-spacing:.04em;
  margin-bottom:12px}
.error-banner.warn{border-color:var(--olive)}
.download-bar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:18px;
  padding:18px;background:var(--graphite);border:1px solid var(--iron);border-radius:4px}
.download-bar .label{font-family:var(--font-mono);font-size:11px;letter-spacing:.12em;
  color:var(--smoke);text-transform:uppercase}
.dl-btn{background:transparent;color:var(--lime);border:1px solid var(--lime);border-radius:4px;
  padding:8px 14px;font-family:var(--font-ui);font-size:12px;font-weight:600;
  text-transform:uppercase;letter-spacing:.08em;cursor:pointer;transition:box-shadow .15s}
.dl-btn:hover{box-shadow:var(--glow);background:rgba(197,255,74,.06)}

footer{max-width:1280px;margin:0 auto;text-align:center;color:var(--fog);
  font-family:var(--font-mono);font-size:10px;letter-spacing:.18em;text-transform:uppercase;
  padding:32px 24px 44px;line-height:1.9}
</style>
</head>
<body>
<div class="neon-divider"></div>

<div class="wrap">
  <div class="col-left">

  <!-- ЛЕВАЯ ПАНЕЛЬ: НАСТРОЙКИ -->
  <section class="panel" id="cfgPanel">
    <div class="panel-head">
      <h2>[ Конфигурация · Запуск проверки ]</h2>
      <span class="idx">CF 01</span>
    </div>

    <div class="field">
      <label for="endpoint">Endpoint <span class="hint">· base URL</span></label>
      <input type="text" id="endpoint" placeholder="https://dashscope.aliyuncs.com/compatible-mode/v1">
    </div>

    <div class="field">
      <label for="keys">API-ключи <span class="hint">· извлекутся sk-... из мусора, дубликаты удалятся</span>
        <span class="preset-link" id="keysFileLink" title="Извлечь ключи из текстового файла">[ 📁 из файла ]</span>
      </label>
      <textarea id="keys" rows="5" placeholder="sk-ключ-1&#10;sk-ключ-2"></textarea>
      <span class="file-info" id="keysFileInfo"></span>
      <input type="file" id="keysFileInput" style="display:none">
    </div>

    <div class="field">
      <label for="proxies">Прокси <span class="hint">· HTTP/SOCKS5, по одному в строке; пусто = без прокси</span>
        <span class="preset-link" id="proxiesFileLink" title="Загрузить список прокси из файла">[ 📁 из файла ]</span>
      </label>
      <textarea id="proxies" rows="3" placeholder="http://user:pass@host:port&#10;socks5://host:port"></textarea>
      <span class="file-info" id="proxiesInfo"></span>
      <input type="file" id="proxiesFileInput" style="display:none">
    </div>

    <div class="field">
      <label for="models">Модели <span class="hint">· по одной в строке</span>
        <span class="preset-link" id="presetLink" title="Подставить пресет моделей">[ ↑ пресет ]</span>
      </label>
      <textarea id="models" rows="5" placeholder="qwen3.8-max&#10;ZHIPU/GLM-5.3"></textarea>
    </div>

    <div class="settings-grid">
      <div class="field">
        <label for="delay">Задержка, с</label>
        <input type="number" id="delay" min="0" max="10" step="0.1" value="0.5">
      </div>
      <div class="field">
        <label for="maxTokens">Max tokens</label>
        <input type="number" id="maxTokens" min="1" max="500" step="1" value="5">
      </div>
      <div class="field">
        <label for="concurrency">Потоки</label>
        <input type="number" id="concurrency" min="1" max="50" step="1" value="5">
      </div>
    </div>

    <div class="btns">
      <button class="act run" id="runBtn">▶ Начать проверку</button>
      <button class="act stop" id="stopBtn" style="flex:0 0 auto;display:none">■ Стоп</button>
      <button class="act ghost" id="clearBtn" style="flex:0 0 auto">Очистить</button>
    </div>
  </section>

  </div>

  <!-- ПРАВАЯ ПАНЕЛЬ: РЕЗУЛЬТАТЫ -->
  <section class="panel" id="resPanel">
    <div class="panel-head">
      <h2>[ Результаты · Вывод ]</h2>
      <span class="idx">RS 02</span>
    </div>
    <div class="results-header">
      <div class="stats" id="stats">готово к запуску</div>
      <div class="stats" id="timer"></div>
    </div>
    <div class="progress"><div id="progressBar"></div></div>

    <div id="errorBanner" style="display:none"></div>
    <div id="results">
      <div class="empty">[ введите ключи и модели · нажмите «начать проверку» ]</div>
    </div>

    <div class="download-bar" id="downloadBar" style="display:none">
      <span class="label">[ экспорт рабочих ключей ]</span>
      <button class="dl-btn" data-fmt="json">JSON</button>
      <button class="dl-btn" data-fmt="txt">TXT</button>
      <button class="dl-btn" data-fmt="csv">CSV</button>
      <span class="label" id="dlInfo"></span>
    </div>
  </section>
</div>

<footer>Локальный терминал · данные не покидают компьютер (кроме запросов к DashScope — напрямую или через ваши прокси) · шрифты: Google Fonts</footer>

<script>
'use strict';
const $ = (id) => document.getElementById(id);
const MODEL_PRESET = __MODEL_PRESET_JSON__;
const state = { running:false, results:[], keysFull:[], abort:null, timerInt:null, t0:0 };

// ---------- сохранение настроек ----------
const SAVED_KEYS = ['endpoint','keys','models','proxies','delay','maxTokens','concurrency'];
function saveSettings(){
  const obj = {};
  SAVED_KEYS.forEach(id => obj[id] = $(id).value);
  try { localStorage.setItem('checker_settings', JSON.stringify(obj)); } catch(e){}
}
function loadSettings(){
  let obj = null;
  try { obj = JSON.parse(localStorage.getItem('checker_settings') || 'null'); } catch(e){}
  if(!obj){
    $('endpoint').value = 'https://dashscope.aliyuncs.com/compatible-mode/v1';
    return;
  }
  SAVED_KEYS.forEach(id => { if(obj[id] !== undefined) $(id).value = obj[id]; });
}
SAVED_KEYS.forEach(id => $(id).addEventListener('input', saveSettings));
$('presetLink').addEventListener('click', ()=>{
  $('models').value = MODEL_PRESET.join('\n'); saveSettings();
});
loadSettings();

// ---------- извлечение ключей и загрузка файлов ----------
// Зеркалит extract_keys() на бэкенде: sk- + 16 и более букв/цифр внутри
// произвольного текста; запасной вариант — строка целиком токен sk-...
const KEY_RE = /(^|[^A-Za-z0-9])(sk-[A-Za-z0-9]{16,})/g;
function extractKeysWithStats(text){
  const out = [], seen = new Set();
  let total = 0;
  String(text).split('\n').forEach(line => {
    line = line.trim();
    if(!line) return;
    let found = [];
    let m; KEY_RE.lastIndex = 0;
    while((m = KEY_RE.exec(line)) !== null) found.push(m[2]);
    if(!found.length){
      const parts = line.split(/\s+/);
      if(parts.length === 1 && /^sk-\S+$/.test(parts[0])) found.push(parts[0]);
    }
    found.forEach(k => { total++; if(!seen.has(k)){ seen.add(k); out.push(k); } });
  });
  return { keys: out, duplicates: total - out.length };
}
function extractKeys(text){ return extractKeysWithStats(text).keys; }
// Добавляет строки в textarea без дубликатов; возвращает число новых строк.
function mergeLines(ta, newLines){
  const existing = ta.value.split('\n').map(s => s.trim()).filter(Boolean);
  const seen = new Set(existing);
  let added = 0;
  newLines.forEach(l => { if(l && !seen.has(l)){ seen.add(l); existing.push(l); added++; } });
  ta.value = existing.join('\n');
  saveSettings();
  return added;
}
function bindFileLink(linkId, inputId, onContent){
  const link = $(linkId), input = $(inputId);
  link.addEventListener('click', ()=> input.click());
  input.addEventListener('change', ()=>{
    const f = input.files && input.files[0];
    if(!f) return;
    const reader = new FileReader();
    reader.onload = ()=> onContent(String(reader.result || ''), f.name);
    reader.onerror = ()=> alert('Не удалось прочитать файл: ' + f.name);
    reader.readAsText(f);
    input.value = '';
  });
}
bindFileLink('keysFileLink', 'keysFileInput', (text, name)=>{
  const kx = extractKeysWithStats(text);
  const found = kx.keys;
  if(!found.length){
    $('keysFileInfo').textContent = '⚠ ' + name + ': ключи вида sk-... не найдены';
    return;
  }
  const added = mergeLines($('keys'), found);
  $('keysFileInfo').textContent = '✓ ' + name + ': найдено ключей: ' + found.length +
    (kx.duplicates ? ' (дубликатов в файле: ' + kx.duplicates + ')' : '') + ', добавлено новых: ' + added;
});
bindFileLink('proxiesFileLink', 'proxiesFileInput', (text, name)=>{
  const lines = text.split('\n').map(s => s.trim()).filter(s => s && s.indexOf('#') !== 0);
  if(!lines.length){
    $('proxiesInfo').textContent = '⚠ ' + name + ': прокси в файле не найдены';
    return;
  }
  const added = mergeLines($('proxies'), lines);
  $('proxiesInfo').textContent = '✓ ' + name + ': загружено прокси: ' + lines.length + ', добавлено новых: ' + added;
});

// ---------- утилиты ----------
function escapeHtml(s){ return String(s).replace(/[&<>"']/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

function setRunning(v){
  state.running = v;
  $('runBtn').disabled = v;
  $('stopBtn').style.display = v ? '' : 'none';
  $('cfgPanel').style.opacity = v ? '.7' : '1';
}
function clearResults(){
  state.results = []; state.keysFull = [];
  $('results').innerHTML = '<div class="empty">[ проверка выполняется… ]</div>';
  $('downloadBar').style.display = 'none';
  $('errorBanner').style.display = 'none';
  $('progressBar').style.width = '0%';
  $('stats').textContent = 'выполняется…';
  $('timer').textContent = '';
}
function fmtTime(sec){
  const m = Math.floor(sec/60), s = Math.floor(sec%60);
  return (m>0?m+'м ':'') + s + 'с';
}

// ---------- рендер карточек ----------
function renderCards(){
  const cont = $('results'); cont.innerHTML = '';
  state.results.forEach((r, i) => cont.appendChild(buildCard(i)));
}
function buildCard(i){
  const r = state.results[i];
  const card = document.createElement('div'); card.className = 'card';
  const head = document.createElement('div'); head.className = 'card-head';
  const left = document.createElement('div');
  const kd = document.createElement('span'); kd.className = 'key-display masked';
  kd.textContent = r.masked; kd.dataset.idx = i; kd.dataset.revealed = '0';
  const reveal = document.createElement('button'); reveal.className = 'reveal';
  reveal.textContent = '👁 показать';
  reveal.addEventListener('click', ()=> toggleReveal(i, kd, reveal));
  left.appendChild(kd);
  const badge = document.createElement('span'); badge.className = 'badge pending';
  badge.textContent = 'ожидание';
  head.appendChild(left); head.appendChild(reveal); head.appendChild(badge);
  const chips = document.createElement('div'); chips.className = 'chips';
  r.models.forEach(mo => {
    const c = document.createElement('span'); c.className = 'chip pending';
    c.textContent = mo.model; c.dataset.model = mo.model; chips.appendChild(c);
  });
  card.appendChild(head); card.appendChild(chips);
  r._badge = badge; r._chipsEl = chips; r._kd = kd; r._reveal = reveal;
  return card;
}
function toggleReveal(i, kd, btn){
  const r = state.results[i];
  if(kd.dataset.revealed === '0'){
    kd.textContent = state.keysFull[i] || r.masked;
    kd.classList.remove('masked'); kd.dataset.revealed='1'; btn.textContent='скрыть';
  } else {
    kd.textContent = r.masked; kd.classList.add('masked'); kd.dataset.revealed='0';
    btn.textContent='👁 показать';
  }
}

// ---------- обновление по событиям ----------
function onStart(evt){
  state.keysFull = (state._keysFullSent || []);
  state.results = evt.keys.map(k => ({
    masked: k.masked,
    models: evt.models.map(m => ({model:m, status:'pending', message:''})),
    _badge:null, _chipsEl:null, _kd:null, _reveal:null
  }));
  renderCards();
  state.t0 = Date.now();
  if(state.timerInt) clearInterval(state.timerInt);
  state.timerInt = setInterval(()=>{
    $('timer').textContent = fmtTime((Date.now()-state.t0)/1000);
  }, 500);
  let statsText = 'Проверяю 0/' + evt.total + ' комбинаций…';
  if(evt.proxies_total) statsText += ' · через прокси: ' + evt.proxies_total;
  if(evt.duplicates_removed) statsText += ' · удалено дубликатов: ' + evt.duplicates_removed;
  $('stats').textContent = statsText;
  if(evt.proxies_invalid){
    const b = $('errorBanner');
    b.style.display = ''; b.className = 'error-banner warn';
    b.textContent = '⚠ Пропущено невалидных строк прокси: ' + evt.proxies_invalid;
  }
}
function onResult(evt){
  const r = state.results[evt.key_index]; if(!r) return;
  const m = r.models.find(x => x.model === evt.model);
  if(m){ m.status = evt.success ? 'ok' : 'fail'; m.message = evt.message; }
  if(r._chipsEl){
    const chip = r._chipsEl.querySelector('[data-model="'+CSS.escape(evt.model)+'"]');
    if(chip){
      chip.className = 'chip ' + (evt.success ? 'ok' : 'fail');
      chip.textContent = evt.model + (evt.success ? ' ✓' : ' ✕');
      chip.title = evt.message || '';
    }
  }
  updateCardBadge(r);
  updateProgress();
}
function updateCardBadge(r){
  if(!r._badge) return;
  const ok = r.models.filter(m => m.status==='ok').length;
  const done = r.models.filter(m => m.status!=='pending' && m.status!=='checking').length;
  const total = r.models.length;
  if(done < total){
    r._badge.className = 'badge pending';
    r._badge.textContent = done + '/' + total + '…';
  } else if(ok === total){
    r._badge.className = 'badge ok'; r._badge.textContent = '✓ ' + ok + '/' + total;
  } else if(ok === 0){
    r._badge.className = 'badge none'; r._badge.textContent = '✕ 0/' + total;
  } else {
    r._badge.className = 'badge some'; r._badge.textContent = '⚠ ' + ok + '/' + total;
  }
}
function updateProgress(){
  let done=0, ok=0;
  state.results.forEach(r => r.models.forEach(m => {
    if(m.status==='ok'||m.status==='fail') done++;
    if(m.status==='ok') ok++;
  }));
  const total = state.results.reduce((a,r)=>a+r.models.length, 0) || 1;
  const pct = Math.round(done/total*100);
  $('progressBar').style.width = pct + '%';
  $('stats').textContent = 'Проверено ' + done + '/' + total + ' · ' + ok + ' рабочих · ' + pct + '%';
}
function onDone(evt){
  if(state.timerInt){ clearInterval(state.timerInt); state.timerInt=null; }
  $('timer').textContent = '⏱ ' + fmtTime(evt.elapsed_sec);
  $('progressBar').style.width = '100%';
  $('stats').textContent = (evt.stopped ? 'Остановлено · ' : 'Готово · ') +
    evt.working_keys + ' рабочих ключей · ' + evt.total_success + '/' + evt.total + ' моделей';
  showDownloadBar();
}
// Показать блок скачивания, если есть ≥1 рабочий результат.
function showDownloadBar(){
  const wr = workingResults();
  if(!wr.length){ return; }
  $('downloadBar').style.display = '';
  const totalModels = wr.reduce((a, w) => a + w.models.length, 0);
  $('dlInfo').textContent = wr.length + ' ключей · ' + totalModels + ' моделей';
}
// Финализация при отмене (клиент прервал fetch — done от бэкенда не придёт).
function finalizeStopped(){
  if(state.timerInt){ clearInterval(state.timerInt); state.timerInt=null; }
  $('timer').textContent = '⏱ ' + fmtTime((Date.now() - (state.t0 || Date.now()))/1000);
  const wr = workingResults();
  let done = 0;
  state.results.forEach(r => r.models.forEach(m => { if(m.status==='ok'||m.status==='fail') done++; }));
  const total = state.results.reduce((a,r)=>a+r.models.length, 0);
  const pct = total ? Math.round(done/total*100) : 0;
  $('progressBar').style.width = pct + '%';
  $('stats').textContent = 'Остановлено · ' + wr.length + ' рабочих ключей · ' + done + '/' + total + ' проверено';
  showDownloadBar();
}
function onError(evt){
  const b = $('errorBanner');
  b.style.display = ''; b.className = 'error-banner';
  b.textContent = '⚠ ' + (evt.message || 'Ошибка');
  $('stats').textContent = 'Ошибка';
}

// ---------- сбор рабочих результатов для экспорта ----------
function workingResults(){
  const out = [];
  const checkedAt = new Date().toISOString();
  state.results.forEach((r,i) => {
    const okModels = r.models.filter(m => m.status==='ok').map(m => m.model);
    if(okModels.length){
      out.push({
        key: state.keysFull[i] || r.masked,
        masked: r.masked,
        models: okModels,
        working_count: okModels.length,
        total_checked: r.models.length,
        checked_at: checkedAt
      });
    }
  });
  return out;
}

// ---------- экспорт файлов ----------
function csvField(s){ return '"' + String(s).replace(/"/g, '""') + '"'; }
function downloadFile(fmt){
  const wr = workingResults();
  if(!wr.length){ alert('Нет рабочих ключей для скачивания'); return; }
  let content, mime, ext;
  if(fmt === 'json'){
    content = JSON.stringify(wr, null, 2); mime='application/json'; ext='json';
  } else if(fmt === 'txt'){
    const lines = ['# DashScope working keys',
      '# Checked: ' + new Date().toISOString(),
      '# Total working keys: ' + wr.length, ''];
    wr.forEach(w => lines.push(w.key + ' | ' + w.models.join(', ')));
    content = lines.join('\n'); mime='text/plain'; ext='txt';
  } else if(fmt === 'csv'){
    const rows = ['key,models,working_count'];
    wr.forEach(w => rows.push(
      csvField(w.key) + ',' + csvField(w.models.join('|')) + ',' + w.working_count));
    content = rows.join('\n'); mime='text/csv'; ext='csv';
  } else return;
  const blob = new Blob([content], {type:mime+';charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'dashscope_keys.' + ext;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(a.href), 1000);
}
document.querySelectorAll('.dl-btn').forEach(b => b.addEventListener('click', ()=> downloadFile(b.dataset.fmt)));

// ---------- запуск / стоп ----------
function startCheck(){
  const endpoint = $('endpoint').value.trim();
  const kx = extractKeysWithStats($('keys').value);
  const keys = kx.keys;
  const models = $('models').value.split('\n').map(s => s.trim()).filter(Boolean);
  const proxies = $('proxies').value.split('\n').map(s => s.trim()).filter(s => s && s.indexOf('#') !== 0);
  if(!endpoint){ alert('Укажите endpoint'); return; }
  if(!keys.length){ alert('Введите хотя бы один ключ вида sk-...'); return; }
  if(!models.length){ alert('Введите хотя бы одну модель'); return; }
  if(kx.duplicates > 0){
    $('keysFileInfo').textContent = 'ℹ Удалено дубликатов ключей: ' + kx.duplicates +
      ', проверяю ' + keys.length + ' уникальных';
  }
  saveSettings();
  state.keysFull = keys;                 // храним полные ключи локально (для экспорта)
  state._keysFullSent = keys;
  clearResults();
  setRunning(true);
  state.abort = new AbortController();
  fetch('/api/check', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      endpoint: endpoint, keys: keys, models: models, proxies: proxies,
      delay: parseFloat($('delay').value) || 0,
      max_tokens: parseInt($('maxTokens').value) || 5,
      max_concurrency: parseInt($('concurrency').value) || 5
    }),
    signal: state.abort.signal
  }).then(async (resp) => {
    if(!resp.body){ throw new Error('Нет потока ответа'); }
    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    while(true){
      const {done, value} = await reader.read();
      if(done) break;
      buf += dec.decode(value, {stream:true});
      let idx;
      while((idx = buf.indexOf('\n\n')) >= 0){
        const chunk = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        handleChunk(chunk);
      }
    }
    if(buf.trim()) handleChunk(buf);
    finishRun();
  }).catch((e) => {
    if(e.name === 'AbortError'){
      finalizeStopped();
    } else {
      $('stats').textContent = 'Ошибка соединения';
      alert('Ошибка: ' + e.message);
    }
    finishRun();
  });
}
function finishRun(){
  if(state.timerInt){ clearInterval(state.timerInt); state.timerInt=null; }
  setRunning(false);
}
function handleChunk(chunk){
  const lines = chunk.split('\n');
  let dataStr = '';
  for(const line of lines){ if(line.indexOf('data:') === 0) dataStr += line.slice(5); }
  dataStr = dataStr.trim();
  if(!dataStr) return;
  let evt; try { evt = JSON.parse(dataStr); } catch(e){ return; }
  switch(evt.type){
    case 'start':  onStart(evt); break;
    case 'result': onResult(evt); break;
    case 'done':   onDone(evt); break;
    case 'error':  onError(evt); break;
  }
}
function stopCheck(){
  if(state.abort){ try { state.abort.abort(); } catch(e){} }
  finishRun();
}
$('runBtn').addEventListener('click', startCheck);
$('stopBtn').addEventListener('click', stopCheck);
$('clearBtn').addEventListener('click', ()=>{
  if(state.running) return;
  state.results=[]; state.keysFull=[];
  $('results').innerHTML = '<div class="empty">[ введите ключи и модели · нажмите «начать проверку» ]</div>';
  $('downloadBar').style.display='none';
  $('errorBanner').style.display='none';
  $('progressBar').style.width='0%';
  $('stats').textContent='готово к запуску';
  $('timer').textContent='';
});
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args, **kwargs):
        pass  # тишина в консоли

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            preset_json = json.dumps(MODEL_PRESET, ensure_ascii=False)
            body = HTML_PAGE.replace("__MODEL_PRESET_JSON__", preset_json).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):
        if self.path != "/api/check":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            payload = {}

        # SSE-поток с chunked-encoding для надёжной стриминг-доставки в браузер.
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        send_lock = threading.Lock()
        stop_event = threading.Event()

        def write_chunk(data_bytes):
            # фрейм chunked: <hex-len>\r\n<data>\r\n
            self.wfile.write(("{0:X}\r\n".format(len(data_bytes))).encode("ascii"))
            self.wfile.write(data_bytes)
            self.wfile.write(b"\r\n")
            self.wfile.flush()

        def send_event(evt):
            if stop_event.is_set():
                return
            line = "data: " + json.dumps(evt, ensure_ascii=False) + "\n\n"
            with send_lock:
                try:
                    write_chunk(line.encode("utf-8"))
                except (BrokenPipeError, ConnectionResetError, OSError):
                    stop_event.set()

        try:
            run_check_session(payload, send_event, stop_event)
        except Exception as e:
            try:
                send_event({"type": "error", "message": "Внутренняя ошибка: {0}".format(e)})
            except Exception:
                pass
        finally:
            # завершающий нулевой chunk закрывает поток корректно
            try:
                with send_lock:
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
            except Exception:
                pass
            self.close_connection = True


def find_free_port(preferred=(8765, 8766, 8767, 8768, 8769, 8770)):
    for p in preferred:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    print("=" * 60)
    print("DashScope API Key Checker · zkPass Terminal")
    print("=" * 60)
    port = find_free_port()
    url = "http://127.0.0.1:{0}/".format(port)
    print("Сервер запущен: {0}".format(url))
    print("Шрифты подгружаются из интернета (Google Fonts).")
    print("Открываю браузер... (Ctrl+C для выхода)")
    print("=" * 60)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстанавливаю сервер...")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
