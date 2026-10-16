# 🔑 DashScope Key Checker · Terminal

**RU:** Локальный веб-терминал для проверки API-ключей DashScope в эстетике «шифрованного терминала»: почти чёрный холст, сигнальный лайм `#c5ff4a`, моноширинный вывод. Вставляете ключи (или файл-помойку) — получаете честную карту рабочих моделей и экспорт живых ключей.

**EN:** A local web terminal for checking DashScope API keys, styled as an encrypted terminal: near-black canvas, signal lime `#c5ff4a`, monospace output. Paste keys (or a junk file) — get an honest map of working models and export the living keys.

---

## ✨ Возможности / Features

**RU**
- Проверка «ключи × модели» параллельно: потоки, задержка и max tokens настраиваются в UI.
- Извлечение `sk-...` ключей из любого мусорного текста — логи, JSON-дампы, переписки: остаются только ключи, дубликаты удаляются автоматически.
- Загрузка ключей и прокси из текстовых файлов одной кнопкой «📁 ИЗ ФАЙЛА».
- HTTP / HTTPS / SOCKS4 / SOCKS5 прокси с ротацией по кругу; пустой список = работа напрямую.
- Живой поток результатов (SSE): карточки ключей, чипы моделей, прогресс-бар, отмена на лету.
- Экспорт рабочих ключей: JSON / TXT / CSV.
- Тёмная тема в духе zkPass: hairline-границы вместо теней, острые углы, один неоновый акцент.

**EN**
- Parallel “keys × models” checks: concurrency, delay and max tokens configurable in the UI.
- Extracts `sk-...` keys from any junk text — logs, JSON dumps, chat exports: keys only, duplicates removed automatically.
- One-click “📁 FROM FILE” upload for both keys and proxies.
- HTTP / HTTPS / SOCKS4 / SOCKS5 proxies with round-robin rotation; empty list = direct connection.
- Live SSE result stream: key cards, model chips, progress bar, instant stop.
- Working-key export: JSON / TXT / CSV.
- zkPass-flavoured dark theme: hairline borders instead of shadows, sharp corners, a single neon accent.

## 🚀 Быстрый старт / Quick start

```bash
pip install -r requirements.txt
python api_checker.py
# браузер откроется сам / the browser opens automatically
```

## 🧪 Тесты / Tests

```bash
python test_features.py
# юнит-тесты + интеграция с мок-сервером DashScope / unit tests + DashScope mock-server integration
```

## 📁 Структура / Layout

| Файл / File | Назначение / Purpose |
|---|---|
| `api_checker.py` | Весь апп: бэкенд + веб-UI в одном файле / The whole app: backend + web UI in one file |
| `test_api_keys.py` | Консольный тестер ключей / Console key tester |
| `test_api_keys_gui.py` | tkinter-тестер ключей / tkinter key tester |
| `test_features.py` | Автотесты возможностей / Feature test suite |
| `_mock_dashscope.py` | Мок DashScope API для тестов / DashScope API mock for tests |
| `keys.example.txt` | Пример файла-помойки с ключами / Sample junk file with embedded keys |
| `proxies.example.txt` | Формат списка прокси / Proxy list format reference |

## ⚠️ Дисклеймер / Disclaimer

**RU:** Инструмент предназначен для проверки ваших собственных ключей и прокси. Не используйте чужие ключи.
**EN:** This tool is meant for checking your own keys and proxies. Do not use keys that are not yours.
