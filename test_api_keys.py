#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Простой тестер API-ключей DashScope.
Вставь свои ключи и модели ниже, затем запусти: python test_api_keys.py
"""

import requests
import time
import sys

# ---------------- НАСТРОЙКИ ----------------

# Вставь сюда свои API-ключи (один или несколько)
API_KEYS = [
    "sk-YOUR_KEY_1",
    # "sk-YOUR_KEY_2",
]

# Вставь сюда модели для проверки
MODELS = [
    "qwen-max-latest",
    "qwen-plus-latest",
    "qwen-turbo-latest",
    # добавь свои модели
]

# URL и параметры запроса
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
PROMPT = "Say only 'ok'"
MAX_TOKENS = 5

# Задержка между запросами, чтобы не упереться в rate limit (в секундах)
DELAY = 0.5

# -----------------------------------------

def test_key_model(key, model):
    """Делает тестовый запрос и возвращает (success, message)."""
    url = f"{BASE_URL}/chat/completions"
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": PROMPT}],
        "max_tokens": MAX_TOKENS,
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        if response.status_code == 200:
            data = response.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return True, f"OK ({response.status_code}) -> {content[:60].strip()!r}"
        else:
            try:
                err = response.json()
            except Exception:
                err = response.text
            return False, f"FAIL HTTP {response.status_code} -> {err[:120]}"
    except requests.exceptions.Timeout:
        return False, "TIMEOUT"
    except requests.exceptions.RequestException as e:
        return False, f"REQUEST ERROR: {e}"


def mask_key(key):
    """Скрывает часть ключа для безопасного вывода."""
    if len(key) <= 12:
        return key
    return f"{key[:8]}...{key[-4:]}"


def main():
    print("=" * 60)
    print("DashScope API Key Tester")
    print("=" * 60)

    if not API_KEYS or API_KEYS == ["sk-YOUR_KEY_1"]:
        print("\n[!] Не забудь вставить API-ключи в список API_KEYS")
        sys.exit(1)

    if not MODELS or MODELS == ["qwen-max-latest"]:
        print("\n[!] Не забудь добавить модели в список MODELS")
        sys.exit(1)

    # Чекаем только уникальные ключи (удаляем дубликаты, сохраняя порядок).
    unique_keys, seen = [], set()
    for k in API_KEYS:
        k = k.strip()
        if k and k not in seen:
            seen.add(k)
            unique_keys.append(k)
    dups = len(API_KEYS) - len(unique_keys)
    if dups > 0:
        print(f"[i] Удалено дубликатов ключей: {dups}, проверяю {len(unique_keys)} уникальных")

    results = {}

    for key in unique_keys:
        print(f"\n>>> Ключ: {mask_key(key)}")
        for model in MODELS:
            print(f"   Проверяю модель: {model}... ", end="", flush=True)
            success, msg = test_key_model(key, model)
            status = "OK" if success else "FAIL"
            print(f"{status} | {msg}")
            results.setdefault(mask_key(key), {})[model] = success
            time.sleep(DELAY)

    # Итоговая таблица
    print("\n" + "=" * 60)
    print("ИТОГОВАЯ ТАБЛИЦА")
    print("=" * 60)
    for key_masked, models in results.items():
        print(f"\nКлюч: {key_masked}")
        for model, worked in models.items():
            mark = "[OK]" if worked else "[FAIL]"
            print(f"  {mark} {model}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[!] ОШИБКА: {e}")
    finally:
        print("\n" + "=" * 60)
        input("Нажми Enter, чтобы закрыть окно...\n")