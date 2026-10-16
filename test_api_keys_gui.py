#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GUI-тестер API-ключей DashScope (tkinter)."""

import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

import requests


class ApiTesterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DashScope API Key Tester")
        self.root.geometry("900x700")
        self.root.minsize(700, 500)

        # Заголовок
        tk.Label(root, text="DashScope API Key Tester", font=("Segoe UI", 16, "bold")).pack(pady=10)

        # --- Ввод API-ключей ---
        frame_keys = tk.LabelFrame(root, text="API-ключи (по одному на строку)", font=("Segoe UI", 10, "bold"), padx=10, pady=5)
        frame_keys.pack(fill=tk.BOTH, expand=False, padx=10, pady=5)
        self.keys_text = scrolledtext.ScrolledText(frame_keys, height=6, wrap=tk.WORD)
        self.keys_text.pack(fill=tk.BOTH, expand=True)
        self._bind_paste(self.keys_text)

        # --- Ввод эндпоинта ---
        frame_url = tk.LabelFrame(root, text="Endpoint (base URL)", font=("Segoe UI", 10, "bold"), padx=10, pady=5)
        frame_url.pack(fill=tk.X, padx=10, pady=5)
        self.url_entry = tk.Entry(frame_url)
        self.url_entry.insert(0, "https://dashscope.aliyuncs.com/compatible-mode/v1")
        self.url_entry.pack(fill=tk.X, expand=True)
        self._bind_paste(self.url_entry)

        # --- Ввод моделей ---
        frame_models = tk.LabelFrame(root, text="Модели (по одному на строку)", font=("Segoe UI", 10, "bold"), padx=10, pady=5)
        frame_models.pack(fill=tk.BOTH, expand=False, padx=10, pady=5)
        self.models_text = scrolledtext.ScrolledText(frame_models, height=6, wrap=tk.WORD)
        self.models_text.pack(fill=tk.BOTH, expand=True)
        self._bind_paste(self.models_text)

        # --- Настройки ---
        frame_settings = tk.LabelFrame(root, text="Настройки", font=("Segoe UI", 10, "bold"), padx=10, pady=5)
        frame_settings.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(frame_settings, text="Задержка между запросами (сек):").grid(row=0, column=0, sticky="w")
        self.delay_var = tk.DoubleVar(value=0.5)
        tk.Spinbox(frame_settings, from_=0, to=10, increment=0.1, textvariable=self.delay_var, width=5).grid(row=0, column=1, sticky="w", padx=5)

        tk.Label(frame_settings, text="Max tokens:").grid(row=0, column=2, sticky="w", padx=(30, 0))
        self.max_tokens_var = tk.IntVar(value=5)
        tk.Spinbox(frame_settings, from_=1, to=500, increment=1, textvariable=self.max_tokens_var, width=5).grid(row=0, column=3, sticky="w", padx=5)

        # --- Кнопки ---
        frame_buttons = tk.Frame(root)
        frame_buttons.pack(fill=tk.X, padx=10, pady=10)
        self.run_btn = tk.Button(frame_buttons, text="Запустить проверку", font=("Segoe UI", 11, "bold"), bg="#4CAF50", fg="white", command=self.start_check)
        self.run_btn.pack(side=tk.LEFT, padx=5)
        self.clear_btn = tk.Button(frame_buttons, text="Очистить лог", command=self.clear_log)
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        # --- Прогресс ---
        self.progress = ttk.Progressbar(root, mode="determinate")
        self.progress.pack(fill=tk.X, padx=10, pady=5)

        # --- Лог результатов ---
        frame_log = tk.LabelFrame(root, text="Лог результатов", font=("Segoe UI", 10, "bold"), padx=10, pady=5)
        frame_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.log = scrolledtext.ScrolledText(frame_log, wrap=tk.WORD, state=tk.DISABLED)
        self.log.pack(fill=tk.BOTH, expand=True)

    def _bind_paste(self, widget):
        """Добавляет вставку через Ctrl+V и правый клик."""
        # Для ScrolledText получаем внутренний Text-виджет
        target = widget
        if isinstance(widget, scrolledtext.ScrolledText):
            children = [c for c in widget.winfo_children() if isinstance(c, tk.Text)]
            if children:
                target = children[0]

        def do_paste(event=None):
            try:
                text = self.root.clipboard_get()
            except tk.TclError:
                return "break"
            try:
                target.insert(tk.INSERT, text)
            except tk.TclError:
                return "break"
            return "break"

        def select_all():
            if isinstance(target, tk.Entry):
                target.select_range(0, tk.END)
                target.icursor(tk.END)
            else:
                target.tag_add("sel", "1.0", tk.END)
                target.mark_set(tk.INSERT, tk.END)

        def show_menu(event):
            menu = tk.Menu(target, tearoff=0)
            menu.add_command(label="Вставить (Ctrl+V)", command=do_paste)
            menu.add_command(label="Выделить всё (Ctrl+A)", command=select_all)
            menu.tk_popup(event.x_root, event.y_root)

        target.bind("<Control-v>", do_paste)
        target.bind("<Control-V>", do_paste)
        target.bind("<Button-3>", show_menu)
        target.bind("<Control-a>", lambda e: (select_all(), "break"))
        target.bind("<Control-A>", lambda e: (select_all(), "break"))

    def log_write(self, text, tag=None):
        self.log.config(state=tk.NORMAL)
        self.log.insert(tk.END, text + "\n", tag)
        self.log.see(tk.END)
        self.log.config(state=tk.DISABLED)
        self.root.update_idletasks()

    def clear_log(self):
        self.log.config(state=tk.NORMAL)
        self.log.delete(1.0, tk.END)
        self.log.config(state=tk.DISABLED)

    def start_check(self):
        keys_raw = self.keys_text.get("1.0", tk.END).strip()
        models_raw = self.models_text.get("1.0", tk.END).strip()
        base_url = self.url_entry.get().strip()

        if not keys_raw:
            messagebox.showwarning("Нет ключей", "Введите хотя бы один API-ключ")
            return
        if not models_raw:
            messagebox.showwarning("Нет моделей", "Введите хотя бы одну модель")
            return
        if not base_url:
            messagebox.showwarning("Нет endpoint", "Введите endpoint URL")
            return

        keys = [k.strip() for k in keys_raw.splitlines() if k.strip()]
        models = [m.strip() for m in models_raw.splitlines() if m.strip()]

        # Чекаем только уникальные ключи (удаляем дубликаты, сохраняя порядок).
        unique_keys, seen = [], set()
        for k in keys:
            if k not in seen:
                seen.add(k)
                unique_keys.append(k)
        dups = len(keys) - len(unique_keys)
        keys = unique_keys

        self.run_btn.config(state=tk.DISABLED, text="Проверка...")
        self.progress["value"] = 0
        self.progress["maximum"] = len(keys) * len(models)

        thread = threading.Thread(target=self.check_worker, args=(keys, models, base_url, dups), daemon=True)
        thread.start()

    def check_worker(self, keys, models, base_url, dups=0):
        delay = self.delay_var.get()
        max_tokens = self.max_tokens_var.get()
        prompt = "Say only 'ok'"

        total = len(keys) * len(models)
        count = 0
        all_results = {}

        self.root.after(0, self.log_write, f"Начинаю проверку {len(keys)} ключей x {len(models)} моделей = {total} комбинаций")
        if dups:
            self.root.after(0, self.log_write, f"[i] Удалено дубликатов ключей: {dups}, проверяю {len(keys)} уникальных")
        self.root.after(0, self.log_write, f"Endpoint: {base_url}")
        self.root.after(0, self.log_write, "-" * 60)

        for key in keys:
            masked = self.mask_key(key)
            self.root.after(0, self.log_write, f"\n>>> Ключ: {masked}")
            per_key_results = []
            for model in models:
                count += 1
                success, msg = self.test_key_model(key, model, base_url, prompt, max_tokens)
                per_key_results.append((model, success))
                mark = "OK" if success else "FAIL"
                self.root.after(0, self.log_write, f"[{mark}] {model}: {msg}")
                self.root.after(0, self.progress.step, 1)
                time.sleep(delay)
            all_results[masked] = per_key_results

        self.root.after(0, self.print_summary, all_results)
        self.root.after(0, self.run_btn.config, {"state": tk.NORMAL, "text": "Запустить проверку"})

    def print_summary(self, results):
        self.root.after(0, self.log_write, "\n" + "=" * 60)
        self.root.after(0, self.log_write, "ИТОГОВЫЙ РЕЗУЛЬТАТ")
        self.root.after(0, self.log_write, "=" * 60)

        for key, models_result in results.items():
            working = [m for m, ok in models_result if ok]
            failed = [m for m, ok in models_result if not ok]

            self.root.after(0, self.log_write, f"\n🔑 Ключ: {key}")
            self.root.after(0, self.log_write, f"   Работает моделей: {len(working)} / {len(models_result)}")

            if working:
                self.root.after(0, self.log_write, "   ✅ Работают:")
                for m in working:
                    self.root.after(0, self.log_write, f"      • {m}")
            else:
                self.root.after(0, self.log_write, "   ✅ Работают: нет")

            if failed:
                self.root.after(0, self.log_write, "   ❌ Не работают:")
                for m in failed:
                    self.root.after(0, self.log_write, f"      • {m}")

        self.root.after(0, self.log_write, "\n" + "=" * 60)
        self.root.after(0, self.log_write, "ПРОВЕРКА ЗАВЕРШЕНА")

    def test_key_model(self, key, model, base_url, prompt, max_tokens):
        url = f"{base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            if response.status_code == 200:
                data = response.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                return True, f"HTTP 200 -> {content[:60].strip()!r}"
            else:
                try:
                    err = response.json()
                except Exception:
                    err = response.text
                return False, f"HTTP {response.status_code} -> {str(err)[:120]}"
        except requests.exceptions.Timeout:
            return False, "TIMEOUT"
        except requests.exceptions.RequestException as e:
            return False, f"REQUEST ERROR: {e}"

    @staticmethod
    def mask_key(key):
        if len(key) <= 12:
            return key
        return f"{key[:8]}...{key[-4:]}"


def main():
    try:
        import requests
    except ImportError:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Нет библиотеки", "Установи requests:\npip install requests")
        return

    root = tk.Tk()
    app = ApiTesterApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()