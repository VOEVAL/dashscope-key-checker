#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Мок DashScope /v1/chat/completions для тестов api_checker.py.

Поведение:
  - ключи, начинающиеся с "sk-ok"   -> HTTP 200 (модель доступна)
  - ключи, начинающиеся с "sk-bad" -> HTTP 401 (неверный ключ)
  - модель "nonexistent-model"     -> HTTP 404 (модель недоступна)
  - небольшая искусственная задержка 0.3с
Запуск: python _mock_dashscope.py  (порт 9911)
"""
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MOCK_PORT = 9911


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a, **k):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            payload = {}
        auth = self.headers.get("Authorization", "")
        key = auth.replace("Bearer ", "").strip()
        model = payload.get("model", "")

        time.sleep(0.3)  # имитация сетевой задержки

        if not key.startswith("sk-ok"):
            self._send(401, {"error": {"code": "InvalidApiKey", "message": "Invalid API key"}})
            return
        if model == "nonexistent-model":
            self._send(404, {"error": {"code": "ModelNotFound", "message": "Model not found"}})
            return
        # успех
        self._send(200, {
            "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
            "usage": {"total_tokens": 5},
        })

    def do_GET(self):
        # чтобы видеть, что мок жив
        body = b"mock dashscope up"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", MOCK_PORT), MockHandler)
    print("Mock DashScope on http://127.0.0.1:%d/v1" % MOCK_PORT)
    srv.serve_forever()


if __name__ == "__main__":
    main()
