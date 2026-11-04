#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
小白菜读论文 · 局域网账号同步服务

用法：
    python 本地同步服务.py            # 默认端口 8788
    python 本地同步服务.py 9000       # 指定端口

手机与电脑连同一个 WiFi，在浏览器打开启动时打印的地址；
在网页顶部「☁ 同步」里注册一个账号，其它设备用同一账号密码登录，即可共享全部数据。
数据保存在本目录（纯本地，不上传任何云端）：
    同步账号.json      账号与密码哈希（PBKDF2-SHA256，不存明文）
    同步数据_<hash>.json  每个账号一份数据
"""
import base64
import hashlib
import json
import os
import re
import socket
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

ROOT = os.path.dirname(os.path.abspath(__file__))
ACCOUNT_FILE = os.path.join(ROOT, '同步账号.json')
APP_PAGE = '事件相机阅读清单.html'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8788

LOCK = threading.Lock()
USER_RE = re.compile(r'^[\w\u4e00-\u9fa5.-]{2,24}$')


def now_ms():
    return int(time.time() * 1000)


def data_file(user):
    h = hashlib.sha1(user.encode('utf-8')).hexdigest()[:16]
    return os.path.join(ROOT, '同步数据_%s.json' % h)


def load_json(path, default):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, obj):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)


def load_accounts():
    a = load_json(ACCOUNT_FILE, {})
    return a if isinstance(a, dict) else {}


def hash_pass(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 120000).hex()


def load_state(user):
    s = load_json(data_file(user), None)
    if isinstance(s, dict) and isinstance(s.get('data'), dict):
        s.setdefault('meta', {})
        s.setdefault('version', 0)
        return s
    return {'version': 0, 'meta': {}, 'data': {}}


def try_json(text):
    try:
        return json.loads(text)
    except Exception:
        return None


def union(a, b):
    """合并两个 JSON 值：数组按 id/内容取并集，对象递归合并，标量 b 覆盖 a。"""
    if isinstance(a, list) and isinstance(b, list):
        out, seen = [], set()
        for it in a + b:
            if isinstance(it, dict) and 'id' in it:
                key = 'id:' + str(it.get('id'))
            else:
                key = json.dumps(it, ensure_ascii=False, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            out.append(it)
        return out
    if isinstance(a, dict) and isinstance(b, dict):
        out = dict(a)
        for k, v in b.items():
            out[k] = union(out[k], v) if k in out else v
        return out
    return b


def merge_payload(state, payload):
    data = state.setdefault('data', {})
    meta = state.setdefault('meta', {})
    in_data = payload.get('data') or {}
    in_meta = payload.get('meta') or {}
    changed = False

    for k, raw in in_data.items():
        if not isinstance(raw, str):
            raw = json.dumps(raw, ensure_ascii=False)
        ts = int(in_meta.get(k) or 0)
        old_ts = int(meta.get(k) or 0)
        if k not in data:
            data[k] = raw
            meta[k] = ts
            changed = True
            continue
        old = data[k]
        if old == raw:
            meta[k] = max(ts, old_ts)
            continue
        ov, nv = try_json(old), try_json(raw)
        if isinstance(ov, (list, dict)) and isinstance(nv, (list, dict)):
            data[k] = json.dumps(union(ov, nv), ensure_ascii=False)
        else:
            data[k] = raw if ts >= old_ts else old
        meta[k] = max(ts, old_ts)
        changed = True

    if changed:
        state['version'] = int(state.get('version') or 0) + 1
    return state


def b64_to_text(v):
    try:
        return base64.b64decode(v.encode('ascii')).decode('utf-8')
    except Exception:
        try:
            return v or ''
        except Exception:
            return ''


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Sync-User, X-Sync-Pass')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        user = b64_to_text(self.headers.get('X-Sync-User') or '').strip()
        password = b64_to_text(self.headers.get('X-Sync-Pass') or '')
        if not user or not password:
            return None, '缺少账号或密码'
        acc = load_accounts().get(user)
        if not acc:
            return None, '账号不存在，请先注册'
        if hash_pass(password, acc.get('salt', '')) != acc.get('hash', ''):
            return None, '密码不正确'
        return user, None

    def _state_payload(self, state):
        return {
            'ok': True,
            'version': state.get('version', 0),
            'meta': state.get('meta', {}),
            'data': state.get('data', {}),
        }

    def _read_body(self):
        try:
            n = int(self.headers.get('Content-Length') or 0)
            return json.loads(self.rfile.read(n).decode('utf-8') or '{}')
        except Exception:
            return None

    def do_GET(self):
        path = self.path.split('?')[0]
        if path in ('/', '/index.html'):
            self.send_response(302)
            self.send_header('Location', '/' + quote(APP_PAGE))
            self.end_headers()
            return
        if path == '/api/state':
            user, err = self._auth()
            if err:
                self._json(401, {'ok': False, 'error': err})
                return
            with LOCK:
                state = load_state(user)
            self._json(200, self._state_payload(state))
            return
        if path == '/api/ping':
            self._json(200, {'ok': True, 'accounts': len(load_accounts())})
            return
        super().do_GET()

    def do_POST(self):
        path = self.path.split('?')[0]
        if path == '/api/register':
            payload = self._read_body()
            if payload is None:
                self._json(400, {'ok': False, 'error': '请求格式错误'})
                return
            user = str(payload.get('user') or '').strip()
            password = str(payload.get('pass') or '')
            if not USER_RE.match(user):
                self._json(400, {'ok': False, 'error': '账号需为 2-24 位中文/字母/数字（不含空格）'})
                return
            if len(password) < 4:
                self._json(400, {'ok': False, 'error': '密码至少 4 位'})
                return
            with LOCK:
                accounts = load_accounts()
                if user in accounts:
                    self._json(409, {'ok': False, 'error': '账号已存在，请直接登录'})
                    return
                salt = hashlib.sha1((user + str(now_ms())).encode('utf-8')).hexdigest()[:16]
                accounts[user] = {'salt': salt, 'hash': hash_pass(password, salt), 'created': now_ms()}
                save_json(ACCOUNT_FILE, accounts)
            self._json(200, {'ok': True, 'user': user})
            return

        if path == '/api/login':
            payload = self._read_body()
            if payload is None:
                self._json(400, {'ok': False, 'error': '请求格式错误'})
                return
            user = str(payload.get('user') or '').strip()
            password = str(payload.get('pass') or '')
            acc = load_accounts().get(user)
            if not acc:
                self._json(401, {'ok': False, 'error': '账号不存在，请先注册'})
                return
            if hash_pass(password, acc.get('salt', '')) != acc.get('hash', ''):
                self._json(401, {'ok': False, 'error': '密码不正确'})
                return
            self._json(200, {'ok': True, 'user': user})
            return

        if path == '/api/state':
            user, err = self._auth()
            if err:
                self._json(401, {'ok': False, 'error': err})
                return
            payload = self._read_body()
            if payload is None:
                self._json(400, {'ok': False, 'error': '请求格式错误'})
                return
            with LOCK:
                state = load_state(user)
                state = merge_payload(state, payload)
                save_json(data_file(user), state)
            self._json(200, self._state_payload(state))
            return

        self.send_error(404)

    def log_message(self, fmt, *args):
        msg = fmt % args
        if '/api/' in msg:
            return
        super().log_message(fmt, *args)


def lan_ips():
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if ip not in ips and not ip.startswith('127.'):
                ips.append(ip)
    except Exception:
        pass
    return ips


def main():
    server = ThreadingHTTPServer(('0.0.0.0', PORT), Handler)
    name = '事件相机阅读清单.html'
    print('=' * 60)
    print(' 小白菜读论文 · 账号同步服务已启动')
    print(' 电脑打开：http://127.0.0.1:%d/%s' % (PORT, name))
    for ip in lan_ips():
        print(' 手机打开：http://%s:%d/%s' % (ip, PORT, name))
    print('')
    print(' 两端打开页面后，点「☁ 同步」注册/登录同一账号即可共享数据。')
    print(' 若手机连不上，请在 Windows 防火墙中允许 python。按 Ctrl+C 停止。')
    print('=' * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n已停止。')


if __name__ == '__main__':
    main()
