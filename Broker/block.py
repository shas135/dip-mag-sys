import json
import os
import ipaddress
from typing import List
class Blocklist:
    def __init__(self, path: str):
        self.path = path
        self._networks: List[ipaddress._BaseNetwork] = []
        self._mtime = 0
        self.load()
    def load(self):
        try: st = os.stat(self.path)
        except FileNotFoundError:
            self._networks = []
            self._mtime = 0
            return
        if st.st_mtime == self._mtime: return
        try:
            with open(self.path, "r", encoding="utf-8") as f: data = json.load(f)
        except Exception as e:
            self._networks = []
            self._mtime = 0
            return
        nets = []
        for item in data.get("blocked", []):
            try:
                if '/' in item: nets.append(ipaddress.ip_network(item, strict=False))
                else: nets.append(ipaddress.ip_network(item + ('/128' if ':' in item else '/32'), strict=False))
            except Exception as e: print(f"В файле блокировок ошибка: {item}: {e}")
        self._networks = nets
        self._mtime = st.st_mtime
        print(f"[Blocks] Загружено {len(self._networks)} блокировок с {self.path}")
    def is_blocked(self, ip: str) -> bool:
        self.load()
        try:  a = ipaddress.ip_address(ip)
        except Exception: return False
        for net in self._networks:
            if a in net: return True
        return False
