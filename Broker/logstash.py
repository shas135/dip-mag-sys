import json
import asyncio
import urllib.request
import urllib.error
from datetime import datetime, timezone

class send_logstash:
    def __init__(self, url: str):
        self.url = url

    @staticmethod
    def _utc_now():
        return datetime.now(timezone.utc).isoformat()

    def _post_sync(self, payload: dict):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",)
        with urllib.request.urlopen(req, timeout=3) as resp:
            resp.read()

    async def send(self, payload: dict):
        #payload.setdefault("source_type", "broker")
        payload.setdefault("timestamp", self._utc_now())
        try:
            await asyncio.to_thread(self._post_sync, payload)
        except Exception as e:
            print(f"[logstash] ошибка отправки: {e}")

    async def blocked_ip(self, protocol, client_ip, username=None, details=None):
        payload = {
            "event": "Попытка доступа с заблокированного адреса",
            "protocol": protocol,
            "client_ip": client_ip,
            "username": username,
            "reason": "IP заблокирован",
            "details": details or {},
        }
        await self.send(payload)

    async def auth_failure(self, protocol, client_ip, username=None):
        payload = {
            "event": "Неудачная аутентификация",
            "protocol": protocol,
            "client_ip": client_ip,
            "username": username,
            "reason": "Неверные учетные данные",
        }
        await self.send(payload)

    async def acl_break(self, protocol, client_ip, username=None, action=None, target=None):
        payload = {
            "event": "Попытка нарушения ACL",
            "protocol": protocol,
            "client_ip": client_ip,
            "username": username,
            "action": action,
            "target": target,
            "reason": "Отказ в доступе",
        }
        await self.send(payload)
