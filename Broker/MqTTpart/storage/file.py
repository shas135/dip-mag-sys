import json
import os
import base64


class per_storage():
    def __init__(self, path="mqtt.json"):
        self.path = path
        self.sessions = {}
        self.retained = {}

        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.sessions = decode(data.get("sessions", {}))
                    self.retained = decode(data.get("retained", {}))
            except json.JSONDecodeError:
                self.sessions = {}
                self.retained = {}
        

    async def load_session(self, clientID):
        return self.sessions.get(clientID)

    async def save_session(self, clientID, data):
        self.sessions[clientID] = data
        self._flush()

    async def delete_session(self, clientID):
        self.sessions.pop(clientID, None)
        self._flush()

    async def load_retained(self):
        return dict(self.retained)

    async def save_retained(self, topic, mes):
        self.retained[topic] = mes
        self._flush()

    async def delete_retained(self, topic):
        self.retained.pop(topic, None)
        self._flush()

    def _flush(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "sessions": encode(self.sessions),
                    "retained": encode(self.retained),
                },
                f,
                indent=2,
            )

def encode(obj):
    if isinstance(obj, bytes):
        return {
            "__type__": "bytes",
            "data": base64.b64encode(obj).decode()
        }
    if isinstance(obj, dict):
        return {k: encode(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [encode(v) for v in obj]
    return obj


def decode(obj):
    if isinstance(obj, dict):
        if obj.get("__type__") == "bytes":
            return base64.b64decode(obj["data"])
        return {k: decode(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [decode(v) for v in obj]
    return obj
