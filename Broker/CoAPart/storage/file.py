import json
import os
class per_storage():
    def __init__(self, path="coap.json"):
        self.path = path
        self.resources = {}
        self.observers = {}
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.resources = {
                    bytes.fromhex(k): bytes.fromhex(v)
                    for k, v in data.get("resources", {}).items()
                }
                self.observers = {}
                for k, lst in data.get("observers", {}).items():
                    path_b = bytes.fromhex(k)
                    self.observers[path_b] = {
                        ((ip, port), bytes.fromhex(token_hex))
                        for ip, port, token_hex in lst
                    }
    def _flush(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "resources": {
                        k.hex(): v.hex()
                        for k, v in self.resources.items()
                    },
                    "observers": {
                        k.hex(): [
                            [addr[0], addr[1], token.hex()]
                            for addr, token in obs
                        ]
                        for k, obs in self.observers.items()
                    }
                },
                f,
                indent=2
                    )
    async def get_resource(self, path):
        return self.resources.get(path)
    async def set_resource(self, path, value):
        self.resources[path] = value
        self._flush()
    async def delete_resource(self, path):
        self.resources.pop(path, None)
        self._flush()
    async def list_resources(self):
        return list(self.resources.keys())
    async def list_observer(self):
        return list(self.observer.keys())
    async def add_observer(self, path, addr, token):
        #print(f"   AAAA   add_observer{self.observers.items()}")
        self.observers.setdefault(path, set()).add((addr, token))
        self._flush()
    async def remove_observer(self, path, addr, token):
        #print(f"   AAAA   remove_observer {self.observers.items()}")
        if path not in self.observers: return
        self.observers[path].discard((addr, token))
        if not self.observers[path]: self.observers.pop(path)
        self._flush()
    async def get_observers(self, path):
        return self.observers.get(path, set())
    async def seen_message(self, addr, msg_id):
        return False
    async def list_observed_paths(self):
        return list(self.observers.keys())
    async def clear_observers(self):
        self.observers = {}
        self._flush()
