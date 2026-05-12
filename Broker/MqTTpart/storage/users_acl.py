import json
import os
from MqTTpart.protocol_logic import match_topic

class AclFile:
    def __init__(self, path):
        self.path = path
        self._data = {}
        self._load()

    def _load(self):
        if not os.path.exists(self.path):
            self._data = {}
            return

        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self._data = json.load(f)
        except Exception as e:
            self._data = {}

    def rules_for(self, role, action):
        return self._data.get(role, {}).get(action, [])
    
    def check(self, username: str, action: str, topic: str) -> bool:
        user_rules = self._data.get(username)
        if not user_rules:
            return False  #пользователь не найден знач нет прав

        rules = user_rules.get(action, [])
        for rule in rules:
            if match_topic(rule, topic):
                return True

        return False