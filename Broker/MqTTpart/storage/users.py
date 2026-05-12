import json
from pathlib import Path
import os

class UsersFile:
    def __init__(self, path="mqtt_users.json"):
        self.path = path
        self._users = {}
        self._mtime = 0

    def _reload_if_needed(self):
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            self._users = {}
            self._mtime = 0
            return

        if st.st_mtime != self._mtime:
            with open(self.path, "r", encoding="utf-8") as f:
                self._users = json.load(f)
            self._mtime = st.st_mtime

    def get(self, username):
        self._reload_if_needed()
        return self._users.get(username)