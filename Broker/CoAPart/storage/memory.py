import time

class mem_storage():
    def __init__(self):
        self.resources = {}
        self.observers = {} 
        self.recent = {}       
        self.dedup_window = 60  

    async def get_resource(self, path):
        return self.resources.get(path)

    async def set_resource(self, path, value):
        self.resources[path] = value

    async def delete_resource(self, path):
        self.resources.pop(path, None)

    async def list_resources(self):
        return list(self.resources.keys())

    async def add_observer(self, path, addr, token):
        self.observers.setdefault(path, set()).add((addr, token))

    async def remove_observer(self, path, addr):
        if path in self.observers:
            self.observers[path] = {
                o for o in self.observers[path] if o[0] != addr
            }

    async def get_observers(self, path):
        return self.observers.get(path, set())

    async def remember_message(self, addr, msg_id):
        self.recent[(addr, msg_id)] = time.time()

    async def seen_message(self, addr, msg_id):
        now = time.time()
        ts = self.recent.get((addr, msg_id))
        if ts and now - ts < self.dedup_window:
            return True
        return False

    async def list_observed_paths(self):
        return list(self.observers.keys())
