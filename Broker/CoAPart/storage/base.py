class storage():
    def __init__(self, memory, persistent):
        self.mem = memory
        self.disk = persistent
    async def boot(self):
        for path in await self.disk.list_resources():
            value = await self.disk.get_resource(path)
            await self.mem.set_resource(path, value)
        for path in await self.disk.list_observed_paths():
            for addr, token in await self.disk.get_observers(path):
                await self.mem.add_observer(path, addr, token) 
    async def get_resource(self, path):
        return await self.mem.get_resource(path)
    async def set_resource(self, path, value):
        await self.mem.set_resource(path, value)
        await self.disk.set_resource(path, value)
    async def delete_resource(self, path):
        await self.mem.delete_resource(path)
        await self.disk.delete_resource(path)
    async def list_resources(self):
        return await self.mem.list_resources()
    async def add_observer(self, path, addr, token):
        await self.mem.add_observer(path, addr, token)
        await self.disk.add_observer(path, addr, token)
    async def remove_observer(self, path, addr, token):
        await self.mem.remove_observer(path, addr)
        await self.disk.remove_observer(path, addr, token)
    async def get_observers(self, path):
        return await self.mem.get_observers(path)
    async def remember_message(self, addr, msg_id):
        await self.mem.remember_message(addr, msg_id)
    async def seen_message(self, addr, msg_id):
        return await self.mem.seen_message(addr, msg_id)
