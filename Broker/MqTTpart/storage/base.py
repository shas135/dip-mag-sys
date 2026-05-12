class storage():
    def __init__(self, mem_storage, per_storage):
        self.mem = mem_storage
        self.disk = per_storage

    async def load_session(self, clientID):
        data = await self.disk.load_session(clientID)
        if data:
            await self.mem.save_session(clientID, data)
        return data

    async def save_session(self, clientID, data):
        await self.mem.save_session(clientID, data)
        await self.disk.save_session(clientID, data)

    async def delete_session(self, clientID):
        await self.mem.delete_session(clientID)
        await self.disk.delete_session(clientID)

    async def load_retained(self):
        retained = await self.disk.load_retained()
        for topic, mes in retained.items():
            await self.mem.save_retained(topic, mes)
        return retained

    async def save_retained(self, topic, mes):
        await self.mem.save_retained(topic, mes)
        await self.disk.save_retained(topic, mes)

    async def delete_retained(self, topic):
        await self.mem.delete_retained(topic)
        await self.disk.delete_retained(topic)
