class mem_storage():
    def __init__(self):
        self.sessions = {}
        self.retained = {}

    async def load_session(self, clientID):
        return self.sessions.get(clientID)

    async def save_session(self, clientID, data):
        self.sessions[clientID] = data

    async def delete_session(self, clientID):
        self.sessions.pop(clientID, None)

    async def load_retained(self):
        return dict(self.retained)

    async def save_retained(self, topic, mes):
        self.retained[topic] = mes

    async def delete_retained(self, topic):
        self.retained.pop(topic, None)

def save_session(session):
    return {
        "subscriptions": dict(session.subscriptions),
        "stek_out": dict(session.stek_out),
        "qos2_out": dict(session.qos2_stek_out),
        "qos2_in": dict(session.qos2_stek_in),
        "packet_id": session.packet_id,
        "will": session.will,
    }

def load_session(session, data):
    session.subscriptions = data.get("subscriptions", {})
    session.stek_out = data.get("stek_out", {})
    session.qos2_stek_out = data.get("qos2_out", {})
    session.qos2_stek_in = data.get("qos2_in", {})
    session.packet_id = data.get("packet_id", 1)
    session.will = data.get("will")

async def persist_session(broker, session):
    if not session.clean_start:
        await broker.storage.save_session(session.client_id, save_session(session))
