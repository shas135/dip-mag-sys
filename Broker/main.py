import asyncio
import os
import ssl
from MqTTpart.tcp_serv import start_MqTT_server
from MqTTpart.protocol_logic import broker as MqTTBroker
from MqTTpart.storage.memory import mem_storage as mem_MqTTStorage
from MqTTpart.storage.file import per_storage as per_MqTTStorage
from MqTTpart.storage.base import storage as MqTTStorage
from MqTTpart.storage.users import UsersFile
from MqTTpart.storage.users_acl import AclFile
from CoAPart.udp_serv import start_CoAP_server
from CoAPart.CoAP_logic import broker as CoAPbroker
from CoAPart.storage.memory import mem_storage as mem_CoAPStorage
from CoAPart.storage.file import per_storage as per_CoAPStorage
from CoAPart.storage.base import storage as CoAPstorage
from block import Blocklist
from logstash import send_logstash
async def main():
    #tls
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    cert_dir = os.path.join(BASE_DIR, "cert")
    server_crt = os.path.join(cert_dir, "server.crt")
    server_key = os.path.join(cert_dir, "server.key")
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=server_crt, keyfile=server_key)
    #logstash
    logstash = send_logstash("http://192.168.2.2:8081")
    #mqtt
    memory_mqtt = mem_MqTTStorage()
    persist_mqtt = per_MqTTStorage("mqtt.json")
    storage_mqtt = MqTTStorage(memory_mqtt, persist_mqtt)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    users_path = os.path.join(BASE_DIR, "mqtt_users.json")
    users_acl_path = os.path.join(BASE_DIR, "mqtt_users_acl.json")
    users = UsersFile(users_path)
    users_acl = AclFile(users_acl_path)
    MqTT_broker = MqTTBroker(storage_mqtt)
    MqTT_broker.retained = await storage_mqtt.load_retained() #??
    MqTT_broker.users = users
    MqTT_broker.users_acl = users_acl
    blocklist = Blocklist(os.path.join(BASE_DIR, "blockedip.json"))
    MqTT_broker.blocklist = blocklist
    MqTT_broker.logstash = logstash
    #coap
    memory_coap = mem_CoAPStorage()
    persist_coap = per_CoAPStorage("coap.json")
    await persist_coap.clear_observers() #при перезапуске observers очищаются
    storage_coap = CoAPstorage(memory_coap, persist_coap)
    await storage_coap.boot()
    coap_broker = CoAPbroker(storage_coap)
    coap_broker.blocklist = blocklist
    coap_broker.logstash = logstash
    await asyncio.gather(
        start_MqTT_server(MqTT_broker, host="0.0.0.0", port=1883),
        start_MqTT_server(MqTT_broker, host="0.0.0.0", port=8883, ssl_context=ssl_ctx),
        start_CoAP_server(coap_broker),
    )
if __name__ == "__main__":
    asyncio.run(main())
