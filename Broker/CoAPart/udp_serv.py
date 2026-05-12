import asyncio
import CoAPart.CoAP_logic as Cl
import CoAPart.storage.memory as sm 
class CoAPProtocol(asyncio.DatagramProtocol):
    def __init__(self, broker):
        self.broker = broker

    def connection_made(self, transport):
        print(f"[CoAP] UDP server started")
        self.transport = transport

    def datagram_received(self, data, addr):
        if hasattr(self.broker, "blocklist") and self.broker.blocklist.is_blocked(addr[0]):
            print(f"[CoAP] Blocked: {addr[0]}")
            if hasattr(self.broker, "logstash"):
                asyncio.create_task(self.broker.logstash.blocked_ip(protocol = "coap", client_ip = addr[0]))
            return
        print(f"[CoAP]Client(({addr})) connected и отправил {data}")
        asyncio.create_task(
            Cl.Cl(self.transport, self.broker, data, addr)
        )
async def start_CoAP_server(broker, host="0.0.0.0", port=5683):
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(
        lambda: CoAPProtocol(broker),
        local_addr=(host, port)
    )
