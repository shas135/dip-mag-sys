import asyncio
import CoAPart.CoAP_packets_work as Cpw
class broker:
    def __init__(self, storage):
        self.sessions = {}
        #self.observers = {}
        #self.resources = {}
        self.pending = {}
        self.observer_c = {}
        self.storage = storage
        self.blocklist = {}
        self.acl = { #todo
    "anonymous": {
        "get":    [b"public"],
        "put":    [b"public"],
        "post": [b"public"],
        "observe": [b"public"]
    },
    "device": {
        "get":    [b"sensors"],
        "put":    [b"sensors"],
        "post": [b"sensors"],
        "observe": [b"sensors"]
    },
    "admin": {
        "get":    [b"#"],
        "put":    [b"#"],
        "post": [b"#"],
        "delete": [b"#"],
        "observe": [b"#"]
    }
}
async def Cl(transport, broker, rawdata, addr):
    print(f"[CoAP]Client raw CoAP packet: {rawdata}")
    try:
        packet = Cpw.parse_CoAP(rawdata)
    except Exception as e:
        print("         [CoAP] ошибка parse:", e)
        return 
    print(f"[CoAP]Client CoAP packet: {packet}")
    msg_type = packet['Type']
    mid = packet['Message ID']
    if msg_type == 2:
        task = broker.pending.pop((addr, mid), None)
        if task: task.cancel()
        return
    elif msg_type == 3:
        task = broker.pending.pop((addr, mid), None)
        if task: task.cancel()
        ##!!!
        #await broker.storage.remove_observer(path, addr)
        return
    session = broker.sessions.setdefault(addr, { "last_mid": None })
    response = await packet_work(session, broker, packet, addr, transport)
    if response:
        transport.sendto(Cpw.deparse_CoAP(response), addr)
        if response['Type'] == 0:
            task = asyncio.create_task(retransmit(transport, broker, addr, response))
            broker.pending[(addr, response['Message ID'])] = task
async def packet_work(session, broker, packet, addr, transport):
    code = packet["Code"] 
    if code == 0: return None
    __packets = {
        1: handle_get,
        2: handle_post,
        3: handle_put,
        4: handle_delete
    }
    print(f"        [CoAP]! Debug | packet_code={code} | packet={packet}")
    handle_packet = __packets.get(code)
    if not handle_packet: raise ValueError(f"No handler for code = ({code})")
    return await handle_packet(session, broker, packet, addr, transport)
def error(packet, code):
    return {
        'Version': 1,
        'Type': 2,
        'Code': code,
        'Message ID': packet['Message ID'],
        'Token': packet['Token'],
        'Options': [],
        'Payload': None
    }
#Сравнение  так
def match_path(rule, path):
    if rule == b"#":
        return True
    return path.startswith(rule)
#Проверка прав
def check_acl(broker, session, action, path, token):
    if token == b"device": role = "device"
    elif token == b"admin": role = "admin"
    else: role = "device" 
    rules = broker.acl.get(role, {}).get(action, [])
    for rule in rules:
        if match_path(rule, path):
            return True
    return False
async def retransmit(transport, broker, addr, packet):
    timeout = 2
    mid = packet['Message ID']
    raw = Cpw.deparse_CoAP(packet)
    try:
        for _ in range(4):
            await asyncio.sleep(timeout)
            transport.sendto(raw, addr)
            timeout *= 2
    except asyncio.CancelledError:
        return
    finally:
        broker.pending.pop((addr, mid), None)
async def handle_get(session, broker, packet,addr, transport):
    path =  b"/".join(v for n, v in packet['Options'] if n == 11)
    if not check_acl(broker, session, "get", path, packet['Token']): 
        if hasattr(broker, "logstash"):
            await broker.logstash.acl_break(protocol = "coap", client_ip = addr[0], 
                        username = None, action= "get", target = path.decode(errors="ignore"))
        return error(packet, 131) 
    #payload = broker.resources.get(path)
    payload = await broker.storage.get_resource(path)
    if payload is None: return error(packet, 132)
    #observe = [v for n, v in packet['Options'] if n == 6]
    options = []
    observe_value = None
    for n, v in packet['Options']:
        if n == 6:
            observe_value = v
            break
    if observe_value == b'\x01': await broker.storage.remove_observer(path, addr, packet['Token'])
    elif observe_value in (b'', b'\x00'):                       
        if not check_acl(broker, session, "observe", path, packet['Token']): 
            if hasattr(broker, "logstash"):
                await broker.logstash.acl_break(protocol = "coap", client_ip = addr[0], 
                        username = None, action= "observe", target = path.decode(errors="ignore"))
            return error(packet, 131) 
        #broker.observers.setdefault(path, set()).add(addr) !!
        await broker.storage.add_observer(path, addr, packet['Token'])
        count = broker.observer_c.get(path, 0)
        broker.observer_c[path] = count + 1
        options.append((6, count.to_bytes(1, 'big'))) 
    else:
        await broker.storage.remove_observer(path, addr, packet['Token']) ##todo
    return {
        'Version': 1,
        'Type': 2,
        'Code': 69,
        'Message ID': packet['Message ID'],
        'Token': packet['Token'],
        'Options': options,
        'Payload': payload
    }
async def handle_put(session, broker, packet, addr, transport):
    path = b"/".join(v for n, v in packet['Options'] if n == 11)
    if not check_acl(broker, session, "put", path, packet['Token']):
        if hasattr(broker, "logstash"):
            await broker.logstash.acl_break(protocol = "coap", client_ip = addr[0], 
                        username = None, action= "put", target = path.decode(errors="ignore"))
        return error(packet, 131)
    payload = packet['Payload'] or b""
    await broker.storage.set_resource(path, payload)
    #broker.resources[path] = packet['Payload'] or b""
    #payload = broker.resources.get(path, b"")
    count = broker.observer_c.get(path, 0)
    broker.observer_c[path] = count + 1
    #for addr in broker.observers.get(path, []):
    for addr, token in await broker.storage.get_observers(path):
        packetob = {
            'Version': 1,
            'Type': 0, 
            'Code': 69,
            'Message ID': (count & 0xFFFF),
            'Token': token,
            'Options': [(6, count.to_bytes(1, 'big'))],
            'Payload': payload
        }
        rawpacket = Cpw.deparse_CoAP(packetob)
        transport.sendto(rawpacket, addr)
    return {
        'Version': 1,
        'Type': 2,
        'Code': 68, 
        'Message ID': packet['Message ID'],
        'Token': packet['Token'],
        'Options': [],
        'Payload': None
    }
async def handle_post(session, broker, packet, addr, transport):
    path = b"/".join(v for n, v in packet['Options'] if n == 11)
    if not check_acl(broker, session, "post", path, packet['Token']):
        if hasattr(broker, "logstash"):
            await broker.logstash.acl_break(protocol = "coap", client_ip = addr[0], 
                        username = None, action= "post", target = path.decode(errors="ignore"))
        return error(packet, 131)
    payload = packet['Payload'] or b""
    old = await broker.storage.get_resource(path)
    new_obj = old is None
    #new_obj = path not in broker.resources
    #broker.resources[path] = payload
    await broker.storage.set_resource(path, payload)
    #payload = broker.resources.get(path, b"")
    #await broker.storage.get_resource(path)
    count = broker.observer_c.get(path, 0)
    broker.observer_c[path] = count + 1
    #for addr in broker.observers.get(path, []):
    for addr, token in await broker.storage.get_observers(path):
        packetob = {
            'Version': 1,
            'Type': 0, 
            'Code': 69,
            'Message ID': (count & 0xFFFF),
            'Token': token,
            'Options': [(6, count.to_bytes(1, 'big'))],
            'Payload': payload
        }
        rawpacket = Cpw.deparse_CoAP(packetob)
        transport.sendto(rawpacket, addr)
    return {
        'Version': 1,
        'Type': 2,
        'Code': 65 if new_obj else 68,
        'Message ID': packet['Message ID'],
        'Token': packet['Token'],
        'Options': [],
        'Payload': None
    }
async def handle_delete(session, broker, packet, addr, transport):
    path = b"/".join(v for n, v in packet['Options'] if n == 11)
    if not check_acl(broker, session, "delete", path, packet['Token']):
        if hasattr(broker, "logstash"):
            await broker.logstash.acl_break(protocol = "coap", client_ip = addr[0], 
                        username = None, action= "delete", target = path.decode(errors="ignore"))
        return error(packet, 131) 
    exists = await broker.storage.get_resource(path)
    if exists is None: return error(packet, 132)
    await broker.storage.delete_resource(path)
    return {
        'Version': 1,
        'Type': 2, 
        'Code': 66, 
        'Message ID': packet['Message ID'],
        'Token': packet['Token'],
        'Options': [],
        'Payload': None
    }