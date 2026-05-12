import asyncio
import time
import MqTTpart.packets_work3 as pw
import MqTTpart.storage.memory as sb
#Работа с wildcard topic
def match_topic(filter, topic):
    filter_lvl = filter.split('/')
    topic_lvl = topic.split('/')
    for i, f in enumerate(filter_lvl):
        if f == '#': return True
        if i >= len(topic_lvl): return False
        if f == '+': continue
        if f != topic_lvl[i]: return False
    return len(filter_lvl) == len(topic_lvl)
#Сессии
class client_session:
    #Инициализация переменных
    def __init__(self, reader, writer):
        #Переменные с информацией о соединении
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info('peername')
        self.protocol_version = 0
        #Переменные с информацией
        self.connected = False
        self.client_id = None
        #Для времени
        self.keep_alive = 0
        self.last_packet_time = time.monotonic()
        self.alive_task = None
        #Время жизни сессии
        self.session_expiry_interval = 0
        self.session_expiry_task = None
        #Для рассылок
        self.subscriptions = {}
        #Для qos
        self.stek_in = set() #для qos1 
        self.stek_out = {} #для qos1 
        self.qos2_stek_out = {} #для qos2
        self.qos2_stek_in = {} #для qos2
        self.packet_id = 1
        self.qos1_task = None
        #will
        self.will = None
        self.good_disconnect = False
        #clean start
        self.clean_start = True
        self.session_present = False
        #Auth
        self.authenticated = False
        self.auth_method = None
        self.auth_data = None
        self.authenticated_username = None
    #Для qos номерки пакетов
    def next_pid(self):
        pid = self.packet_id
        self.packet_id += 1
        if self.packet_id > 0xFFFF: self.packet_id = 1
        return pid
    #ACL todo
    def role(self):
        if self.authenticated:
            return "token"
        return "anonymous"
    async def send(self,data):
        self.writer.write(data)
        await self.writer.drain()
class broker:
    def __init__(self, storage):
        self.sessions = {}
        self.subscriptions = {}
        self.retained = {}
        self.storage = storage
        #self.retained = await storage.load_retained() тут запилить это
        self.users = {}
        self.users_acl = {}
        self.blocklist = {}
        self.acl = { #todo 
            "anonymous": { 
                "publish": ["public/#"],
                "subscribe": ["public/#"]
            },
            "token": {
                "publish": ["sensors/#"],
                "subscribe": ["sensors/#", "alerts/#"]
            }
    }
#broker потом создать в tcp_serv
async def packet_work(session, broker, packet):
    session.last_packet_time = time.monotonic()
    packet_type = packet["Type"]
    __packets = {
        1: handle_CONNECT,
        3: handle_PUBLISH,
        4: handle_PUBACK,
        5: handle_PUBREC,
        6: handle_PUBREL,
        7: handle_PUBCOMP,
        8: handle_SUBSCRIBE,
        10: handle_UNSUBSCRIBE,
        12: handle_PINGREQ,
        14: handle_DISCONNECT,
        15: handle_AUTH, #todo
    }
    #print(f"        [MQTT]! Debug | packet_type={packet_type} | packet={packet}")
    handle_packet = __packets.get(packet_type)
    if not handle_packet: raise ValueError(f"No handler for packet type({packet_type})")
    await handle_packet(session, broker, packet)
#Обработка connect
async def handle_CONNECT(session, broker, packet):
    #Если connect уже отправлялся check
    if session.connected == True: 
        print(f"            [MQTT]Malformed packet(CONNECT) from {session.peer}")
        session.writer.close()
        return
    session.good_disconnect = False
    #Обработка данных
    vh = packet["Variable header"]
    payload = packet["Payload"]
    clientID = payload["ClientID"]
    if vh["Connect Flags"]["User Name Flag"] == True:
        username = payload['User Name']
    else: username = None
    if vh["Connect Flags"]["Password Flag"] == True:
        password = payload['Password']
    else: password = None
    protocol_version = packet["Variable header"]['Protocol Version']
    if broker.users:    
        stored_cred = broker.users.get(username)
        #print(f"stored_cred={stored_cred}")
        if stored_cred is None or password != stored_cred:
            if hasattr(broker, "logstash"):
                peer = session.peer
                ip = peer[0] if peer else None
                await broker.logstash.auth_failure(protocol = "mqtt", client_ip = ip, username = username)
            connack = pw.deparse_CONNACK({
            "Variable header": {
                "Connect Acknowledge Flags": 0,
                "Connect Reason Code": 0x04,
                "Properties": {}
            }
        }, protocol_version)
            await session.send(connack)
            session.writer.close()
            return 
    clean_start = vh["Connect Flags"]["Clean_Start"]
    will_delay = 0
    if protocol_version == 5:
        if vh["Connect Flags"]["Will_Flag"]:
            will_props = payload.get("Will Properties", {})
            will_delay = will_props.get("Will Delay Interval", 0)
        properties = vh.get("Properties", {})
        session.session_expiry_interval = properties.get("Session Expiry Interval", 0)
    else:
        session.session_expiry_interval = 0
    session.protocol_version = protocol_version
    session.client_id = clientID
    session.clean_start = clean_start
    session.session_present = False
    session.authenticated_username = username
    if not clean_start:
        data = await broker.storage.load_session(clientID)
        if data:
            sb.load_session(session, data)
            session.session_present = True
    else:
        await broker.storage.delete_session(clientID)
    broker.sessions[clientID] = session
    #Соединение восстановилось доотправить
    if session.session_present:
        for pid, mes in session.stek_out.items():
            pub = pw.deparse_PUBLISH({
            "Flags": {
                "DUP flag": 1,
                "QoS level": 1,
                "RETAIN": mes["retain"]
            },
            "Variable header": {
                "Topic Name": mes["topic"],
                "Packet Identifier": pid,
                "Properties": {}
            },
            "Payload": mes["payload"]
            }, session.protocol_version)
            session.writer.write(pub)
        await session.writer.drain()
    session.client_id = payload["ClientID"]
    session.connected = True
    #Keep alive работа
    session.keep_alive = vh["Keep Alive"]
    session.alive_task = asyncio.create_task(keep_alive_watchdog(session, broker))
    broker.sessions[session.client_id] = session
    #Запуск функции проверки puback для qos todo (может сделать только для qos1 чтобы запускался)
    session.qos1_task = asyncio.create_task(qos1_check_puback(session))
    #Если есть will сохраняем 
    if vh["Connect Flags"]['Will_Flag']:
        session.will = {
            "topic": payload["Will Topic"],
            "payload": payload["Will Payload"],
            "qos": vh["Connect Flags"]["Will_QoS"],
            "retain": vh["Connect Flags"]["Will_Retain"],
            "delay": will_delay
        }
    else:
        session.will = None
    #Ответ connack
    connack = pw.deparse_CONNACK({
        "Variable header": {
            "Connect Acknowledge Flags": 1 if session.session_present else 0,
            "Connect Reason Code": 0,
            "Properties": {}
        }
    }, session.protocol_version)
    await session.send(connack)
#Обработка publish
async def handle_PUBLISH(session, broker, packet):
    #Если connect еще не отправлялся check
    if not session.connected: 
        print(f"            [MQTT]Malformed packet(PUBLISH) from {session.peer}")
        session.writer.close()
        return
    #Обработка данных
    topic_name = packet["Variable header"]["Topic Name"]
    payload = packet["Payload"]["payload"]
    if isinstance(payload, dict): payload = payload.get("payload")
    if payload in (None, "none"): payload = b""
    qos = packet["Flags"]["QoS level"]
    packetID = packet["Variable header"].get("Packet Identifier")
    retain = packet["Flags"]["RETAIN"]
    #Проверка доступа к топику auth
    if not check_acl(broker, session, "publish", topic_name) and session.protocol_version == 5:
        dis = pw.deparse_DISCONNECT({
                "Variable header": {
                    "DISCONNECT Reason Code": 0x87, #Not authorized
                    "Properties": {}
                }})
        await session.send(dis)
        session.writer.close()
        return
    if not broker.users_acl.check(session.authenticated_username, "publish", topic_name):
        if hasattr(broker, "logstash"):
            peer = session.peer
            ip = peer[0] if peer else None
            await broker.logstash.acl_break(protocol = "mqtt", client_ip = ip, 
                        username = session.authenticated_username, action="publish", target=topic_name)
        dis = pw.deparse_DISCONNECT({
                "Variable header": {
                    "DISCONNECT Reason Code": 0x87, #Not authorized
                    "Properties": {}
                }})
        await session.send(dis)
        session.writer.close()
        return
    #Обработка qos копий
    if qos == 1:
        puback = pw.deparse_PUBACK({
            "Variable header": {
                "Packet Identifier": packetID,
                "PUBACK Reason Code": 0x00,
                "Properties": {}
            }
            })
        await session.send(puback)
        await sb.persist_session(broker, session)
    elif qos == 2:
        if packetID in session.qos2_stek_in:
            #Если уже приходил
            pubrec = pw.deparse_PUBREC({
            "Variable header": {
                "Packet Identifier": packetID,
                "Properties": {}
            }})
            await session.send(pubrec)
            return
        #Сохранение пакета
        session.qos2_stek_in[packetID] = {"topic": topic_name, "payload": payload, "retain": retain}
        #session.qos2_stek_in[packetID] = packet
        #Ответ pubrec
        pubrec = pw.deparse_PUBREC({
        "Variable header": {
            "Packet Identifier": packetID,
            #"PUBREC Reason Code": 0x00,
            "Properties": {}
        }
        })
        await session.send(pubrec)
        return
    await publish(broker, topic=topic_name, payload=payload, qos=qos, retain=retain)
#Обработка puback
async def handle_PUBACK(session, broker, packet):
    if not session.connected:
        session.writer.close()
        return
    packetID = packet["Variable header"].get("Packet Identifier")
    if packetID not in session.stek_out:
        return
    del session.stek_out[packetID]
    await sb.persist_session(broker, session)
#Обработка pubrec
async def handle_PUBREC(session, broker, packet):
    packetID = packet["Variable header"].get("Packet Identifier")
    #if packetID not in session.qos2_stek_in: return
    if packetID not in session.qos2_stek_out: return
    pubrel = pw.deparse_PUBREL({
        "Variable header": {
            "Packet Identifier": packetID,
            "Properties": {}
        }
    })
    await session.send(pubrel)
#Обработка pubrel
async def handle_PUBREL(session,broker,packet):
    packetID = packet["Variable header"].get("Packet Identifier")
    #mes = session.qos2_stek_in.pop(packetID, None)
    mes = session.qos2_stek_in.get(packetID)
    if mes:
        await publish(
            broker,
            topic=mes["topic"],
            payload=mes["payload"],
            qos=2,
            retain=mes["retain"]
        )
    else:
        return
    del session.qos2_stek_in[packetID]
    await sb.persist_session(broker, session)
    pubcomp = pw.deparse_PUBCOMP({
        "Variable header": {
            "Packet Identifier": packetID,
            "Properties": {}
        }
    })
    await session.send(pubcomp)
#Обработка pubcomp
async def handle_PUBCOMP(session, broker, packet):
    packetID = packet["Variable header"].get("Packet Identifier")
    session.qos2_stek_out.pop(packetID, None)
    await sb.persist_session(broker, session)
#Обработка subscribe
async def handle_SUBSCRIBE(session, broker, packet):
    #Если connect еще не отправлялся check
    if not session.connected: 
        print(f"            [MQTT]Malformed packet(SUBSCRIBE) from {session.peer}")
        session.writer.close()
        return
    #Обработка данных
    packet_id = packet["Variable header"]["Packet Identifier"]
    topic = packet["Payload"]["The Topic Filter"]
    options = packet["Payload"]["Subscription Options"]
    qos = options & 0x03
    reason_codes = []
    if not check_acl(broker, session, "subscribe", topic) and session.protocol_version == 5:
        reason_codes.append(0x87)  #Not authorized
    elif not broker.users_acl.check(session.authenticated_username, "publish", topic):
        if hasattr(broker, "logstash"):
            peer = session.peer
            ip = peer[0] if peer else None
            await broker.logstash.acl_break(protocol = "mqtt", client_ip = ip, 
                        username = session.authenticated_username, action="subscribe", target=topic)
        reason_codes.append(0x87)  #Not authorized
    else:
        session.subscriptions[topic] = qos
        #broker.subscriptions.setdefault(topic, set()).add(session)
        broker.subscriptions.setdefault(topic, {})[session] = qos
        reason_codes.append(min(qos, 2))
    #Ответ suback
    suback = pw.deparse_SUBACK({
        "Variable header": {
            "Packet Identifier": packet_id,
            "Properties": {}
        },
        "Payload": {
            "Subscribe Reason Codes": reason_codes
        }
    }, session.protocol_version)
    session.writer.write(suback)
    #Если retained есть, отправляем его новому подписчику
    for retained_topic, retained_mes in broker.retained.items():
        if match_topic(topic, retained_topic):
            pub = pw.deparse_PUBLISH({
                    "Flags": {
                        "DUP flag": 0,
                        "QoS level": 0,
                        "RETAIN": 1
                    },
                    "Variable header": {
                        "Topic Name": retained_topic,
                        "Properties": {}
                    },
                    "Payload": retained_mes["payload"]
                }, session.protocol_version)
            session.writer.write(pub)
    await session.writer.drain()
    await sb.persist_session(broker, session)
#Обработка unsubscribe
async def handle_UNSUBSCRIBE(session, broker, packet):
    #Если connect еще не отправлялся check
    if not session.connected:
        session.writer.close()
        return
    #Обработка данных
    packet_id = packet["Variable header"]["Packet Identifier"]
    topic_filter = packet["Payload"]["The Topic Filter"]
    reason_codes = []
    subs = broker.subscriptions.get(topic_filter)
    if subs and session in subs:
        #subs.discard(session)
        subs.pop(session, None)
        reason_codes.append(0x00)
    else: reason_codes.append(0x11) 
    if subs is not None and not subs:
        del broker.subscriptions[topic_filter]
    answer = {
        "Variable header": {
            "Packet Identifier": packet_id,
            "Properties": {}
        },
        "Payload": {
            "Unsubscribe Reason Codes": reason_codes
        }
    }
    session.writer.write(pw.deparse_fixed_header(answer, session.protocol_version))
    await session.writer.drain()
    await sb.persist_session(broker, session)
#Обработка pingreq
async def handle_PINGREQ(session, broker, packet):
    # если клиент не прошёл CONNECT — ошибка
    if not session.connected:
        session.writer.close()
        return
    pingresp = pw.deparse_PINGRESP() # pingresp в ответ на pingreq
    await session.send(pingresp)
#Обработка disconnect
async def handle_DISCONNECT(session, broker, packet):
    session.good_disconnect = True
    session.will = None
    session.connected = False
    #session.writer.close()
    await disconnect(broker, session)
    #if not session.clean_start:
        #await broker.storage.save_session(session.client_id, sb.save_session(session))
    #else:
        #await broker.storage.delete_session(session.client_id)
#Обработка auth
async def handle_AUTH(session, broker, packet):
    properties = packet["Variable header"].get("Properties", {})
    method = properties.get("Authentication Method")
    data = properties.get("Authentication Data")
    if method != "token": #todo
        await session.send(
            pw.deparse_DISCONNECT({
                "Variable header": {
                    "DISCONNECT Reason Code": 0x8C, #Bad authentication method
                    "Properties": {}
                }}, session.protocol_version)
            )
        session.writer.close()
        return
    if data != b"secret123":
        await session.send(
            pw.deparse_DISCONNECT({
                "Variable header": {
                    "DISCONNECT Reason Code": 0x87, #Not authorized
                    "Properties": {}
                }}, session.protocol_version)
            )
        session.writer.close()
        return
    session.authenticated = True
    session.auth_method = method
#Publish
async def publish(broker, topic, payload, qos=0, retain=0):
    # retain
    if retain and payload == b"":
        broker.retained.pop(topic, None)
        await broker.storage.delete_retained(topic)
    elif retain: 
        broker.retained[topic] = {"payload": payload,"qos": qos}
        await broker.storage.save_retained(topic, broker.retained[topic])
    for filter, subs_dict in broker.subscriptions.items():
        if not match_topic(filter, topic):
            continue
        for session, sub_qos in subs_dict.items():
            #sub_qos = session.subscriptions.get(filter, 0)
            deliver_qos = min(qos,sub_qos)
            if not session.connected:
                if deliver_qos == 1:
                    pid = session.next_pid()
                    session.stek_out[pid] = {"topic": topic, "payload": payload, "retain": retain}
                continue
            pid = None
            dup = 0
            if deliver_qos == 1:
                pid = session.next_pid()
                session.stek_out[pid] = {"topic": topic, "payload": payload, "retain": retain, "qos": deliver_qos}
                await sb.persist_session(broker, session)
            if deliver_qos == 2:
                pid = session.next_pid()
                session.qos2_stek_out[pid] = {"topic": topic, "payload": payload, "retain": retain}
            pub = pw.deparse_PUBLISH({
                "Flags": {
                    "DUP flag": dup,
                    "QoS level": deliver_qos,
                    "RETAIN": retain
                },
                "Variable header": {
                    "Topic Name": topic,
                    "Packet Identifier": pid,
                    "Properties": {}
                },
                "Payload": payload
            }, session.protocol_version)
            session.writer.write(pub)
    for session in broker.sessions.values():
        if session.connected:
            await session.writer.drain()
#Отключение 
async def disconnect(broker, session):
    if session.alive_task:
        session.alive_task.cancel()
    if session.will and not session.good_disconnect:
        if session.will["delay"] > 0:
            await asyncio.sleep(session.will["delay"])
            if session.connected: return
            await publish(broker, topic=session.will["topic"], payload=session.will["payload"], qos=session.will["qos"], retain=session.will["retain"])
        else: await publish(broker, topic=session.will["topic"], payload=session.will["payload"], qos=session.will["qos"], retain=session.will["retain"])
        if session.clean_start == 1:
            await broker.storage.delete_session(session.client_id)
    if session.clean_start or session.session_expiry_interval == 0:
        broker.sessions.pop(session.client_id, None)
        for subs in broker.subscriptions.values():
            #subs.discard(session)
            if session in subs:
                subs.pop(session, None)
    else:
        session.session_expiry_task = asyncio.create_task(expire_session(broker, session, session.session_expiry_interval))
    if session.qos1_task:
        session.qos1_task.cancel()
        session.qos1_task = None
    session.writer.close()
    await session.writer.wait_closed()
#Проверка прошел ли keep alive
async def keep_alive_watchdog(session, broker):
    if session.keep_alive == 0: return  # keep alive отключён
    timeout = session.keep_alive * 1.5
    try:
        while True:
            await asyncio.sleep(session.keep_alive)
            now = time.monotonic()

            if now - session.last_packet_time > timeout:
                print(f"    [MQTT] Client timeout: {session.peer}")
                await disconnect(broker, session)
                break
    except asyncio.CancelledError:
        pass
#Время истечения сессии
async def expire_session(broker, session, delay):
    try:
        await asyncio.sleep(delay)
        broker.sessions.pop(session.client_id, None)

        for subs in broker.subscriptions.values():
            #subs.discard(session)
            if session in subs:
                subs.pop(session, None)
    except asyncio.CancelledError:
        pass
#Если не пришел puback
async def qos1_check_puback(session):
    try:
        while session.connected:
            await asyncio.sleep(5) 
            for pid, mes in list(session.stek_out.items()):
                pub = pw.deparse_PUBLISH({
                    "Flags": {
                        "DUP flag": 1,
                        "QoS level": 1,
                        "RETAIN": mes["retain"]
                    },
                    "Variable header": {
                        "Topic Name": mes["topic"],
                        "Packet Identifier": pid,
                        "Properties": {}
                    },
                    "Payload": mes["payload"]
                }, session.protocol_version)
                session.writer.write(pub)
            await session.writer.drain()
    except asyncio.CancelledError:
        pass
    except ConnectionResetError:
        pass
#Проверка прав
def check_acl(broker, session, action, topic):
    role = session.role()
    rules = broker.acl.get(role, {}).get(action, [])
    for rule in rules:
        if match_topic(rule, topic):
            return True
    return False
#todo
#auth методы мб jwt организовать и ответы пакетов точно не так поменять(вызов fixed_header лучше пускать, а не напрямую)!!!! type добавить будто и место куда его направлять
#will ну тяжко при каждом не правильном дисконекте (и сообщения не доходят если отправили пока отключен саб) 