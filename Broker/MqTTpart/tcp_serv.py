import asyncio
import MqTTpart.protocol_logic as pl
import MqTTpart.packets_work3 as pw  
def find_packet(buffer):
    if len(buffer) < 2: return None
    x = 1
    remaining_length = 0
    vbi_len = 0
    while True:
        if 1 + vbi_len >= len(buffer): return None
        byte = buffer[1 + vbi_len]
        vbi_len += 1
        remaining_length += (byte & 0x7F) * x
        if (byte & 0x80) == 0: break
        x *= 128
        #Больше 4 байт - быть не может
        if x > 128 * 128 * 128:
            raise ValueError("Malformed Remaining Length")
    header_len = 1 + vbi_len
    total_len = header_len + remaining_length
    if len(buffer) < total_len: return None
    packet = bytes(buffer[:total_len])
    del buffer[:total_len]
    return packet
async def start_MqTT_server(broker, host="0.0.0.0", port=1883, ssl_context=None):
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, broker), host, port, ssl=ssl_context)
    print(f"[MQTT] TCP server started on {host}:{port} and TLS = {ssl_context is not None}")
    async with server:
        await server.serve_forever()
#Обслуживание 1 клиента, работает пока есть соединение
async def handle_client(reader, writer, broker):
    session = pl.client_session(reader,writer)
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else None
    if hasattr(broker, "blocklist") and ip:
        if broker.blocklist.is_blocked(ip):
            print(f"[MQTT] Blocked: {session.peer}")
            if hasattr(broker, "logstash"):
                await broker.logstash.blocked_ip(protocol = "mqtt", client_ip = ip)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception: pass
            return
    print(f'[MQTT] Client({session.peer}) connected')
    #Персональный буфер
    client_buffer = bytearray()
    try:
        while True:
            #Ожидание байтов (4096 максимум)
            data = await reader.read(4096)
            if not data: break
            #Получили байты в буфер
            #print(f"[MQTT]Client({session.peer}) send bytes: {data.hex()}")
            client_buffer += data
            #Проверка в буфере набрался ли пакет mqtt
            while True:
                raw_packet = find_packet(client_buffer)
                if raw_packet is None: break
                #print(f"[MQTT]Client({session.peer}) raw MQTT packet: {raw_packet.hex()}")
                #Из байт в словарь
                mqtt_packet = pw.parse_fixed_header(data=raw_packet, pt = session.protocol_version)
                #Обработка пакета(в виде словаря)
                await pl.packet_work(session, broker, mqtt_packet)
    except Exception as e:
        print(f'[MQTT]Client({session.peer}) has problem: {e}')
    finally:
        print(f'[MQTT]Client({session.peer}) disconnected')
        await pl.disconnect(broker, session)
