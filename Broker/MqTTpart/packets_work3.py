# https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.pdf

def parse_fixed_header(data: bytes, pt):
    if not data:
        raise ValueError("Empty data")

    fixed_header = data[0]
    control_packet_type = fixed_header >> 4
    flags = fixed_header & 0xF

    val = 0
    b_count = 0
    x = 1
    i = 1
    while i <= 4:
        data[i]
        val += (data[i] & 0x7F) * x
        x *= 128
        b_count += 1
        if data[i] & 0x80 == 0:
            break
        i += 1

    if control_packet_type == 1:
        return parse_CONNECT(data[1+b_count:(1+b_count)+val])
    elif control_packet_type == 2:
        return parse_CONNACK(data[1+b_count:(1+b_count)+val], pt)
    elif control_packet_type == 3:
        return parse_PUBLISH(data[1+b_count:(1+b_count)+val], flags, val, pt)
    elif control_packet_type == 4:
        return parse_PUBACK(data[1+b_count:(1+b_count)+val], val, pt)
    elif control_packet_type == 5:
        return parse_PUBREC(data[1+b_count:(1+b_count)+val], val, pt)
    elif control_packet_type == 6:
        return parse_PUBREL(data[1+b_count:(1+b_count)+val], val, pt)
    elif control_packet_type == 7:
        return parse_PUBCOMP(data[1+b_count:(1+b_count)+val], val, pt)
    elif control_packet_type == 8:
        return parse_SUBSCRIBE(data[1+b_count:(1+b_count)+val], val, pt)
    elif control_packet_type == 9:
        return parse_SUBACK(data[1+b_count:(1+b_count)+val], val, pt)
    elif control_packet_type == 10:
        return parse_UNSUBSCRIBE(data[1+b_count:(1+b_count)+val], val, pt)
    elif control_packet_type == 11:
        return parse_UNSUBACK(data[1+b_count:(1+b_count)+val], val, pt)
    elif control_packet_type == 12:
        return parse_PINGREQ()
    elif control_packet_type == 13:
        return parse_PINGRESP()
    elif control_packet_type == 14:
        return parse_DISCONNECT(data[1+b_count:(1+b_count)+val], val, pt)
    elif control_packet_type == 15:
        return parse_AUTH(data[1+b_count:(1+b_count)+val], val)

    # Работа с пакетом типа connect


def parse_CONNECT(data: bytes):
    protocol_name_length = data[1]
    # Имя протокола MQTT в UTF-8
    protocol_name = data[2:2+protocol_name_length].decode('utf-8')
    # Версия протокола
    protocol_version = data[6]
    # Флаги соединения
    connect_flags = data[7]
    reserved_flag = connect_flags & 0x01
    clean_start_flag = connect_flags & 0x02
    will_flag = connect_flags & 0x04
    will_QoS_flag = (connect_flags & 0x18) >> 3
    will_retain_flag = connect_flags & 0x20
    password_flag = connect_flags & 0x40
    username_flag = connect_flags & 0x80
    if reserved_flag != 0:
        raise ValueError(f'connection reserved flag != 0 {connect_flags}')
    # Keep-alive
    keepalive = (data[8] << 8) | (data[9])
    # Properties
    i = 10
    if protocol_version == 5:
        connect_poperties = {
            0x11: lambda data, i: ("Session Expiry Interval", int.from_bytes(data[i:i+4], 'big'), i + 4),
            0x21: lambda data, i: ("Receive Maximum", int.from_bytes(data[i:i+2], 'big'), i + 2),
            0x27: lambda data, i: ("Maximum Packet Size", int.from_bytes(data[i:i+4], 'big'), i + 4),
            0x22: lambda data, i: ("Topic Alias Maximum", int.from_bytes(data[i:i+2], 'big'), i + 2),
            0x19: lambda data, i: ("Request Response Information", data[i], i + 1),
            0x17: lambda data, i: ("Request Problem Information", data[i], i + 1),
            0x15: lambda data, i: (
                "Authentication Method", data[i+2:i+2 +
                                            int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
            0x16: lambda data, i: (
                "Authentication Data", data[i+2:i+2 +
                                            int.from_bytes(data[i:i+2], 'big')],
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
            # will properties
            0x18: lambda data, i: ("Will Delay Interval", int.from_bytes(data[i:i+4], 'big'), i + 4),
            0x01: lambda data, i: ("Payload Format Indicator", data[i], i + 1),
            0x02: lambda data, i: ("Message Expiry Interval", int.from_bytes(data[i:i+4], 'big'), i + 4),
            0x03: lambda data, i: (
                "Content Type", data[i+2:i+2 +
                                    int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
            0x08: lambda data, i: (
                "Response Topic", data[i+2:i+2 +
                                    int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
            0x09: lambda data, i: (
                "Correlation Data", data[i+2:i+2 +
                                        int.from_bytes(data[i:i+2], 'big')],
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
        }
        properties = {}
        properties_length = 0
        b_count = 1
        x = 1
        while True:
            d = data[i]
            properties_length += (d & 0x7F) * x
            x *= 128
            b_count += 1
            i += 1
            if d & 0x80 == 0:
                break
        properties_end = i + properties_length
        p_us_pr_c = 1
        while i < properties_end:
            prop_id = data[i]
            i += 1
            if prop_id in connect_poperties:
                prop_name, val, i = connect_poperties[prop_id](data, i)
                properties[prop_name] = val
            # Может быть несколько User Property
            elif prop_id == 0x26:
                us_pr_length = int.from_bytes(data[i:i+2], 'big')
                i += 2
                val1 = data[i:i+us_pr_length].decode('utf-8')
                i += us_pr_length

                val_length = int.from_bytes(data[i:i+2], 'big')
                i += 2
                val2 = data[i:i+val_length].decode('utf-8')
                i += val_length

                properties[f"User Property {p_us_pr_c}"] = (val1, val2)
                p_us_pr_c += 1
            else:
                raise ValueError(f'prop_id = {prop_id} error')
        # Payloads
    payload_i = i
    # Client ID
    payloads = {}
    client_id_length = (data[payload_i] << 8) | (data[payload_i+1])
    payload_i += 2
    client_id = data[payload_i:payload_i+client_id_length]
    payloads['ClientID'] = client_id
    payload_i += client_id_length
    will_properties = {}
    if will_flag > 0:
        if protocol_version == 5:
            # Опять какая-то тема с Properties
            will_properties_length = 0
            b_count = 1
            x = 1
            i = payload_i
            while True:
                d = data[i]
                will_properties_length += (d & 0x7F) * x
                x *= 128
                b_count += 1
                i += 1
                if d & 0x80 == 0:
                    break
            will_properties_end = i + will_properties_length
            p_us_pr_c = 1
            while i < will_properties_end:
                prop_id = data[i]
                i += 1
                if prop_id in connect_poperties:
                    prop_name, val, i = connect_poperties[prop_id](data, i)
                    will_properties[prop_name] = val
                # Может быть несколько User Property
                elif prop_id == 0x26:
                    us_pr_length = int.from_bytes(data[i:i+2], 'big')
                    i += 2
                    val1 = data[i:i+us_pr_length].decode('utf-8')
                    i += us_pr_length

                    val_length = int.from_bytes(data[i:i+2], 'big')
                    i += 2
                    val2 = data[i:i+val_length].decode('utf-8')
                    i += val_length

                    will_properties[f"User Property {p_us_pr_c}"] = (
                        val1, val2)
                    p_us_pr_c += 1
                else:
                    raise ValueError(f'prop_id = {prop_id} error')
            payloads['Will Properties'] = will_properties
        payload_i = i
        #
        willtopic_flag_length = (
            data[payload_i] << 8) | (data[payload_i+1])
        payload_i += 2
        will_topic = data[payload_i:payload_i +
                          willtopic_flag_length].decode('utf-8')
        payloads['Will Topic'] = will_topic
        payload_i += willtopic_flag_length
        #
        will_payload_length = (data[payload_i] << 8) | (data[payload_i+1])
        payload_i += 2
        will_payload = data[payload_i:payload_i +
                            will_payload_length].decode('utf-8')
        payloads['Will Payload'] = will_payload
        payload_i += will_payload_length
    if username_flag > 0:
        username_length = (data[payload_i] << 8) | (data[payload_i+1])
        payload_i += 2
        username = data[payload_i:payload_i +
                        username_length].decode('utf-8')
        payloads['User Name'] = username
        payload_i += username_length
    if password_flag > 0:
        password_length = (data[payload_i] << 8) | (data[payload_i+1])
        payload_i += 2
        password = data[payload_i:payload_i +
                        password_length].decode('utf-8')
        payloads['Password'] = password
        payload_i += password_length
    return {
        'Type': 1,
        "Variable header": {
            'Protocol Name': protocol_name,
            'Protocol Version': protocol_version,
            "Connect Flags": {
                "User Name Flag": bool(username_flag),
                "Password Flag": bool(password_flag),
                "Will_Retain": bool(will_retain_flag),
                "Will_QoS": will_QoS_flag,
                "Will_Flag": bool(will_flag),
                "Clean_Start": bool(clean_start_flag)
            },
            "Keep Alive": keepalive,
            "Properties": properties if protocol_version == 5 else None
        },
        "Payload": payloads
    }

    # Работа с типом connack


def parse_CONNACK(data: bytes, protocol_version):
    i = 0
    connect_acknowledge_flags = data[i]
    i += 1
    session_present_flag = connect_acknowledge_flags & 0x01
    connection_reason_code = data[i]
    i += 1
    # Список значений connect reason code
    connection_reason_codes = { 
        0x00: ("Success"),
        0x01: ("Connection Refused, unacceptable protocol version"),
        0x02: ("Connection Refused, identifier rejected"),
        0x03: ("Connection Refused, Server unavailable"),
        0x04: ("Connection Refused, bad user name or password"),
        0x05: ("Connection Refused, not authorized "),
        0x80: ("Unspecified error"),
        0x81: ("Malformed Packet "),
        0x82: ("Protocol Error"),
        0x83: ("Implementation specific error"),
        0x84: ("Unsupported Protocol Version "),
        0x85: ("Client Identifier not valid"),
        0x86: ("Bad User Name or Password"),
        0x87: ("Not authorized "),
        0x88: ("Server unavailable"),
        0x89: ("Server busy"),
        0x8A: ("Banned"),
        0x8C: ("Bad authentication method"),
        0x90: ("Topic Name invalid"),
        0x95: ("Packet too large"),
        0x97: ("Quota exceeded"),
        0x99: ("Payload format invalid"),
        0x9A: ("Retain not supported"),
        0x9B: ("QoS not supported"),
        0x9C: ("Use another server"),
        0x9D: ("Server moved"),
        0x9F: ("Connection rate exceeded"),
    }
    connection_reason_code_text = connection_reason_codes[connection_reason_code]
    # Properties
    if protocol_version == 5:
        connack_poperties = {
            0x11: lambda data, i: ("Session Expiry Interval", int.from_bytes(data[i:i+4], 'big'), i + 4),
            0x21: lambda data, i: ("Receive Maximum", int.from_bytes(data[i:i+2], 'big'), i + 2),
            0x27: lambda data, i: ("Maximum Packet Size", int.from_bytes(data[i:i+4], 'big'), i + 4),
            0x22: lambda data, i: ("Topic Alias Maximum", int.from_bytes(data[i:i+2], 'big'), i + 2),
            0x15: lambda data, i: (
                "Authentication Method", data[i+2:i+2 +
                                            int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
            0x16: lambda data, i: (
                "Authentication Data", data[i+2:i+2 +
                                            int.from_bytes(data[i:i+2], 'big')],
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
            0x12: lambda data, i: (
                "Assigned Client Identifier", data[i+2:i+2 +
                                                int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
            0x13: lambda data, i: ("Server Keep Alive", int.from_bytes(data[i:i+2], 'big'), i + 2),
            0x1A: lambda data, i: (
                "Response Information", data[i+2:i+2 +
                                            int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
            0x1C: lambda data, i: (
                "Server Reference", data[i+2:i+2 +
                                        int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
            0x1F: lambda data, i: (
                "Reason String", data[i+2:i+2 +
                                    int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
            0x24: lambda data, i: ("Maximum QoS", data[i], i + 1),
            0x25: lambda data, i: ("Retain Available", data[i], i + 1),
            0x28: lambda data, i: ("Wildcard Subscription Available", data[i], i + 1),
            0x29: lambda data, i: ("Subscription Identifier Available", data[i], i + 1),
            0x2A: lambda data, i: ("Shared Subscription Available ", data[i], i + 1),
        }
        properties = {}
        properties_length = 0
        b_count = 1
        x = 1
        while True:
            d = data[i]
            properties_length += (d & 0x7F) * x
            x *= 128
            b_count += 1
            i += 1
            if d & 0x80 == 0:
                break
        properties_end = i + properties_length
        p_us_pr_c = 1
        while i < properties_end:
            prop_id = data[i]
            i += 1
            if prop_id in connack_poperties:
                prop_name, val, i = connack_poperties[prop_id](data, i)
                properties[prop_name] = val
            # Может быть несколько User Property
            elif prop_id == 0x26:
                us_pr_length = int.from_bytes(data[i:i+2], 'big')
                i += 2
                val1 = data[i:i+us_pr_length].decode('utf-8')
                i += us_pr_length

                val_length = int.from_bytes(data[i:i+2], 'big')
                i += 2
                val2 = data[i:i+val_length].decode('utf-8')
                i += val_length

                properties[f"User Property {p_us_pr_c}"] = (val1, val2)
                p_us_pr_c += 1
            else:
                raise ValueError(f'prop_id = {prop_id} error')

    return {
        'Type': 2,
        "Variable header": {
            "Connect Acknowledge Flags": connect_acknowledge_flags,
            "Connect Reason Code": connection_reason_code,
            "Properties": properties if protocol_version == 5 else None
        }
    }

    # Работа с типом publish


def parse_PUBLISH(data: bytes, flags, remaining_length, protocol_version):
    dup_flags = (flags >> 3) & 0x01
    qos_flags = (flags >> 1) & 0x03
    retain_flag = flags & 0x01
    packet_identifier = 'none'
    i = 0
    topic_name_length = (data[i] << 8) | (data[i+1])
    i += 2
    topic_name = data[i:i+topic_name_length].decode('utf-8')
    i += topic_name_length
    if qos_flags > 0:
        packet_identifier = (data[i] << 8) | (data[i+1])
        i += 2
        # Properties
    if protocol_version == 5:
        publish_poperties = {
            0x01: lambda data, i: ("Payload Format Indicator", data[i], i + 1),
            0x02: lambda data, i: ("Message Expiry Interval", int.from_bytes(data[i:i+4], 'big'), i + 4),
            0x03: lambda data, i: (
                "Content Type", data[i+2:i+2 +
                                    int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
            0x08: lambda data, i: (
                "Response Topic", data[i+2:i+2 +
                                    int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
            0x09: lambda data, i: (
                "Correlation Data", data[i+2:i+2 +
                                        int.from_bytes(data[i:i+2], 'big')],
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
            0x23: lambda data, i: ("Topic Alias", int.from_bytes(data[i:i+2], 'big'), i + 2),
        }
        properties = {}
        properties_length = 0
        b_count = 1
        x = 1
        while True:
            d = data[i]
            properties_length += (d & 0x7F) * x
            x *= 128
            b_count += 1
            i += 1
            if d & 0x80 == 0:
                break
        properties_end = i + properties_length
        p_us_pr_c = 1
        while i < properties_end:
            prop_id = data[i]
            i += 1
            if prop_id in publish_poperties:
                prop_name, val, i = publish_poperties[prop_id](data, i)
                properties[prop_name] = val
            # Может быть несколько User Property
            elif prop_id == 0x26:
                us_pr_length = int.from_bytes(data[i:i+2], 'big')
                i += 2
                val1 = data[i:i+us_pr_length].decode('utf-8')
                i += us_pr_length

                val_length = int.from_bytes(data[i:i+2], 'big')
                i += 2
                val2 = data[i:i+val_length].decode('utf-8')
                i += val_length

                properties[f"User Property {p_us_pr_c}"] = (val1, val2)
                p_us_pr_c += 1
            elif prop_id == 0x0B:
                val = 0
                x = 1
                while True:
                    d = data[i]
                    val += (d & 0x7F) * x
                    x *= 128
                    i += 1
                    if (d & 0x80) == 0:
                        break
                properties['SubscriptionIdentifier'] = val
            else:
                raise ValueError(f'prop_id = {prop_id} error')
        # Payloads
        # Содержит какие-то данные неопределенные в стандарте
    payload_i = i
    payload_length = remaining_length - payload_i
    payloads = {}
    if payload_length > 0:
        payloads['payload'] = data[payload_i:payload_i+payload_length]
    else:
        payloads['payload'] = 'none'
    return {
        'Type': 3,
        "Flags": {
            "DUP flag": dup_flags,
            "QoS level": qos_flags,
            "RETAIN": retain_flag
        },
        "Variable header": {
            "Topic Name": topic_name,
            "Packet Identifier": packet_identifier,
            "Properties": properties if protocol_version == 5 else None
        },
        "Payload": payloads
    }

    # Работа с типом puback


def parse_PUBACK(data: bytes, remaining_length, protocol_version):
    i = 0
    packet_identifier = (data[i] << 8) | (data[i+1])
    i += 2
    if (remaining_length == 2):
        puback_reason_code = 0x00
        puback_reason_code_text = "Success"
        return {
            'Type': 4,
            "Variable header": {
                "Packet Identifier": packet_identifier,
                "PUBACK Reason Code": puback_reason_code if protocol_version == 5 else None,
                "Properties": None
            }
        }
    puback_reason_code = data[i]
    i += 1
    # Список значений puback reason code
    puback_reason_codes = {
        0x00: ("Success"),
        0x10: ("No matching subscribers"),
        0x80: ("Unspecified error"),
        0x83: ("Implementation specific error"),
        0x87: ("Not authorized"),
        0x90: ("Topic Name invalid"),
        0x91: ("Packet identifier in use"),
        0x97: ("Quota exceeded"),
        0x99: ("Payload format invalid"),
    }
    puback_reason_code_text = puback_reason_codes[puback_reason_code]

    # Properties
    puback_poperties = {
        0x1F: lambda data, i: (
            "Reason String", data[i+2:i+2 +
                                  int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
            i + 2 + int.from_bytes(data[i:i+2], 'big')
        ),
    }
    properties = {}
    properties_length = 0
    b_count = 1
    x = 1
    while True:
        d = data[i]
        properties_length += (d & 0x7F) * x
        x *= 128
        b_count += 1
        i += 1
        if d & 0x80 == 0:
            break
    properties_end = i + properties_length
    p_us_pr_c = 1
    while i < properties_end:
        prop_id = data[i]
        i += 1
        if prop_id in puback_poperties:
            prop_name, val, i = puback_poperties[prop_id](data, i)
            properties[prop_name] = val
        # Может быть несколько User Property
        elif prop_id == 0x26:
            us_pr_length = int.from_bytes(data[i:i+2], 'big')
            i += 2
            val1 = data[i:i+us_pr_length].decode('utf-8')
            i += us_pr_length

            val_length = int.from_bytes(data[i:i+2], 'big')
            i += 2
            val2 = data[i:i+val_length].decode('utf-8')
            i += val_length

            properties[f"User Property {p_us_pr_c}"] = (val1, val2)
            p_us_pr_c += 1
        else:
            raise ValueError(f'prop_id = {prop_id} error')
    return {
        'Type': 4,
        "Variable header": {
            "Packet Identifier": packet_identifier,
            "PUBACK Reason Code": puback_reason_code,
            "Properties": properties
        }
    }

    # Работа с типом pubrec


def parse_PUBREC(data: bytes, remaining_length, protocol_version):
    i = 0
    packet_identifier = (data[i] << 8) | (data[i+1])
    i += 2
    if (remaining_length == 2):
        pubrec_reason_code = 0x00
        pubrec_reason_code_text = "Success"
        return {
            'Type': 5,
            "Variable header": {
                "Packet Identifier": packet_identifier,
                "PUBREC Reason Code": pubrec_reason_code if protocol_version == 5 else None,
                "Properties": None
            }
        }
    pubrec_reason_code = data[i]
    i += 1
    # Список значений pubrec reason code
    pubrec_reason_codes = {
        0x00: ("Success"),
        0x10: ("No matching subscribers"),
        0x80: ("Unspecified error"),
        0x83: ("Implementation specific error"),
        0x87: ("Not authorized"),
        0x90: ("Topic Name invalid"),
        0x91: ("Packet identifier in use"),
        0x97: ("Quota exceeded"),
        0x99: ("Payload format invalid"),
    }
    pubrec_reason_code_text = pubrec_reason_codes[pubrec_reason_code]

    # Properties
    pubrec_poperties = {
        0x1F: lambda data, i: (
            "Reason String", data[i+2:i+2 +
                                  int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
            i + 2 + int.from_bytes(data[i:i+2], 'big')
        ),
    }
    properties = {}
    properties_length = 0
    b_count = 1
    x = 1
    while True:
        d = data[i]
        properties_length += (d & 0x7F) * x
        x *= 128
        b_count += 1
        i += 1
        if d & 0x80 == 0:
            break
    properties_end = i + properties_length
    p_us_pr_c = 1
    while i < properties_end:
        prop_id = data[i]
        i += 1
        if prop_id in pubrec_poperties:
            prop_name, val, i = pubrec_poperties[prop_id](data, i)
            properties[prop_name] = val
        # Может быть несколько User Property
        elif prop_id == 0x26:
            us_pr_length = int.from_bytes(data[i:i+2], 'big')
            i += 2
            val1 = data[i:i+us_pr_length].decode('utf-8')
            i += us_pr_length

            val_length = int.from_bytes(data[i:i+2], 'big')
            i += 2
            val2 = data[i:i+val_length].decode('utf-8')
            i += val_length

            properties[f"User Property {p_us_pr_c}"] = (val1, val2)
            p_us_pr_c += 1
        else:
            raise ValueError(f'prop_id = {prop_id} error')
    return {
        'Type': 5,
        "Variable header": {
            "Packet Identifier": packet_identifier,
            "PUBREC Reason Code": pubrec_reason_code,
            "Properties": properties
        }
    }

    # Работа с типом pubrel


def parse_PUBREL(data: bytes, remaining_length, protocol_version):
    i = 0
    packet_identifier = (data[i] << 8) | (data[i+1])
    i += 2
    if (remaining_length == 2):
        pubrel_reason_code = 0x00
        pubrel_reason_code_text = "Success"
        return {
            'Type': 6,
            "Variable header": {
                "Packet Identifier": packet_identifier,
                "PUBREL Reason Code": pubrel_reason_code if protocol_version == 5 else None,
                "Properties": None
            }
        }
    pubrel_reason_code = data[i]
    i += 1
    # Список значений pubrel reason code
    pubrel_reason_codes = {
        0x00: ("Success"),
        0x92: ("Packet Identifier not found"),
    }
    pubrel_reason_code_text = pubrel_reason_codes[pubrel_reason_code]

    # Properties
    pubrec_poperties = {
        0x1F: lambda data, i: (
            "Reason String", data[i+2:i+2 +
                                  int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
            i + 2 + int.from_bytes(data[i:i+2], 'big')
        ),
    }
    properties = {}
    properties_length = 0
    b_count = 1
    x = 1
    while True:
        d = data[i]
        properties_length += (d & 0x7F) * x
        x *= 128
        b_count += 1
        i += 1
        if d & 0x80 == 0:
            break
    properties_end = i + properties_length
    p_us_pr_c = 1
    while i < properties_end:
        prop_id = data[i]
        i += 1
        if prop_id in pubrec_poperties:
            prop_name, val, i = pubrec_poperties[prop_id](data, i)
            properties[prop_name] = val
        # Может быть несколько User Property
        elif prop_id == 0x26:
            us_pr_length = int.from_bytes(data[i:i+2], 'big')
            i += 2
            val1 = data[i:i+us_pr_length].decode('utf-8')
            i += us_pr_length

            val_length = int.from_bytes(data[i:i+2], 'big')
            i += 2
            val2 = data[i:i+val_length].decode('utf-8')
            i += val_length

            properties[f"User Property {p_us_pr_c}"] = (val1, val2)
            p_us_pr_c += 1
        else:
            raise ValueError(f'prop_id = {prop_id} error')
    return {
        'Type': 6,
        "Variable header": {
            "Packet Identifier": packet_identifier,
            "PUBREL Reason Code": pubrel_reason_code,
            "Properties": properties
        }
    }

    # Работа с типом pubcomp


def parse_PUBCOMP(data: bytes, remaining_length, protocol_version):
    i = 0
    packet_identifier = (data[i] << 8) | (data[i+1])
    i += 2
    if (remaining_length == 2):
        pubcomp_reason_code = 0x00
        pubcomp_reason_code_text = "Success"
        return {
            'Type': 7,
            "Variable header": {
                "Packet Identifier": packet_identifier,
                "PUBCOMP Reason Code": pubcomp_reason_code if protocol_version == 5 else None,
                "Properties": None
            }
        }
    pubcomp_reason_code = data[i]
    i += 1
    # Список значений pubcomp reason code
    pubcomp_reason_codes = {
        0x00: ("Success"),
        0x92: ("Packet Identifier not found"),
    }
    pubcomp_reason_code_text = pubcomp_reason_codes[pubcomp_reason_code]

    # Properties
    pubcomp_poperties = {
        0x1F: lambda data, i: (
            "Reason String", data[i+2:i+2 +
                                  int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
            i + 2 + int.from_bytes(data[i:i+2], 'big')
        ),
    }
    properties = {}
    properties_length = 0
    b_count = 1
    x = 1
    while True:
        d = data[i]
        properties_length += (d & 0x7F) * x
        x *= 128
        b_count += 1
        i += 1
        if d & 0x80 == 0:
            break
    properties_end = i + properties_length
    p_us_pr_c = 1
    while i < properties_end:
        prop_id = data[i]
        i += 1
        if prop_id in pubcomp_poperties:
            prop_name, val, i = pubcomp_poperties[prop_id](data, i)
            properties[prop_name] = val
        # Может быть несколько User Property
        elif prop_id == 0x26:
            us_pr_length = int.from_bytes(data[i:i+2], 'big')
            i += 2
            val1 = data[i:i+us_pr_length].decode('utf-8')
            i += us_pr_length

            val_length = int.from_bytes(data[i:i+2], 'big')
            i += 2
            val2 = data[i:i+val_length].decode('utf-8')
            i += val_length

            properties[f"User Property {p_us_pr_c}"] = (val1, val2)
            p_us_pr_c += 1
        else:
            raise ValueError(f'prop_id = {prop_id} error')
    return {
        'Type': 7,
        "Variable header": {
            "Packet Identifier": packet_identifier,
            "PUBCOMP Reason Code": pubcomp_reason_code,
            "Properties": properties
        }
    }

    # Работа с типом subscribe


def parse_SUBSCRIBE(data: bytes, remaining_length, protocol_version):
    i = 0
    packet_identifier = (data[i] << 8) | (data[i+1])
    i += 2
    # Properties
    if protocol_version == 5:
        properties = {}
        properties_length = 0
        b_count = 1
        x = 1
        while True:
            d = data[i]
            properties_length += (d & 0x7F) * x
            x *= 128
            b_count += 1
            i += 1
            if d & 0x80 == 0:
                break
        properties_end = i + properties_length
        p_us_pr_c = 1
        while i < properties_end:
            prop_id = data[i]
            i += 1
            if prop_id == 0x0B:
                val = 0
                x = 1
                while True:
                    d = data[i]
                    val += (d & 0x7F) * x
                    x *= 128
                    i += 1
                    if (d & 0x80) == 0:
                        break
                properties['SubscriptionIdentifier'] = val
            # Может быть несколько User Property
            elif prop_id == 0x26:
                us_pr_length = int.from_bytes(data[i:i+2], 'big')
                i += 2
                val1 = data[i:i+us_pr_length].decode('utf-8')
                i += us_pr_length

                val_length = int.from_bytes(data[i:i+2], 'big')
                i += 2
                val2 = data[i:i+val_length].decode('utf-8')
                i += val_length

                properties[f"User Property {p_us_pr_c}"] = (val1, val2)
                p_us_pr_c += 1
            else:
                raise ValueError(f'prop_id = {prop_id} error')
    # payload
    payload_i = i
    payloads = {}
    c = 1
    payload_length = remaining_length - payload_i
    while payload_i < i+payload_length:
        topic_filter_length = (data[payload_i] << 8) | (data[payload_i+1])
        payload_i += 2
        topic_filter = data[payload_i:payload_i +
                            topic_filter_length].decode('utf-8')
        payload_i += topic_filter_length
        payloads[f'The Topic Filter'] = topic_filter
        subscription_options = data[payload_i]
        payloads[f'Subscription Options'] = subscription_options
        payload_i += 1
        c += 1

    return {
        'Type': 8,
        "Variable header": {
            "Packet Identifier": packet_identifier,
            "Properties": properties if protocol_version == 5 else None
        },
        "Payload": payloads
    }

    # Работа с типом suback


def parse_SUBACK(data: bytes, remaining_length, protocol_version):
    i = 0
    packet_identifier = (data[i] << 8) | (data[i+1])
    i += 2
    # Properties
    if protocol_version == 5:
        suback_poperties = {
            0x1F: lambda data, i: (
                "Reason String", data[i+2:i+2 +
                                    int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
        }
        properties = {}
        properties_length = 0
        b_count = 1
        x = 1
        while True:
            d = data[i]
            properties_length += (d & 0x7F) * x
            x *= 128
            b_count += 1
            i += 1
            if d & 0x80 == 0:
                break
        properties_end = i + properties_length
        p_us_pr_c = 1
        while i < properties_end:
            prop_id = data[i]
            i += 1
            if prop_id in suback_poperties:
                prop_name, val, i = suback_poperties[prop_id](data, i)
                properties[prop_name] = val
            # Может быть несколько User Property
            elif prop_id == 0x26:
                us_pr_length = int.from_bytes(data[i:i+2], 'big')
                i += 2
                val1 = data[i:i+us_pr_length].decode('utf-8')
                i += us_pr_length

                val_length = int.from_bytes(data[i:i+2], 'big')
                i += 2
                val2 = data[i:i+val_length].decode('utf-8')
                i += val_length

                properties[f"User Property {p_us_pr_c}"] = (val1, val2)
                p_us_pr_c += 1
            else:
                raise ValueError(f'prop_id = {prop_id} error')
    # payload
    suback_reason_codes = {
        0x00: ("Granted QoS 0"),
        0x01: ("Granted QoS 1"),
        0x02: ("Granted QoS 2"),
        0x80: ("Unspecified error"),
        0x83: ("Implementation specific error"),
        0x87: ("Not authorized"),
        0x8F: ("Topic Filter invalid"),
        0x91: ("Packet Identifier in use"),
        0x97: ("Quota exceeded"),
        0x9E: ("Shared Subscriptions not supported"),
        0xA1: ("Subscription Identifiers not supported"),
        0xA2: ("Wildcard Subscriptions not supported"),
    }
    payload_i = i
    payloads = {}
    c = 1
    payload_length = remaining_length - payload_i
    while payload_i < i+payload_length:
        suback_reason_code = data[payload_i]
        payload_i += 1
        suback_reason_code_text = suback_reason_codes[suback_reason_code]
        payloads[f'suback_reason_code_text {c}'] = suback_reason_code_text
        c += 1

    return {
        'Type': 9,
        "Variable header": {
            "Packet Identifier": packet_identifier,
            "Properties": properties if protocol_version == 5 else None
        },
        "Payload": payloads
    }

    # Работа с типом unsubscribe


def parse_UNSUBSCRIBE(data: bytes, remaining_length, protocol_version):
    i = 0
    packet_identifier = (data[i] << 8) | (data[i+1])
    i += 2
    # Properties
    if protocol_version == 5:
        properties = {}
        properties_length = 0
        b_count = 1
        x = 1
        while True:
            d = data[i]
            properties_length += (d & 0x7F) * x
            x *= 128
            b_count += 1
            i += 1
            if d & 0x80 == 0:
                break
        properties_end = i + properties_length
        p_us_pr_c = 1
        while i < properties_end:
            prop_id = data[i]
            i += 1
            # Может быть несколько User Property
            if prop_id == 0x26:
                us_pr_length = int.from_bytes(data[i:i+2], 'big')
                i += 2
                val1 = data[i:i+us_pr_length].decode('utf-8')
                i += us_pr_length

                val_length = int.from_bytes(data[i:i+2], 'big')
                i += 2
                val2 = data[i:i+val_length].decode('utf-8')
                i += val_length

                properties[f"User Property {p_us_pr_c}"] = (val1, val2)
                p_us_pr_c += 1
            else:
                raise ValueError(f'prop_id = {prop_id} error')
    # payload
    payload_i = i
    payloads = {}
    c = 1
    payload_length = remaining_length - payload_i
    while payload_i < i+payload_length:
        topic_filter_length = (data[payload_i] << 8) | (data[payload_i+1])
        payload_i += 2
        topic_filter = data[payload_i:payload_i +
                            topic_filter_length].decode('utf-8')
        payload_i += topic_filter_length
        payloads[f'topic_filter {c}'] = topic_filter
        c += 1

    return {
        'Type': 10,
        "Variable header": {
            "Packet Identifier": packet_identifier,
            "Properties": properties if protocol_version == 5 else None
        },
        "Payload": payloads
    }

    # Работа с типом unsuback


def parse_UNSUBACK(data: bytes, remaining_length, protocol_version):
    i = 0
    packet_identifier = (data[i] << 8) | (data[i+1])
    i += 2
    # Properties
    if protocol_version == 5:
        unsuback_poperties = {
            0x1F: lambda data, i: (
                "Reason String", data[i+2:i+2 +
                                    int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
                i + 2 + int.from_bytes(data[i:i+2], 'big')
            ),
        }
        properties = {}
        properties_length = 0
        b_count = 1
        x = 1
        while True:
            d = data[i]
            properties_length += (d & 0x7F) * x
            x *= 128
            b_count += 1
            i += 1
            if d & 0x80 == 0:
                break
        properties_end = i + properties_length
        p_us_pr_c = 1
        while i < properties_end:
            prop_id = data[i]
            i += 1
            if prop_id in unsuback_poperties:
                prop_name, val, i = unsuback_poperties[prop_id](data, i)
                properties[prop_name] = val
            # Может быть несколько User Property
            elif prop_id == 0x26:
                us_pr_length = int.from_bytes(data[i:i+2], 'big')
                i += 2
                val1 = data[i:i+us_pr_length].decode('utf-8')
                i += us_pr_length

                val_length = int.from_bytes(data[i:i+2], 'big')
                i += 2
                val2 = data[i:i+val_length].decode('utf-8')
                i += val_length

                properties[f"User Property {p_us_pr_c}"] = (val1, val2)
                p_us_pr_c += 1
            else:
                raise ValueError(f'prop_id = {prop_id} error')
    # payload
        unsuback_reason_codes = {
            0x00: ("Success"),
            0x11: ("No subscription existed"),
            0x80: ("Unspecified error"),
            0x83: ("Implementation specific error"),
            0x87: ("Not authorized"),
            0x8F: ("Topic Filter invalid"),
            0x91: ("Packet Identifier in use"),
        }
        payload_i = i
        payloads = {}
        c = 1
        payload_length = remaining_length - payload_i
        while payload_i < i+payload_length:
            unsuback_reason_code = data[payload_i]
            payload_i += 1
            unsuback_reason_code_text = unsuback_reason_codes[unsuback_reason_code]
            payloads[f'unsuback_reason_code_text {c}'] = unsuback_reason_code_text
            c += 1

    return {
        'Type': 11,
        "Variable header": {
            "Packet Identifier": packet_identifier,
            "Properties": properties if protocol_version == 5 else None
        },
        "Payload": payloads if protocol_version == 5 else None
    }

    # Работа с типом pingreq


def parse_PINGREQ():
    return {
        'Type': 12
    }

    # Работа с типом pingresp


def parse_PINGRESP():
    return {
        'Type': 13
    }

    # Работа с типом disconnect


def parse_DISCONNECT(data: bytes, remaining_length, protocol_version):
    if remaining_length == 0:
        return {
            'Type': 14,
            "Variable header": {
                "DISCONNECT Reason Code": 0x00 if protocol_version == 5 else None,
                "Properties": None
            }
        }
    i = 0
    disconnect_reason_code = data[i]
    i += 1
    # Список значений disconnect reason code
    disconnect_reason_codes = {
        0x00: ("Normal disconnection"),
        0x04: ("Disconnect with Will Message"),
        0x80: ("Unspecified error"),
        0x81: ("Malformed Packet"),
        0x82: ("Protocol Error"),
        0x83: ("Implementation specific error"),
        0x87: ("Not authorized"),
        0x89: ("Server busy"),
        0x8B: ("Server shutting down"),
        0x8D: ("Keep Alive timeout"),
        0x8E: ("Session taken over"),
        0x8F: ("Topic Filter invalid"),
        0x90: ("Topic Name invalid"),
        0x93: ("Receive Maximum exceeded"),
        0x94: ("Topic Alias invalid"),
        0x95: ("Packet too large"),
        0x96: ("Message rate too high"),
        0x97: ("Quota exceeded"),
        0x98: ("Administrative action"),
        0x99: ("Payload format invalid"),
        0x9A: ("Retain not supported"),
        0x9B: ("QoS not supported"),
        0x9C: ("Use another server"),
        0x9D: ("Server moved"),
        0x9E: ("Shared Subscriptions not supported"),
        0x9F: ("Connection rate exceeded"),
        0xA0: ("Maximum connect time"),
        0xA1: ("Subscription Identifiers not supported"),
        0xA2: ("Wildcard Subscriptions not supported"),
    }
    disconnect_reason_code_text = disconnect_reason_codes[disconnect_reason_code]

    # Properties
    disconnect_poperties = {
        0x1F: lambda data, i: (
            "Reason String", data[i+2:i+2 +
                                  int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
            i + 2 + int.from_bytes(data[i:i+2], 'big')
        ),
        0x11: lambda data, i: ("Session Expiry Interval", int.from_bytes(data[i:i+4], 'big'), i + 4),
        0x1C: lambda data, i: (
            "Server Reference", data[i+2:i+2 +
                                     int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
            i + 2 + int.from_bytes(data[i:i+2], 'big')
        ),
    }
    properties = {}
    properties_length = 0
    b_count = 1
    x = 1
    while True:
        if remaining_length < 2:
            break
        d = data[i]
        properties_length += (d & 0x7F) * x
        x *= 128
        b_count += 1
        i += 1
        if d & 0x80 == 0:
            break
    properties_end = i + properties_length
    p_us_pr_c = 1
    while i < properties_end:
        prop_id = data[i]
        i += 1
        if prop_id in disconnect_poperties:
            prop_name, val, i = disconnect_poperties[prop_id](data, i)
            properties[prop_name] = val
        # Может быть несколько User Property
        elif prop_id == 0x26:
            us_pr_length = int.from_bytes(data[i:i+2], 'big')
            i += 2
            val1 = data[i:i+us_pr_length].decode('utf-8')
            i += us_pr_length

            val_length = int.from_bytes(data[i:i+2], 'big')
            i += 2
            val2 = data[i:i+val_length].decode('utf-8')
            i += val_length

            properties[f"User Property {p_us_pr_c}"] = (val1, val2)
            p_us_pr_c += 1
        else:
            raise ValueError(f'prop_id = {prop_id} error')
    return {
        'Type': 14,
        "Variable header": {
            "DISCONNECT Reason Code": disconnect_reason_code,
            "Properties": properties
        }
    }

    # Работа с типом auth


def parse_AUTH(data: bytes, remaining_length):
    if remaining_length == 0:
        return {
            'Type': 15,
            "Variable header": {
                "Authenticate Reason Code": 0x00,
                "Properties": None
            }
        }
    i = 0
    auth_reason_code = data[i]
    i += 1
    # Список значений auth reason code
    auth_reason_codes = {
        0x00: ("Success"),
        0x18: ("Continue authentication"),
        0x19: ("Re-authenticate"),
    }
    auth_reason_code_text = auth_reason_codes[auth_reason_code]

    # Properties
    auth_poperties = {
        0x1F: lambda data, i: (
            "Reason String", data[i+2:i+2 +
                                  int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
            i + 2 + int.from_bytes(data[i:i+2], 'big')
        ),
        0x15: lambda data, i: (
            "Authentication Method", data[i+2:i+2 +
                                          int.from_bytes(data[i:i+2], 'big')].decode('utf-8'),
            i + 2 + int.from_bytes(data[i:i+2], 'big')
        ),
        0x16: lambda data, i: (
            "Authentication Data", data[i+2:i+2 +
                                        int.from_bytes(data[i:i+2], 'big')],
            i + 2 + int.from_bytes(data[i:i+2], 'big')
        ),
    }
    properties = {}
    properties_length = 0
    b_count = 1
    x = 1
    while True:
        if remaining_length < 2:
            break
        d = data[i]
        properties_length += (d & 0x7F) * x
        x *= 128
        b_count += 1
        i += 1
        if d & 0x80 == 0:
            break
    properties_end = i + properties_length
    p_us_pr_c = 1
    while i < properties_end:
        prop_id = data[i]
        i += 1
        if prop_id in auth_poperties:
            prop_name, val, i = auth_poperties[prop_id](data, i)
            properties[prop_name] = val
        # Может быть несколько User Property
        elif prop_id == 0x26:
            us_pr_length = int.from_bytes(data[i:i+2], 'big')
            i += 2
            val1 = data[i:i+us_pr_length].decode('utf-8')
            i += us_pr_length

            val_length = int.from_bytes(data[i:i+2], 'big')
            i += 2
            val2 = data[i:i+val_length].decode('utf-8')
            i += val_length

            properties[f"User Property {p_us_pr_c}"] = (val1, val2)
            p_us_pr_c += 1
        else:
            raise ValueError(f'prop_id = {prop_id} error')
    return {
        'Type': 15,
        "Variable header": {
            "Authenticate Reason Code": auth_reason_code,
            "Properties": properties
        }
    }

# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------


def deparse_fixed_header(packet, protocol_version):

    packet_type = packet['Type']

    if packet_type == 1:
        return deparse_CONNECT(packet, protocol_version)
    elif packet_type == 2:
        return deparse_CONNACK(packet, protocol_version)
    elif packet_type == 3:
        return deparse_PUBLISH(packet, protocol_version)
    elif packet_type == 4:
        return deparse_PUBACK(packet)
    elif packet_type == 5:
        return deparse_PUBREC(packet)
    elif packet_type == 6:
        return deparse_PUBREL(packet)
    elif packet_type == 7:
        return deparse_PUBCOMP(packet)
    elif packet_type == 8:
        return deparse_SUBSCRIBE(packet, protocol_version)
    elif packet_type == 9:
        return deparse_SUBACK(packet, protocol_version)
    elif packet_type == 10:
        return deparse_UNSUBSCRIBE(packet, protocol_version)
    elif packet_type == 11:
        return deparse_UNSUBACK(packet, protocol_version)
    elif packet_type == 12:
        return deparse_PINGREQ()
    elif packet_type == 13:
        return deparse_PINGRESP()
    elif packet_type == 14:
        return deparse_DISCONNECT(packet)
    elif packet_type == 15:
        return deparse_AUTH(packet)

    # Работа с типом connect


def deparse_CONNECT(packet, protocol_version):
    # Fixed Header
    fixed_header = bytearray()
    fixed_header.append(0x10)  # Тип пакета + flags(0)
    # remaining length в конце
    # Variable header
    variable_header = bytearray()
    # Protocol name
    variable_header.append(0x0)  # protocol_name_length_L = 0
    variable_header.append(0x4)  # protocol_name_length_R = 4
    variable_header += b'MQTT'  # protocol_name = b"MQTT"
    # Protocol version
    if protocol_version == 5:
        variable_header.append(0x5)  # protocol_version = 5
    elif protocol_version == 4:
        variable_header.append(0x4)  # protocol_version = 3.1.1
    # Connect flags
    User_Name_Flag = packet["Variable header"]["Connect Flags"]["User Name Flag"]
    Password_Flag = packet["Variable header"]["Connect Flags"]["Password Flag"]
    Will_Retain = packet["Variable header"]["Connect Flags"]["Will_Retain"]
    Will_QoS = packet["Variable header"]["Connect Flags"]["Will_QoS"]
    Will_Flag = packet["Variable header"]["Connect Flags"]["Will_Flag"]
    Clean_Start = packet["Variable header"]["Connect Flags"]["Clean_Start"]
    flags = 0
    if Clean_Start:
        flags |= 0x02
    if Will_Flag:
        flags |= 0x04
        flags |= (Will_QoS & 0x03) << 3
        if Will_Retain:
            flags |= 0x20
    if Password_Flag:
        flags |= 0x40
    if User_Name_Flag:
        flags |= 0x80
    variable_header.append(flags)
    # Keep-alive
    variable_header += packet["Variable header"]['Keep Alive'].to_bytes(2, 'big')
    # Properties UserProp номерки добавить
    connect_properties = {
        "Session Expiry Interval": lambda v: b'\x11' + v.to_bytes(4, 'big'),
        "Receive Maximum": lambda v: b'\x21' + v.to_bytes(2, 'big'),
        "Maximum Packet Size": lambda v: b'\x27' + v.to_bytes(4, 'big'),
        "Topic Alias Maximum": lambda v: b'\x22' + v.to_bytes(2, 'big'),
        "Request Response Information": lambda v: b'\x19' + bytes([v]),
        "Request Problem Information": lambda v: b'\x17' + bytes([v]),
        "Authentication Method": lambda v:
        (
            b'\x15' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
        "Authentication Data": lambda v:
        (
            b'\x16' + len(v).to_bytes(2, 'big') + v
        ),
        # Will properties
        "Will Delay Interval": lambda v: b'\x18' + v.to_bytes(4, 'big'),
        "Payload Format Indicator": lambda v: b'\x01' + bytes([v]),
        "Message Expiry Interval": lambda v: b'\x02' + v.to_bytes(4, 'big'),
        "Content Type": lambda v:
        (
            b'\x03' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
        "Response Topic": lambda v:
        (
            b'\x08' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
        "Correlation Data": lambda v:
        (
            b'\x09' + len(v).to_bytes(2, 'big') + v
        ),
    }
    properties = bytearray()
    for name, value in packet["Variable header"]["Properties"].items():
        if name == "User Property":
            userprop = bytearray()
            for key, value in value:
                userprop.append(0x26)
                userprop += len(key.encode()).to_bytes(2,'big') + key.encode()
                userprop += len(value.encode()).to_bytes(2,'big') + value.encode()
            properties += userprop
        elif name in connect_properties:
            properties += connect_properties[name](value)
        else:
            raise ValueError(f"Deparse CONNECT property: {name} error")
    # Variable byte integer
    vbi = bytearray()
    prop_len = len(properties)
    while True:
        d = prop_len % 128
        prop_len //= 128
        if prop_len > 0:
            d |= 0x80
        vbi.append(d)
        if prop_len == 0:
            break
    if protocol_version == 5:
        variable_header += bytes(vbi) + properties
    # Payload
    payload = bytearray()
    # Client id
    payload += len(packet['Payload']['ClientID']).to_bytes(2,
                                                           'big') + packet['Payload']['ClientID'].encode()
    # Will payload
    if Will_Flag:
        # Will properties
        will_properties = bytearray()
        for name, value in packet['Payload']["Will Properties"].items():
            if name == "User Property":
                userprop = bytearray()
                for key, value in value:
                    userprop.append(0x26)
                    userprop += len(key.encode()).to_bytes(2,
                                                           'big') + key.encode()
                    userprop += len(value.encode()).to_bytes(2,
                                                             'big') + value.encode()
                will_properties += userprop
            elif name in connect_properties:
                will_properties += connect_properties[name](value)
            else:
                raise ValueError(f"Deparse CONNECT property: {name} error")
        # Variable byte integer
        vbi = bytearray()
        prop_len = len(will_properties)
        while True:
            d = prop_len % 128
            prop_len //= 128
            if prop_len > 0:
                d |= 0x80
            vbi.append(d)
            if prop_len == 0:
                break
        if protocol_version == 5:
            payload += bytes(vbi) + will_properties
        # Will payload
        payload += len(packet['Payload']['Will Topic']).to_bytes(2, 'big') + packet['Payload']['Will Topic'].encode()
        payload += len(packet['Payload']['Will Payload']).to_bytes(2, 'big')
        payload += packet['Payload']['Will Payload']
        # Username
    if User_Name_Flag:
        payload += len(packet['Payload']['User name']).to_bytes(2,'big') + packet['Payload']['User name'].encode()
        # Password
    if Password_Flag:
        payload += len(packet['Payload']['Password']).to_bytes(2,'big') + packet['Payload']['Password'].encode()
    # Подсчет длины и сборка байтов
    body = variable_header + payload

    rem_length = bytearray()
    body_len = len(body)
    while True:
        d = body_len % 128
        body_len //= 128
        if body_len > 0:
            d |= 0x80
        rem_length.append(d)
        if body_len == 0:
            break
    fixed_header += rem_length
    packet_bytes = fixed_header + body
    return bytes(packet_bytes)
    # Работа с типом connack


def deparse_CONNACK(packet, protocol_version):
    # Fixed Header
    fixed_header = bytearray()
    fixed_header.append(0x20)  # Тип пакета + flags (0)
    # remaining length в конце
    # Variable header
    variable_header = bytearray()
    # Connect Acknowledge Flags// Bit 0 is the Session Present Flag.// Bits 7-1 are reserved and MUST be set to 0
    variable_header.append(packet["Variable header"]['Connect Acknowledge Flags'])
    # Connect Reason Code
    variable_header.append(packet["Variable header"]['Connect Reason Code'])
    # Properties UserProp номерки добавить
    connack_properties = {
        "Session Expiry Interval": lambda v: b'\x11' + v.to_bytes(4, 'big'),
        "Receive Maximum": lambda v: b'\x21' + v.to_bytes(2, 'big'),
        "Maximum Packet Size": lambda v: b'\x27' + v.to_bytes(4, 'big'),
        "Topic Alias Maximum": lambda v: b'\x22' + v.to_bytes(2, 'big'),
        "Maximum QoS": lambda v: b'\x24' + bytes([v]),
        "Retain Available": lambda v: b'\x25' + bytes([v]),
        "Wildcard Subscription Available": lambda v: b'\x28' + bytes([v]),
        "Subscription Identifier Available": lambda v: b'\x29' + bytes([v]),
        "Shared Subscription Available": lambda v: b'\x2A' + bytes([v]),
        "Server Keep Alive": lambda v: b'\x13' + v.to_bytes(2, 'big'),
        "Response Information": lambda v:
        (
            b'\x1A' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
        "Server Reference": lambda v:
        (
            b'\x1C' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
        "Reason String": lambda v:
        (
            b'\x1F' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
        "Assigned Client Identifier": lambda v:
        (
            b'\x12' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
        "Authentication Method": lambda v:
        (
            b'\x15' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
        "Authentication Data": lambda v:
        (
            b'\x16' + len(v).to_bytes(2, 'big') + v
        ),
    }
    properties = bytearray()
    for name, value in packet["Variable header"]["Properties"].items():
        if name == "User Property":
            userprop = bytearray()
            for key, value in value:
                userprop.append(0x26)
                userprop += len(key.encode()).to_bytes(2,
                                                       'big') + key.encode()
                userprop += len(value.encode()).to_bytes(2,
                                                         'big') + value.encode()
            properties += userprop
        elif name in connack_properties:
            properties += connack_properties[name](value)
        else:
            raise ValueError(f"Deparse CONNACK property: {name} error")
    # Variable byte integer
    vbi = bytearray()
    prop_len = len(properties)
    while True:
        d = prop_len % 128
        prop_len //= 128
        if prop_len > 0:
            d |= 0x80
        vbi.append(d)
        if prop_len == 0:
            break
    if protocol_version == 5:
        variable_header += bytes(vbi) + properties
    # Подсчет длины и сборка байтов
    body = variable_header
    rem_length = bytearray()
    body_len = len(body)
    while True:
        d = body_len % 128
        body_len //= 128
        if body_len > 0:
            d |= 0x80
        rem_length.append(d)
        if body_len == 0:
            break
    fixed_header += rem_length
    packet_bytes = fixed_header + body
    return bytes(packet_bytes)
    # Работа с типом publish


def deparse_PUBLISH(packet, protocol_version):
    # Fixed Header
    fixed_header = bytearray()
    dup = packet['Flags']["DUP flag"]
    qos = packet['Flags']["QoS level"]
    retain = packet['Flags']["RETAIN"]
    first_byte = (0x30 | (dup << 3) | (qos << 1) | retain)
    fixed_header.append(first_byte)  # Тип пакета + flags
    # remaining length в конце
    # Variable header
    variable_header = bytearray()
    # Topic name
    topic_name = packet["Variable header"]['Topic Name'].encode()
    variable_header += len(topic_name).to_bytes(2, 'big') + topic_name
    # Packet Identifier
    if qos > 0:
        variable_header += packet["Variable header"]['Packet Identifier'].to_bytes(2, 'big')
        # Properties UserProp номерки добавить
    publish_properties = {
        "Topic Alias": lambda v: b'\x23' + v.to_bytes(2, 'big'),
        "Payload Format Indicator": lambda v: b'\x01' + bytes([v]),
        "Message Expiry Interval": lambda v: b'\x02' + v.to_bytes(4, 'big'),
        "Content Type": lambda v:
        (
            b'\x03' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
        "Response Topic": lambda v:
        (
            b'\x08' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
        "Correlation Data": lambda v:
        (
            b'\x09' + len(v).to_bytes(2, 'big') + v
        ),
    }
    properties = bytearray()
    for name, value in packet["Variable header"]["Properties"].items():
        if name == "User Property":
            userprop = bytearray()
            for key, value in value:
                userprop.append(0x26)
                userprop += len(key.encode()).to_bytes(2,
                                                       'big') + key.encode()
                userprop += len(value.encode()).to_bytes(2,
                                                         'big') + value.encode()
            properties += userprop
        elif name == "Subscription Identifier":
            vbi = bytearray()
            v = value
            while True:
                d = v % 128
                v //= 128
                if v > 0:
                    d |= 0x80
                vbi.append(d)
                if v == 0:
                    break
            properties += b'\x0B' + vbi
        elif name in publish_properties:
            properties += publish_properties[name](value)
        else:
            raise ValueError(f"Deparse PUBLISH property: {name} error")
    # Variable byte integer
    vbi = bytearray()
    prop_len = len(properties)
    while True:
        d = prop_len % 128
        prop_len //= 128
        if prop_len > 0:
            d |= 0x80
        vbi.append(d)
        if prop_len == 0:
            break
    if protocol_version == 5:
        variable_header += bytes(vbi) + properties
    # Payload
    payload = packet['Payload']
    payload = payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode() #fix
    # Подсчет длины и сборка байтов
    body = variable_header + payload
    rem_length = bytearray()
    body_len = len(body)
    while True:
        d = body_len % 128
        body_len //= 128
        if body_len > 0:
            d |= 0x80
        rem_length.append(d)
        if body_len == 0:
            break
    fixed_header += rem_length
    packet_bytes = fixed_header + body
    return bytes(packet_bytes)
    # Работа с типом puback


def deparse_PUBACK(packet):
    # Fixed Header
    fixed_header = bytearray()
    fixed_header.append(0x40)  # Тип пакета + flags
    # remaining length в конце
    # Variable header
    variable_header = bytearray()
    # Topic name
    # Packet Identifier
    variable_header += packet["Variable header"]['Packet Identifier'].to_bytes(2, 'big')
    # Случай если reason code 0 и нет properties
    reason_code = packet["Variable header"].get('PUBACK Reason Code', 0)
    if reason_code == 0 and not packet["Variable header"].get("Properties"):
        body = variable_header
        fixed_header.append(0x02)
        packet_bytes = fixed_header + body
        return bytes(packet_bytes)

    # PUBACK Reason Code
    variable_header.append(reason_code)
    # Properties UserProp номерки добавить
    puback_properties = {
        "Reason String": lambda v:
        (
            b'\x1F' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
    }
    # Случай если rem_len<4
    if not packet["Variable header"].get("Properties"):
        body = variable_header
        fixed_header.append(0x03)
        packet_bytes = fixed_header + body
        return bytes(packet_bytes)
    properties = bytearray()
    for name, value in packet["Variable header"]["Properties"].items():
        if name == "User Property":
            userprop = bytearray()
            for key, value in value:
                userprop.append(0x26)
                userprop += len(key.encode()).to_bytes(2,
                                                       'big') + key.encode()
                userprop += len(value.encode()).to_bytes(2,
                                                         'big') + value.encode()
            properties += userprop
        elif name in puback_properties:
            properties += puback_properties[name](value)
        else:
            raise ValueError(f"Deparse PUBACK property: {name} error")
    # Variable byte integer
    vbi = bytearray()
    prop_len = len(properties)
    while True:
        d = prop_len % 128
        prop_len //= 128
        if prop_len > 0:
            d |= 0x80
        vbi.append(d)
        if prop_len == 0:
            break
    variable_header += bytes(vbi) + properties
    # Подсчет длины и сборка байтов
    body = variable_header
    rem_length = bytearray()
    body_len = len(body)
    while True:
        d = body_len % 128
        body_len //= 128
        if body_len > 0:
            d |= 0x80
        rem_length.append(d)
        if body_len == 0:
            break
    fixed_header += rem_length
    packet_bytes = fixed_header + body
    return bytes(packet_bytes)
    # Работа с типом pubrec


def deparse_PUBREC(packet):
    # Fixed Header
    fixed_header = bytearray()
    fixed_header.append(0x50)  # Тип пакета + flags
    # remaining length в конце
    # Variable header
    variable_header = bytearray()
    # Topic name
    # Packet Identifier
    variable_header += packet["Variable header"]['Packet Identifier'].to_bytes(
        2, 'big')
    # Случай если reason code 0 и нет properties
    reason_code = packet["Variable header"].get('PUBREC Reason Code', 0)
    if reason_code == 0 and not packet["Variable header"].get("Properties"):
        body = variable_header
        fixed_header.append(0x02)
        packet_bytes = fixed_header + body
        return bytes(packet_bytes)

    # PUBREC Reason Code
    variable_header.append(reason_code)
    # Properties UserProp номерки добавить
    pubrec_properties = {
        "Reason String": lambda v:
        (
            b'\x1F' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
    }
    # Случай если rem_len<4
    if not packet["Variable header"].get("Properties"):
        body = variable_header
        fixed_header.append(0x03)
        packet_bytes = fixed_header + body
        return bytes(packet_bytes)
    properties = bytearray()
    for name, value in packet["Variable header"]["Properties"].items():
        if name == "User Property":
            userprop = bytearray()
            for key, value in value:
                userprop.append(0x26)
                userprop += len(key.encode()).to_bytes(2,
                                                       'big') + key.encode()
                userprop += len(value.encode()).to_bytes(2,
                                                         'big') + value.encode()
            properties += userprop
        elif name in pubrec_properties:
            properties += pubrec_properties[name](value)
        else:
            raise ValueError(f"Deparse PUBREC property: {name} error")
    # Variable byte integer
    vbi = bytearray()
    prop_len = len(properties)
    while True:
        d = prop_len % 128
        prop_len //= 128
        if prop_len > 0:
            d |= 0x80
        vbi.append(d)
        if prop_len == 0:
            break
    variable_header += bytes(vbi) + properties
    # Подсчет длины и сборка байтов
    body = variable_header
    rem_length = bytearray()
    body_len = len(body)
    while True:
        d = body_len % 128
        body_len //= 128
        if body_len > 0:
            d |= 0x80
        rem_length.append(d)
        if body_len == 0:
            break
    fixed_header += rem_length
    packet_bytes = fixed_header + body
    return bytes(packet_bytes)
    # Работа с типом pubrel


def deparse_PUBREL(packet):
    # Fixed Header
    fixed_header = bytearray()
    fixed_header.append(0x62)  # Тип пакета + flags
    # remaining length в конце
    # Variable header
    variable_header = bytearray()
    # Topic name
    # Packet Identifier
    variable_header += packet["Variable header"]['Packet Identifier'].to_bytes(
        2, 'big')
    # Случай если reason code 0 и нет properties
    reason_code = packet["Variable header"].get('PUBREL Reason Code', 0)
    if reason_code == 0 and not packet["Variable header"].get("Properties"):
        body = variable_header
        fixed_header.append(0x02)
        packet_bytes = fixed_header + body
        return bytes(packet_bytes)
    # PUBREL Reason Code
    variable_header.append(reason_code)
    # Properties UserProp номерки добавить
    pubrel_properties = {
        "Reason String": lambda v:
        (
            b'\x1F' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
    }
    # Случай если rem_len<4
    if not packet["Variable header"].get("Properties"):
        body = variable_header
        fixed_header.append(0x03)
        packet_bytes = fixed_header + body
        return bytes(packet_bytes)
    properties = bytearray()
    for name, value in packet["Variable header"]["Properties"].items():
        if name == "User Property":
            userprop = bytearray()
            for key, value in value:
                userprop.append(0x26)
                userprop += len(key.encode()).to_bytes(2,
                                                       'big') + key.encode()
                userprop += len(value.encode()).to_bytes(2,
                                                         'big') + value.encode()
            properties += userprop
        elif name in pubrel_properties:
            properties += pubrel_properties[name](value)
        else:
            raise ValueError(f"Deparse PUBREL property: {name} error")
    # Variable byte integer
    vbi = bytearray()
    prop_len = len(properties)
    while True:
        d = prop_len % 128
        prop_len //= 128
        if prop_len > 0:
            d |= 0x80
        vbi.append(d)
        if prop_len == 0:
            break
    variable_header += bytes(vbi) + properties
    # Подсчет длины и сборка байтов
    body = variable_header
    rem_length = bytearray()
    body_len = len(body)
    while True:
        d = body_len % 128
        body_len //= 128
        if body_len > 0:
            d |= 0x80
        rem_length.append(d)
        if body_len == 0:
            break
    fixed_header += rem_length
    packet_bytes = fixed_header + body
    return bytes(packet_bytes)
    # Работа с типом pubcomp


def deparse_PUBCOMP(packet):
    # Fixed Header
    fixed_header = bytearray()
    fixed_header.append(0x70)  # Тип пакета + flags
    # remaining length в конце
    # Variable header
    variable_header = bytearray()
    # Topic name
    # Packet Identifier
    variable_header += packet["Variable header"]['Packet Identifier'].to_bytes(
        2, 'big')
    # Случай если reason code 0 и нет properties
    reason_code = packet["Variable header"].get('PUBCOMP Reason Code', 0)
    if reason_code == 0 and not packet["Variable header"].get("Properties"):
        body = variable_header
        fixed_header.append(0x02)
        packet_bytes = fixed_header + body
        return bytes(packet_bytes)
    # PUBREL Reason Code
    variable_header.append(reason_code)
    # Properties UserProp номерки добавить
    pubcomp_properties = {
        "Reason String": lambda v:
        (
            b'\x1F' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
    }
    # Случай если rem_len<4
    if not packet["Variable header"].get("Properties"):
        body = variable_header
        fixed_header.append(0x03)
        packet_bytes = fixed_header + body
        return bytes(packet_bytes)
    properties = bytearray()
    for name, value in packet["Variable header"]["Properties"].items():
        if name == "User Property":
            userprop = bytearray()
            for key, value in value:
                userprop.append(0x26)
                userprop += len(key.encode()).to_bytes(2,
                                                       'big') + key.encode()
                userprop += len(value.encode()).to_bytes(2,
                                                         'big') + value.encode()
            properties += userprop
        elif name in pubcomp_properties:
            properties += pubcomp_properties[name](value)
        else:
            raise ValueError(f"Deparse PUBCOMP property: {name} error")
    # Variable byte integer
    vbi = bytearray()
    prop_len = len(properties)
    while True:
        d = prop_len % 128
        prop_len //= 128
        if prop_len > 0:
            d |= 0x80
        vbi.append(d)
        if prop_len == 0:
            break
    variable_header += bytes(vbi) + properties
    # Подсчет длины и сборка байтов
    body = variable_header
    rem_length = bytearray()
    body_len = len(body)
    while True:
        d = body_len % 128
        body_len //= 128
        if body_len > 0:
            d |= 0x80
        rem_length.append(d)
        if body_len == 0:
            break
    fixed_header += rem_length
    packet_bytes = fixed_header + body
    return bytes(packet_bytes)
    # Работа с типом subscribe


def deparse_SUBSCRIBE(packet, protocol_version):
    # Fixed Header
    fixed_header = bytearray()
    fixed_header.append(0x82)  # Тип пакета + flags
    # remaining length в конце
    # Variable header
    variable_header = bytearray()
    # Packet Identifier
    variable_header += packet["Variable header"]['Packet Identifier'].to_bytes(
        2, 'big')
    # Properties UserProp номерки добавить
    properties = bytearray()
    for name, value in packet["Variable header"]["Properties"].items():
        if name == "User Property":
            userprop = bytearray()
            for key, value in value:
                userprop.append(0x26)
                userprop += len(key.encode()).to_bytes(2,
                                                       'big') + key.encode()
                userprop += len(value.encode()).to_bytes(2,
                                                         'big') + value.encode()
            properties += userprop
        elif name == "Subscription Identifier":
            vbi = bytearray()
            v = value
            while True:
                d = v % 128
                v //= 128
                if v > 0:
                    d |= 0x80
                vbi.append(d)
                if v == 0:
                    break
            properties += b'\x0B' + vbi
        else:
            raise ValueError(f"Deparse SUBSCRIBE property: {name} error")
    # Variable byte integer
    vbi = bytearray()
    prop_len = len(properties)
    while True:
        d = prop_len % 128
        prop_len //= 128
        if prop_len > 0:
            d |= 0x80
        vbi.append(d)
        if prop_len == 0:
            break
    if protocol_version == 5:
        variable_header += bytes(vbi) + properties
    # Payload
    payload = bytearray()
    for name, value in packet["Payload"]["The Topic Filters"].items():
        payload += len(name.encode()).to_bytes(2, 'big') + name.encode()
        payload += value.to_bytes(1, 'big')
    # Подсчет длины и сборка байтов
    body = variable_header + payload
    rem_length = bytearray()
    body_len = len(body)
    while True:
        d = body_len % 128
        body_len //= 128
        if body_len > 0:
            d |= 0x80
        rem_length.append(d)
        if body_len == 0:
            break
    fixed_header += rem_length
    packet_bytes = fixed_header + body
    return bytes(packet_bytes)
    # Работа с типом suback


def deparse_SUBACK(packet, protocol_version ):
    # Fixed Header
    fixed_header = bytearray()
    fixed_header.append(0x90)  # Тип пакета + flags
    # remaining length в конце
    # Variable header
    variable_header = bytearray()
    # Packet Identifier
    variable_header += packet["Variable header"]['Packet Identifier'].to_bytes(
        2, 'big')
    # Properties UserProp номерки добавить
    suback_properties = {
        "Reason String": lambda v:
        (
            b'\x1F' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
    }
    properties = bytearray()
    for name, value in packet["Variable header"]["Properties"].items():
        if name == "User Property":
            userprop = bytearray()
            for key, value in value:
                userprop.append(0x26)
                userprop += len(key.encode()).to_bytes(2,
                                                       'big') + key.encode()
                userprop += len(value.encode()).to_bytes(2,
                                                         'big') + value.encode()
            properties += userprop
        elif name in suback_properties:
            properties += suback_properties[name](value)
        else:
            raise ValueError(f"Deparse SUBACK property: {name} error")
    # Variable byte integer
    vbi = bytearray()
    prop_len = len(properties)
    while True:
        d = prop_len % 128
        prop_len //= 128
        if prop_len > 0:
            d |= 0x80
        vbi.append(d)
        if prop_len == 0:
            break
    if protocol_version == 5:
        variable_header += bytes(vbi) + properties
    # Payload
    payload = bytearray()
    for value in packet["Payload"]["Subscribe Reason Codes"]:
        payload += value.to_bytes(1, 'big')
    # Подсчет длины и сборка байтов
    body = variable_header + payload
    rem_length = bytearray()
    body_len = len(body)
    while True:
        d = body_len % 128
        body_len //= 128
        if body_len > 0:
            d |= 0x80
        rem_length.append(d)
        if body_len == 0:
            break
    fixed_header += rem_length
    packet_bytes = fixed_header + body
    return bytes(packet_bytes)
    # Работа с типом unsubscribe


def deparse_UNSUBSCRIBE(packet, protocol_version ):
    # Fixed Header
    fixed_header = bytearray()
    fixed_header.append(0xA2)  # Тип пакета + flags
    # remaining length в конце
    # Variable header
    variable_header = bytearray()
    # Packet Identifier
    variable_header += packet["Variable header"]['Packet Identifier'].to_bytes(
        2, 'big')
    # Properties UserProp номерки добавить
    unsubscribe_properties = {
        "Reason String": lambda v:
        (
            b'\x1F' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
    }
    properties = bytearray()
    for name, value in packet["Variable header"]["Properties"].items():
        if name == "User Property":
            userprop = bytearray()
            for key, value in value:
                userprop.append(0x26)
                userprop += len(key.encode()).to_bytes(2,
                                                       'big') + key.encode()
                userprop += len(value.encode()).to_bytes(2,
                                                         'big') + value.encode()
            properties += userprop
        elif name in unsubscribe_properties:
            properties += unsubscribe_properties[name](value)
        else:
            raise ValueError(f"Deparse UNSUBSCRIBE property: {name} error")
    # Variable byte integer
    vbi = bytearray()
    prop_len = len(properties)
    while True:
        d = prop_len % 128
        prop_len //= 128
        if prop_len > 0:
            d |= 0x80
        vbi.append(d)
        if prop_len == 0:
            break
    if protocol_version == 5:
        variable_header += bytes(vbi) + properties
    # Payload
    payload = bytearray()
    for name in packet["Payload"]["The Topic Filters"]:
        payload += len(name.encode()).to_bytes(2, 'big') + name.encode()
    # Подсчет длины и сборка байтов
    body = variable_header + payload
    rem_length = bytearray()
    body_len = len(body)
    while True:
        d = body_len % 128
        body_len //= 128
        if body_len > 0:
            d |= 0x80
        rem_length.append(d)
        if body_len == 0:
            break
    fixed_header += rem_length
    packet_bytes = fixed_header + body
    return bytes(packet_bytes)
    # Работа с типом suback
    # Работа с типом unsuback


def deparse_UNSUBACK(packet,protocol_version  ):
    # Fixed Header
    fixed_header = bytearray()
    fixed_header.append(0xB0)  # Тип пакета + flags
    # remaining length в конце
    # Variable header
    variable_header = bytearray()
    # Packet Identifier
    variable_header += packet["Variable header"]['Packet Identifier'].to_bytes(
        2, 'big')
    # Properties UserProp номерки добавить
    unsuback_properties = {
        "Reason String": lambda v:
        (
            b'\x1F' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
    }
    properties = bytearray()
    for name, value in packet["Variable header"]["Properties"].items():
        if name == "User Property":
            userprop = bytearray()
            for key, value in value:
                userprop.append(0x26)
                userprop += len(key.encode()).to_bytes(2,
                                                       'big') + key.encode()
                userprop += len(value.encode()).to_bytes(2,
                                                         'big') + value.encode()
            properties += userprop
        elif name in unsuback_properties:
            properties += unsuback_properties[name](value)
        else:
            raise ValueError(f"Deparse UNSUBACK property: {name} error")
    # Variable byte integer
    vbi = bytearray()
    prop_len = len(properties)
    while True:
        d = prop_len % 128
        prop_len //= 128
        if prop_len > 0:
            d |= 0x80
        vbi.append(d)
        if prop_len == 0:
            break
    if protocol_version == 5:
        variable_header += bytes(vbi) + properties
    # Payload
    payload = bytearray()
    for value in packet["Payload"]["Unsubscribe Reason Codes"]:
        payload += value.to_bytes(1, 'big')
    # Подсчет длины и сборка байтов
    body = variable_header + payload
    rem_length = bytearray()
    body_len = len(body)
    while True:
        d = body_len % 128
        body_len //= 128
        if body_len > 0:
            d |= 0x80
        rem_length.append(d)
        if body_len == 0:
            break
    fixed_header += rem_length
    packet_bytes = fixed_header + body
    return bytes(packet_bytes)
    # Работа с типом pingreq


def deparse_PINGREQ():
    packet = bytearray()
    packet.append(0xC0)
    packet.append(0x0)
    return bytes(packet)
    # Работа с типом pingresp


def deparse_PINGRESP():
    packet = bytearray()
    packet.append(0xD0)
    packet.append(0x0)
    return bytes(packet)
    # Работа с типом disconnect


def deparse_DISCONNECT(packet ):
    # Fixed Header
    fixed_header = bytearray()
    fixed_header.append(0xE0)  # Тип пакета + flags
    # remaining length в конце
    # Variable header
    variable_header = bytearray()
    # Случай если reason code 0 и нет properties
    reason_code = packet["Variable header"].get(
        'DISCONNECT Reason Code', 0)
    if reason_code == 0 and not packet["Variable header"].get("Properties"):
        body = variable_header
        fixed_header.append(0x00)
        packet_bytes = fixed_header + body
        return bytes(packet_bytes)
    # DISCONNECT Reason Code
    variable_header.append(reason_code)
    # Properties UserProp номерки добавить
    disconnect_properties = {
        "Session Expiry Interval": lambda v: b'\x11' + v.to_bytes(4, 'big'),
        "Server Reference": lambda v:
        (
            b'\x1C' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
        "Reason String": lambda v:
        (
            b'\x1F' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        )
    }
    # Случай если rem_len<2
    if not packet["Variable header"].get("Properties"):
        body = variable_header
        fixed_header.append(0x01)
        packet_bytes = fixed_header + body
        return bytes(packet_bytes)
    properties = bytearray()
    for name, value in packet["Variable header"]["Properties"].items():
        if name == "User Property":
            userprop = bytearray()
            for key, value in value:
                userprop.append(0x26)
                userprop += len(key.encode()).to_bytes(2,
                                                       'big') + key.encode()
                userprop += len(value.encode()).to_bytes(2,
                                                         'big') + value.encode()
            properties += userprop
        elif name in disconnect_properties:
            properties += disconnect_properties[name](value)
        else:
            raise ValueError(f"Deparse DISCONNECT property: {name} error")
    # Variable byte integer
    vbi = bytearray()
    prop_len = len(properties)
    while True:
        d = prop_len % 128
        prop_len //= 128
        if prop_len > 0:
            d |= 0x80
        vbi.append(d)
        if prop_len == 0:
            break
    variable_header += bytes(vbi) + properties
    # Подсчет длины и сборка байтов
    body = variable_header
    rem_length = bytearray()
    body_len = len(body)
    while True:
        d = body_len % 128
        body_len //= 128
        if body_len > 0:
            d |= 0x80
        rem_length.append(d)
        if body_len == 0:
            break
    fixed_header += rem_length
    packet_bytes = fixed_header + body
    return bytes(packet_bytes)
    # Работа с типом auth


def deparse_AUTH(packet):
    # Fixed Header
    fixed_header = bytearray()
    fixed_header.append(0xF0)  # Тип пакета + flags
    # remaining length в конце
    # Variable header
    variable_header = bytearray()
    # Случай если reason code 0 и нет properties
    reason_code = packet["Variable header"].get(
        'Authenticate Reason Code', 0)
    if reason_code == 0 and not packet["Variable header"].get("Properties"):
        body = variable_header
        fixed_header.append(0x00)
        packet_bytes = fixed_header + body
        return bytes(packet_bytes)
    # auth Reason Code
    variable_header.append(reason_code)
    # Properties UserProp номерки добавить
    auth_properties = {
        "Authentication Method": lambda v:
        (
            b'\x15' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        ),
        "Authentication Data": lambda v:
        (
            b'\x16' + len(v).to_bytes(2, 'big') + v
        ),
        "Reason String": lambda v:
        (
            b'\x1F' + len(v.encode()).to_bytes(2, 'big') + v.encode()
        )
    }
    # Случай если rem_len<2
    if not packet["Variable header"].get("Properties"):
        body = variable_header
        fixed_header.append(0x01)
        packet_bytes = fixed_header + body
        return bytes(packet_bytes)
    properties = bytearray()
    for name, value in packet["Variable header"]["Properties"].items():
        if name == "User Property":
            userprop = bytearray()
            for key, value in value:
                userprop.append(0x26)
                userprop += len(key.encode()).to_bytes(2,
                                                       'big') + key.encode()
                userprop += len(value.encode()).to_bytes(2,
                                                         'big') + value.encode()
            properties += userprop
        elif name in auth_properties:
            properties += auth_properties[name](value)
        else:
            raise ValueError(f"Deparse AUTH property: {name} error")
    # Variable byte integer
    vbi = bytearray()
    prop_len = len(properties)
    while True:
        d = prop_len % 128
        prop_len //= 128
        if prop_len > 0:
            d |= 0x80
        vbi.append(d)
        if prop_len == 0:
            break
    variable_header += bytes(vbi) + properties
    # Подсчет длины и сборка байтов
    body = variable_header
    rem_length = bytearray()
    body_len = len(body)
    while True:
        d = body_len % 128
        body_len //= 128
        if body_len > 0:
            d |= 0x80
        rem_length.append(d)
        if body_len == 0:
            break
    fixed_header += rem_length
    packet_bytes = fixed_header + body
    return bytes(packet_bytes)
