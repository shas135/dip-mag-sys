# https://www.rfc-editor.org/rfc/rfc7252

def parse_CoAP(data: bytes):
    if not data:
        raise ValueError("Empty data")
    #Header 32 bits
    version = data[0] >> 6
    if version != 1: return "Malformed packet CoAP (version)"
    type = data[0] >> 4 & 0x3
    token_length = data[0] & 0xF
    code = data[1]
    message_id = int.from_bytes(data[2:4], 'big')
    i = 4
    #Optional
        #token
    token = data[i:i+token_length]
    i += token_length
        #options
    options = [] #section 3.1
    current_option = 0
    payload = None
    while i < len(data):
        if data[i] == 0xFF: #0xFF - маркер начала payload
            i += 1
            payload = data[i:] 
            break
        else:
            delta = (data[i] >> 4 )
            length = data[i] & 0x0F
            i += 1
            if delta == 13:
                delta = data[i] + 13
                i += 1
            elif delta == 14:
                delta = int.from_bytes(data[i:i+2], 'big') + 269
                i += 2
            if length == 13:
                length = data[i] + 13
                i += 1
            elif length == 14:
                length = int.from_bytes(data[i:i+2], 'big') + 269
                i += 2

            current_option += delta
            value = data[i:i+length]
            i += length

            options.append((current_option, value))

    return {
        'Version': version,
        'Type': type,
        'Code': code,
        'Message ID': message_id,
        'Token': token,
        'Options': options,
        'Payload': payload
    }

def deparse_CoAP(packet):
    data = bytearray()
    fb = (packet['Version'] << 6) | (packet['Type'] << 4) | len(packet['Token'])
    data.append(fb)
    data.append(packet['Code'])
    data += packet['Message ID'].to_bytes(2, 'big')
    data += packet['Token']
    current_option = 0
    for number, value in sorted(packet['Options']):
        delta = number - current_option
        current_option = number
        length = len(value)
        #delta
        if delta < 13:
            delta_s = delta
            delta_f = b""
        elif delta < 269:
            delta_s = 13
            delta_f = bytes([delta - 13])
        else:
            delta_s = 14
            delta_f = (delta - 269).to_bytes(2, 'big')
        #length
        if length < 13:
            length_s = length
            length_f = b""
        elif length < 269:
            length_s = 13
            length_f = bytes([length - 13])
        else:
            length_s = 14
            length_f = (length - 269).to_bytes(2, 'big')
        data.append((delta_s << 4) | length_s)
        data += delta_f
        data += length_f
        data += value

    if packet['Payload']:
        data.append(0xFF)
        data += packet['Payload']

    return bytes(data)
