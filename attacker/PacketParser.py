class PacketParser:
    @staticmethod
    def try_parse(buf: bytes):
        """Return (packet_bytes, rest) if a complete MQTT packet is in buf, else (None, buf)."""
        if len(buf) < 2:
            return None, buf
        multiplier = 1
        remaining = 0
        i = 1
        while True:
            if i >= len(buf):
                return None, buf  # need more bytes for the length field
            byte = buf[i]
            remaining += (byte & 0x7F) * multiplier
            i += 1
            if not (byte & 0x80):
                break
            multiplier *= 128
            if multiplier > 128**3:
                raise ValueError("Malformed MQTT remaining length")
        total = i + remaining
        if len(buf) < total:
            return None, buf
        return buf[:total], buf[total:]

    @staticmethod
    def parse_connect(packet: bytes):
        """If packet is an MQTT CONNECT, return a dict with its fields. Else return None."""
        if len(packet) < 2:
            return None
        first = packet[0]
        if (first >> 4) != 1:  # 1 = CONNECT
            return None

        # Skip the remaining-length field to find the variable header
        i = 1
        while True:
            if i >= len(packet):
                return None
            byte = packet[i]
            i += 1
            if not (byte & 0x80):
                break

        body = packet[i:]
        if len(body) < 10:
            return None

        # Protocol name
        proto_len = int.from_bytes(body[0:2], "big")
        if len(body) < 2 + proto_len + 4:
            return None
        proto_name = body[2 : 2 + proto_len].decode(errors="replace")
        pos = 2 + proto_len

        proto_level = body[pos]
        pos += 1
        connect_flags = body[pos]
        pos += 1
        keep_alive = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2

        username_flag = bool(connect_flags & 0x80)
        password_flag = bool(connect_flags & 0x40)
        will_flag = bool(connect_flags & 0x04)
        will_qos = (connect_flags >> 3) & 0x03
        clean_session = bool(connect_flags & 0x02)

        # MQTT 5.0 has a properties field here
        if proto_level == 5:
            if pos >= len(body):
                return None
            props_len = body[pos]
            pos += 1 + props_len

        def read_utf8(data, p):
            if p + 2 > len(data):
                return None, p
            n = int.from_bytes(data[p : p + 2], "big")
            p += 2
            if p + n > len(data):
                return None, p
            return data[p : p + n].decode(errors="replace"), p + n

        def read_binary(data, p):
            if p + 2 > len(data):
                return None, p
            n = int.from_bytes(data[p : p + 2], "big")
            p += 2
            if p + n > len(data):
                return None, p
            return data[p : p + n], p + n

        client_id, pos = read_utf8(body, pos)
        will_topic = will_message = None
        if will_flag:
            will_topic, pos = read_utf8(body, pos)
            will_message, pos = read_binary(body, pos)

        username = password = None
        if username_flag:
            username, pos = read_utf8(body, pos)
        if password_flag:
            pw_bytes, pos = read_binary(body, pos)
            password = pw_bytes.decode(errors="replace")

        return {
            "protocol_name": proto_name,
            "protocol_level": proto_level,
            "keep_alive": keep_alive,
            "clean_session": clean_session,
            "client_id": client_id,
            "will_flag": will_flag,
            "will_qos": will_qos,
            "will_topic": will_topic,
            "will_message": will_message,
            "username": username,
            "password": password,
        }
