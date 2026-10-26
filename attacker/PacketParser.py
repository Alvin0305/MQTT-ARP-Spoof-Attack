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
