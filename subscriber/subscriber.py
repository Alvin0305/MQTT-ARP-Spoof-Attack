import json
from datetime import datetime

import paho.mqtt.client as mqtt

from common.config import BROKER_IP, PORT, TOPIC


def on_connect(client, userdata, flags, rc):
    print(f"[Subscriber] connected, rc={rc}")
    client.subscribe(TOPIC, qos=1)


def on_message(client, userdata, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    try:
        data = json.loads(msg.payload.decode())
        print(f"[{ts}] {msg.topic} -> {data}")
    except Exception:
        print(f"[{ts}] raw payload: {msg.payload}")


def main():
    client = mqtt.Client()

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER_IP, PORT, 60)

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print("subscriber stopping")
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
