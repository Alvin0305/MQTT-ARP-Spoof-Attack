import json
import random
import time

import paho.mqtt.client as mqtt

from common.config import BROKER_IP, PORT, TOPIC


def main():
    client = mqtt.Client()

    client.connect(BROKER_IP, PORT, 60)
    client.loop_start()

    try:
        while True:
            value = round(random.uniform(20.0, 30.0), 2)
            payload = json.dumps({"sensor": "temp-01", "value": value, "unit": "C"})
            client.publish(TOPIC, payload, qos=1)
            print(f"[Publisher] sent: {payload}")
            time.sleep(5)
    except KeyboardInterrupt:
        print("publisher stopping")
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
