# ARP Spoofing

- In this phase, we will run `arp_spoof.py` file which will send unsolicited ARP responses which will poison the ARP Cache of publisher, subscriber and attacker. So whenever the publisher publishes, the packet instead of going to the broker directly, it goes to the attacker. 
- Once the attacker receives the packet. It will log it, tamper it and forward it to the broker.
- We will tamper only PUBLISH packets. CONNECT packet should not be tampered
- For forwarding, we update the iptables
```bash
sudo iptables -t nat -A PREROUTING -s 192.168.57.20 -p tcp --dport 1883 -j REDIRECT --to-port 1884
sudo iptables -t nat -A PREROUTING -s 192.168.57.30 -p tcp --dport 1883 -j REDIRECT --to-port 1884
```
- What this command will do is:
  - When a TCP packet from publisher's IP comes to 1883 port, it will take the packet and redirect it to port 1884 of attacker
  - Similarly when a TCP packet from subscriber's IP comes to 1883 port, it will take the packet and redirect it to port 1884 of attacker
- From the port 1884 of the attacker, mqtt_proxy will forward it to corresponding endpoint
