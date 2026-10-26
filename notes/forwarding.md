```bash
sudo iptables -t nat -A PREROUTING -s 192.168.57.20 -p tcp --dport 1883 -j REDIRECT --to-port 1884
sudo iptables -t nat -A PREROUTING -s 192.168.57.30 -p tcp --dport 1883 -j REDIRECT --to-port 1884
```

# Check
```bash
sudo iptables -t nat -L PREROUTING -n -v
```

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```
