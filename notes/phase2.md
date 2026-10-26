# Authentication Bypassing

## Setting up authentication, in broker side
```bash
sudo mosquitto_passwd -c /etc/mosquitto/passwd publisher
sudo mosquitto_passwd /etc/mosquitto/passwd subscriber
```
- Edit the `/etc/mosquitto/mosquitto.conf` file
```conf
allow_anonymous false
password_file /etc/mosquitto/passwd
```
- This will enable password authentication in broker

## Bypassing Authentication
- Authentication happens only in the CONNECT packet. Once the session is created, further packets are not checked for authentication
- And even if authentication is checked, since TLS is not enabled, the username and password in the CONNECT packet will be clearly visible (plain text) to the attacker
- So, the attacker will basically forward the CONNECT packet without touching it. And tamper the PUBLISH packet's payload
