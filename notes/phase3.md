# ACL Bypassing

## Setting up ACL in Broker
- Save the following content in the file `/etc/mosquitto/mosquitto.acl`
```conf
user publisher
topic write /temperature

user subscriber
topic read /temperature
```
- Add the following line to `/etc/mosquitto/mosquitto.conf` file
```conf
acl_file /etc/mosquitto/mosquitto.acl
```

## Bypassing ACL (Nothing to do)
- ACL will just check 
  - who can (publisher/subscriber)
  - do what (write/read)
  - on which topic
- It doesn't prevent the attacker from tampering the packet payload. 
- It will only check whether no unauthorized device publish and no unauthorized device subscribes to any topic
- So if we try to change the topic name, then it will fail
