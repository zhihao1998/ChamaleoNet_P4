# Dataplane Code for transprent SDN proxy for cyber security

## commands

```bash
bfrt_python /home/zhihaow/codes/transparent_sdn_proxy_p4/bfrt/bfrt_setup.py true

```


Notification mode
Every entry has a individual idle timer. Once the entry has been idling (no packet matched) for longer than the specified idle time, control plane receives a notification callback, which is typically used to delete the corresponding entry.
More flexible, but got concurrency problem (local bfrt controller tries to delete entries while remote Grpc client tries to add)

Polling mode
Every entry is extended with a HIT bit. Every time an  entry is hit, the hardware sets this bit automatically. Once in a while (e.g., every 5 minutes) , the control plane reads the hit bits and if the value of the bit is 0, that means that the entry has not been hit since the previous poll and is probably OK to remove. 
