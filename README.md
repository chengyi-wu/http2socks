# http-to-socks

A TCP socket server runs locally and forward the requests through socks 5 proxy.

```
>>> python server.py
    running @ 127.0.0.1:8080

-h <host:port> for hosting tcp server
-p <host:port> for socks 5 proxy
```

### Features
- default port is 8080
- ThreadingTCPServer
- request_queue_size = 128
- socket bytes forwarding for https
- added 'Z-Forwarded-By' http header (**ONLY** for http requests)

#### Requirements
- Python 3
