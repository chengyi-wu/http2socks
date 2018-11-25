# http-to-socks

A TCP socket server tunnels requests through socks 5 proxy.

```
A "tunnel" acts as a blind relay between two connections without
   changing the messages.  Once active, a tunnel is not considered a
   party to the HTTP communication, though the tunnel might have been
   initiated by an HTTP request.  A tunnel ceases to exist when both
   ends of the relayed connection are closed.  Tunnels are used to
   extend a virtual connection through an intermediary, such as when
   Transport Layer Security (TLS, [RFC5246]) is used to establish
   confidential communication through a shared firewall proxy.
```

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
