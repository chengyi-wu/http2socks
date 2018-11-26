# http-to-socks

Non-caching HTTP proxy in python.

```
>>> python server.py
    Listening @ 127.0.0.1:8080

-h <host:port> for hosting tcp server
-p <host:port> for socks 5 proxy
```

### Features
- [ThreadingHTTPServer](https://docs.python.org/3/library/http.server.html)
- Support socks 5 forward
- Persistent connection
- Supported HTTP commands
   - GET
   - POST
   - HEAD
   - PUT
   - DELETE
   - CONNECT
- Support authentication forward
- HTTPS
   - Act as "tunnel", blindly exchange the bytes from client and server.
   - keep-alive: 30

#### Requirements
- Python 3.6
