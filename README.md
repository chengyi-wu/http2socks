# http-to-socks

A TCP socket server runs locally and forward the requests through socksV5 proxy.

### Details
- default port is 2080
- ThreadingTCPServer
- request_queue_size = 128
- socket bytes forwarding in each request

#### Requirements
- Python 3