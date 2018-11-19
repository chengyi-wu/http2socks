import socket
import socketserver
import select
import logging

class SocksRequestHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.shadowsocks = None
        self.blocksize = 4096
        super(SocksRequestHandler, self).__init__(request, client_address, server)

    def handle(self):
        self.request

        data = self._recvall()
        if len(data) == 0: return
        self.requestline = data.split(b'\r\n')[0].decode('ascii')
        logging.info(self.requestline)

        host, port = self._get_hostport(self.requestline)

        self.shadowsocks = socket.socket()
        try:
            self._connect(host, port)
        except Exception as e:
            logging.warning("Failed to tunnel to %s:%d : %s" % (host, port, str(e)))
            self.shadowsocks.close()
            self._fail(str(e))
            return
        self.shadowsocks.setblocking(0)
        
        method = self._get_method(self.requestline)
        
        if method == 'CONNECT':
            # if https, then send response code 200 to client
            data = 'HTTP/2.0 200 Connection established\r\n\r\n'
            data = bytes(data, 'utf-8')
            self.request.send(data)
        else:
            # if http, then send the data from client to destination
            self.shadowsocks.sendall(data)
        
        self._socket_forward()
    
    def finish(self):
        if self.shadowsocks and self.shadowsocks.fileno() != -1:
            logging.debug("close %d" % self.shadowsocks.fileno())
            self.shadowsocks.close()
        super(SocksRequestHandler, self).finish()

    def _fail(self, err=''):
        data = 'HTTP/2.0 502 Bad Gateway\r\n\r\n' + err
        data = bytes(data, 'utf-8')
        self.request.sendall(data)
        
    def _recvall(self):
        data = b''
        while True:
            buf = self.request.recv(self.blocksize)
            data += buf
            if len(buf) < self.blocksize: break
        return data

    def _get_hostport(self, requestline):
        requestline = requestline.split()
        netloc = requestline[1]
        host = netloc
        port = 80 # default port
        if '://' in netloc:
            host = netloc[netloc.index('://') + 3 : ]
        if '/' in host:
            host = host[ : host.index('/')]
        if ':' in host:
            port = int(host[host.index(':') + 1 : ])
            host = host[ : host.index(':')]
        return host, port

    def _get_method(self, requestline):
        return requestline.split()[0]

    def _connect(self, host, port):
        logging.debug("Tunnel to %s:%d" % (host, port))
        self.shadowsocks.connect((host, port))

    def _socket_forward(self):
        # print("enter _socket_forward")
        buffersize = self.blocksize
        rlist = [self.request, self.shadowsocks]
        while rlist:
            rfd, _, xfd = select.select(rlist, [], rlist, 1.0)
            for fd in xfd:
                if fd in rlist:
                    rlist.remove(fd)
            for fd in rfd:
                data = b''
                try:
                    data = fd.recv(buffersize)
                except:
                    pass
                if data:
                    out = self.shadowsocks
                    if fd is self.shadowsocks:
                        out = self.request
                    out.send(data)
                    logging.debug("_socket_forward %d=>%d : %s" % (fd.fileno(), out.fileno(), len(data)))
                else:
                    rlist = None