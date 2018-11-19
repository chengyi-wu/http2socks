import socket
import socketserver
import select
import logging
import socks
import http.client
import zlib

HTTP_VER = 'HTTP/1.1'
FORWARDED_BY = b'Forwarded-By:PySocks Agent\r\n'

class SocksRequestHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.shadowsocks = None
        self.blocksize = 4096
        super(SocksRequestHandler, self).__init__(request, client_address, server)

    def handle(self):
        data = self._recvall(self.request)
        if len(data) == 0: return
        self.requestline = data.split(b'\r\n')[0].decode('ascii')
        logging.debug(self.requestline)

        host, port = self._get_hostport(self.requestline)

        self.shadowsocks = socks.socksocket()
        try:
            self._connect(host, port)
        except Exception as e:
            logging.warning("Failed to tunnel to %s:%d : %s" % (host, port, str(e)))
            self.shadowsocks.close()
            self._fail(str(e))
            return
        
        method = self._get_method(self.requestline)
        
        if method == 'CONNECT':
            self.request.setblocking(0)
            self.shadowsocks.setblocking(0)
            # if https, send response code 200 to client
            data = HTTP_VER + ' 200 Connection established\r\n\r\n'
            data = bytes(data, 'utf-8')
            self.request.send(data)

            self._socket_forward()
        else:
            # if http, send the data from client to destination
            self.shadowsocks.send(data)

            # forward synchronously
            response = http.client.HTTPResponse(self.shadowsocks, method=method)
            try:
                response.begin()  
            except Exception as err:
                logging.error(str(err))
                response.close()
            status_line = "%s %s %s\r\n" % (HTTP_VER, response.status, response.reason)
            logging.debug(status_line)
            self.request.send(bytes(status_line, 'utf-8'))

            if response.headers:
                for k, v in response.headers.items():
                    # remove TE and CE because I read the body from socket using HTTPResponse
                    if 'Transfer-Encoding' == k or 'Content-Encoding' == k:
                        continue
                    data = bytes(k + ':' + v + '\r\n', 'utf-8')
                    self.request.send(data)
            self.request.send(FORWARDED_BY)
            self.request.send(b'\r\n')
            data = response.read()
            response.close()
            if 'Content-Encoding' in response.headers:
                if response.headers['Content-Encoding'] == 'gzip':
                    data = zlib.decompress(data, 16+zlib.MAX_WBITS)
                else: # handle other CEs
                    pass
            # logging.debug(data)
            self.request.send(data)

    def finish(self):
        if self.shadowsocks and self.shadowsocks.fileno() != -1:
            logging.debug("close %d" % self.shadowsocks.fileno())
            self.shadowsocks.close()
        super(SocksRequestHandler, self).finish()

    def _fail(self, err=''):
        data = HTTP_VER + ' 502 Bad Gateway\r\n\r\n' + err
        data = bytes(data, 'utf-8')
        self.request.send(data)
        
    def _recvall(self, sock):
        data = b''
        while True:
            buf = sock.recv(self.blocksize)
            data += buf
            if len(data) < self.blocksize : break
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
        logging.info("connecting %s:%d from %s:%d" % (host, port, self.client_address[0], self.client_address[1]))
        self.shadowsocks.connect((host, port))

    def _socket_forward(self):
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