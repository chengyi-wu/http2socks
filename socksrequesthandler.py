import socket
import socketserver
import select
import logging
import socks
import http.client
import queue
import traceback

HTTP_VER = 'HTTP/1.1'
FORWARDED_BY = b'Z-Forwarded-By:PySocks Agent\r\n'

logger = logging.getLogger('SocksRequestHandler')

class SocksRequestHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.shadowsocks = None
        self.blocksize = 4096
        super(SocksRequestHandler, self).__init__(request, client_address, server)

    def handle(self):
        data = self._recvall(self.request)
        if len(data) == 0: return
        self.requestline = data.split(b'\r\n')[0].decode('ascii')
        logger.debug("entering [%s]" % self.requestline)

        host, port = self._get_hostport(self.requestline)

        proxyhost, porxyport = self.server.socksproxy
        self.shadowsocks = socks.socksocket()
        if proxyhost and porxyport:
            self.shadowsocks.setproxy(proxyhost, porxyport)
        
        try:
            self._connect(host, port)
        except Exception as e:
            logger.warning("Failed to tunnel to %s:%d : %s" % (host, port, str(e)))
            self.shadowsocks.close()
            self._fail(str(e))
            return
        
        method = self._get_method(self.requestline)
        
        if method == 'CONNECT':
            # if https, send response code 200 to client
            data = HTTP_VER + ' 200 Connection established\r\n\r\n'
            data = bytes(data, 'utf-8')
            self.request.send(data)

            self._socket_forward()
        else:
            # if http, send the data from client to destination
            self.shadowsocks.send(data)

            # forward synchronously
            # have to deal with the response, http request can be redirected to different hosts
            # need to let redirects to finish
            response = http.client.HTTPResponse(self.shadowsocks, method=method)
            try:
                response.begin()  
            except Exception as err:
                logger.exception("%s : %s" % (self.requestline, str(err)))
                response.close()
                return
            status_line = "%s %s %s\r\n" % (HTTP_VER, response.status, response.reason)
            # logger.debug(status_line)
            try:
                self.request.send(bytes(status_line, 'utf-8'))

                if response.headers:
                    for k, v in response.headers.items():
                        data = '%s:%s\r\n' % (k, v)
                        data = bytes(data, 'utf-8')
                        self.request.send(data)
                self.request.send(FORWARDED_BY)
                self.request.send(b'\r\n')
                data = response.read()
                response.close()
                # Transfer-Encoding
                # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding
                # chunked
                # Data is sent in a series of chunks. The Content-Length header is omitted in this case and at the 
                # beginning of each chunk you need to add the length of the current chunk in hexadecimal format, 
                # followed by '\r\n' and then the chunk itself, followed by another '\r\n'. 
                # The terminating chunk is a regular chunk, with the exception that its length is zero. 
                # It is followed by the trailer, which consists of a (possibly empty) sequence of entity header fields.
                if response.headers and response.headers.get('Transfer-Encoding') == 'chunked':
                    size = "{:x}\r\n".format(len(data))
                    self.request.send(bytes(size, 'utf-8'))
                    self.request.send(data + b'\r\n')
                    self.request.send(b'0\r\n')
                else:
                    self.request.send(data)
                self.request.send(b'\r\n')
            except Exception as err:
                logger.exception("%s : %s" % (self.requestline, str(err)))
                response.close()

    def finish(self):
        if self.shadowsocks and self.shadowsocks.fileno() != -1:
            # logger.debug("close %d" % self.shadowsocks.fileno())
            self.shadowsocks.close()
        if hasattr(self, 'requestline'):
            logger.debug("leaving [%s]" % self.requestline)
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
        logger.info("connecting %s:%d from %s:%d" % (host, port, self.client_address[0], self.client_address[1]))
        self.shadowsocks.connect((host, port))

    def _socket_forward(self):
        """ flow
        1. receive data from local socket, put data on local queue
        2. get data from local queue, write it to the remote socket
        3. receive data from remote socket, put data on remote queue
        4. get data from remote queue, write it to the local socket
        """
        self.shadowsocks.setblocking(0)

        req_q = queue.Queue()
        sdw_q = queue.Queue()

        rlist = xlist = [self.request, self.shadowsocks]
        wlist = [self.request, self.shadowsocks]
        while len(rlist) > 1: # self.request is always open
            rfd, wfd, xfd = select.select(rlist, wlist, xlist)
            for fd in xfd:
                rlist.remove(fd)
                fd.close()
            for fd in rfd:
                data = b''
                try:
                    data = fd.recv(self.blocksize)
                except Exception as err:
                    logger.error("%s" % str(err))
                else:
                    logger.debug('RECV from %d : %d' % (fd.fileno(), len(data)))
                if data:
                    if fd is self.request:
                        req_q.put(data)
                        wlist.append(self.shadowsocks)
                    else:
                        sdw_q.put(data)
                        wlist.append(self.request)
                else:
                    rlist.remove(fd)
            for fd in wfd:
                # wlist.remove(fd)
                if fd is self.request:
                    q = sdw_q
                else:
                    q = req_q
                while not q.empty():
                    data = q.get()
                    try:
                        fd.send(data)
                    except Exception as err:
                        logger.error("%s" % str(err))
                        pass
                    else:
                        logger.debug('SEND from %d : %d' % (fd.fileno(), len(data)))

    # def _socket_forward(self):
    #     self.request.setblocking(0)
    #     self.shadowsocks.setblocking(0)
    #     buffersize = self.blocksize
    #     rlist = [self.request, self.shadowsocks]
    #     count = 0
    #     while count < self.connection_timeout:
    #         count += 1
    #         rfd, _, xfd = select.select(rlist, [], rlist, 1.0)
    #         for fd in xfd:
    #             if fd in rlist:
    #                 rlist.remove(fd)
    #         for fd in rfd:
    #             data = b''
    #             try:
    #                 data = fd.recv(buffersize)
    #             except:
    #                 pass
    #             if data:
    #                 out = self.shadowsocks
    #                 if fd is self.shadowsocks:
    #                     out = self.request
    #                 out.send(data)
    #                 logger.debug("_socket_forward %s=>%s : %s" % (fd, out, data))
    #                 count = 0