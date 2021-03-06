from http.server import BaseHTTPRequestHandler
from http import HTTPStatus
import socket
import time
import select
from queue import Queue
from urllib.parse import urlparse
import socks
from http.client import HTTPResponse
import logging

logger = logging.getLogger('RelayRequestHandler')

# maximal line length when calling readline().
_MAXLINE = 65536

class RelayRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, request, classmethod, server):
        self.protocol_version = 'HTTP/1.1' # support persistent connection
        self.shadowsocks = None
        self.debuglevel = server.debuglevel
        self.idle_timeout = 30 # keep-alive timeout for https
        self.proxy = server.proxy
        super(RelayRequestHandler, self).__init__(request, classmethod, server)

    def handle_one_request(self):
        '''Override to handle [Errno 54] Connection reset by peer.
        '''
        try:
            super(RelayRequestHandler, self).handle_one_request()
        except ConnectionResetError as err:
            # client has closed the socket
            self.close_connection = True
            if self.debuglevel > 0 : print("[RelayRequestHandler]", str(err))
        except ConnectionAbortedError as err:
            # client has aborted the socket
            self.close_connection = True
            if self.debuglevel > 0 : print("[RelayRequestHandler]", str(err))

    def finish(self):
        '''Override to make sure no resource leak.
        '''
        if self.shadowsocks and self.shadowsocks.fileno() != -1:
            self.shadowsocks.close()
        super(RelayRequestHandler, self).finish()

    def _recvall(self, sock:socket.socket):
        data = b''
        while True:
            buf = sock.recv(_MAXLINE)
            data += buf
            if len(buf) < _MAXLINE: break
        return data

    def _get_hostport(self, netloc):
        host = netloc
        port = 80
        if ':' in host:
            port = host[host.index(':') + 1:]
            port = int(port)
            host = host[:host.index(':')]
        return host, port

    def _tunnel(self, host, port):
        if self.debuglevel > 0: print("_tunnel (%s, %d)" % (host, port))
        shadowsock = socks.socksocket()
        if self.proxy:
            # shadowsock.setproxy('raspberrypi', 1080)
            shadowsock.set_proxy(self.proxy[0], self.proxy[1])
        try:
            shadowsock.connect((host, port))
        except Exception as err:
            shadowsock.close()
            if self.debuglevel > 0: print("_tunnel", str(err))
            return None
        
        return shadowsock

    def _blind_relay(self):
        if self.debuglevel > 0: print("[_blind_relay] entering [%s]" % self.requestline)
        start_time = time.time()

        req_q = Queue()
        sdw_q = Queue()

        rlist = xlist = [self.request, self.shadowsocks]
        wlist = []

        count = 0
        while len(rlist) == 2: # keep the tunnel
            count += 1
            rfd, wfd, xfd = select.select(rlist, wlist, xlist, 1)
            for fd in xfd:
                rlist = []
                fd.close()
            for fd in rfd:
                data = b''
                try:
                    # client or server may have close the conneciton
                    data = fd.recv(_MAXLINE)
                except socket.error as err:
                    if self.debuglevel > 0:
                        print("[_blind_relay] [rfd] %s" % str(err))
                # else:
                #     print('RECV from [%d] : %s' % (fd.fileno(), data))
                if data:
                    count = 0 # reset timer
                    if fd is self.request:
                        req_q.put(data)
                        wlist += [self.shadowsocks]
                    else:
                        sdw_q.put(data)
                        wlist += [self.request]
                else:
                    rlist.remove(fd)
            for fd in wfd:
                wlist.remove(fd)
                if fd is self.request:
                    q = sdw_q
                else:
                    q = req_q
                while not q.empty():
                    count = 0 # reset timer
                    data = q.get()
                    try:
                        fd.send(data)
                    except socket.error as err:
                        if self.debuglevel > 0:
                            print("[_blind_relay] [wfd] %s" % str(err))
                    # else:
                    #     print('SEND from [%d] : %s' % (fd.fileno(), data))
            if count == self.idle_timeout:
                # idle timeout
                time_elapsed = time.time() - start_time
                logger.info("idle timeout [%s] : %.4f" % (self.requestline, time_elapsed))
                if self.debuglevel > 0:
                    print('[_blind_relay] idle timeout [%s] : %.4f' % (self.requestline, time_elapsed))
                break
        if self.debuglevel > 0: print("[_blind_relay] leaving [%s]" % self.requestline)

    def _relay_request(self, requestline, debuglevel=0):
        data = requestline

        content_length, chunked = None, None
        for hdr in self.headers:
            val = self.headers.get(hdr)
            if hdr.lower() == 'content-length':
                content_length = int(val)
            if hdr.lower() == 'transfer-encoding':
                if val == 'chunked': chunked = True
            buf = "%s:%s\r\n" % (hdr, val)
            data += buf.encode("ascii")
        
        data += b'\r\n'
        # if debuglevel > 0: print("send:", data)
        # self.shadowsocks.send(data)
        # data = None

        # data in the POST
        if content_length:
            data += self.rfile.read(content_length)
        if debuglevel > 0: print("send:", data)
        self.shadowsocks.send(data)

    def _relay_response(self, debuglevel=0):
        resp = HTTPResponse(self.shadowsocks, method=self.command)

        resp.begin()

        # attempt to reuse the shadow socket
        self.close_connection = resp.will_close
        if self.close_connection:
            self.shadowsocks.close()
            self.shadowsocks = None

        if self.debuglevel > 0: # pass
            print("[_relay_response] [%s] resp.will_close=%s" % (self.requestline, resp.will_close))
        
        ver_str = self.protocol_version
        if resp.version == 10:
            ver_str = "HTTP/1.0"
        reply = "%s %s %s\r\n" % (ver_str, resp.code, resp.reason)
        if resp.headers:
            for hdr in resp.headers:
                val = resp.headers[hdr]
                reply += "%s: %s\r\n" % (hdr, val)
        reply += "%s: %s\r\n" % ("Z-Relayed-By", "Python Proxy Server 0.0.2")
        reply += "\r\n"
        reply = reply.encode("latin-1", "strict")

        # if debuglevel > 0: print("response header:", header)

        # self.request.send(header)

        # self.close_connection = True

        # Message body is omitted for cases described in:
        #  - RFC7230: 3.3. 1xx, 204(No Content), 304(Not Modified)
        #  - RFC7231: 6.3.6. 205(Reset Content)
        if (self.command == 'HEAD' or 
            resp.code < HTTPStatus.OK or 
            resp.code in (HTTPStatus.NO_CONTENT, HTTPStatus.RESET_CONTENT, HTTPStatus.NOT_MODIFIED)):
            if resp.will_close:
                resp.close()
            if debuglevel > 0: print("reply:", reply)
            self.request.send(reply)
            return resp.code, reply
        
        resp_body = resp.read()
        if resp.chunked:
            resp_size = len(resp_body)
            reply += ("%x\r\n" % resp_size).encode("utf-8")
            reply += resp_body + b'\r\n'
            reply += b'0\r\n'
        elif len(resp_body) > 0:
            reply += resp_body

        reply += b'\r\n'
        self.request.send(reply)
        if debuglevel > 0: print("reply:", reply)

        if self.debuglevel > 0:
            print("[_relay_response]", resp.code, resp.reason, self.requestline)

        if resp.will_close:
            resp.close()

        if resp.code == HTTPStatus.UNAUTHORIZED:
            self._blind_relay()

        return resp.code, reply

    def _relay(self):
        if self.debuglevel > 0: print("[_relay] entering [%s]" % self.requestline)
        result = urlparse(self.path)
        netloc, path, query, fragment = result.netloc, result.path, result.query, result.fragment

        if not path: path = '/'
        if query: path += '?' + query

        new_requestline = "%s %s %s\r\n" % (self.command, path, self.request_version)
        new_requestline = new_requestline.encode('ascii')

        host, port = self._get_hostport(netloc)

        # do a match up of the socket address
        if self.shadowsocks and self.shadowsocks.addr != (host, port):
            self.shadowsocks.close()
            self.shadowsocks = None

        if not self.shadowsocks or self.shadowsocks.fileno() == -1:
            self.shadowsocks = self._tunnel(host, port)
        
        if not self.shadowsocks:
            self.send_error(HTTPStatus.BAD_GATEWAY, message="Unable to connect to (%s, %d)" % (host, port))
            self.close_connection = True
            return    

        try:
            self._relay_request(new_requestline, debuglevel=self.debuglevel)
        except Exception as err:
            self.send_error(HTTPStatus.BAD_GATEWAY, message=str(err))
            self.close_connection = True
        else:
            try:
                self._relay_response(debuglevel=self.debuglevel)
            except socket.error: # may not be able to send back
                if self.close_connection == "UNKNOWN":
                    self.close_connection = True
                pass
            except Exception as err:
                if self.debuglevel > 0: print("[_relay] [%s]: %s" % (self.requestline, str(err)))
                if self.close_connection == 'UNKNOWN':
                    self.close_connection = True
                raise err
        if self.debuglevel > 0: print("[_relay] leaving [%s]" % self.requestline)

    def do_GET(self):
        self._relay()
        
    def do_POST(self):
        self._relay()

    def do_HEAD(self):
        self._relay()

    def do_PUT(self):
        self._relay()

    def do_DELETE(self):
        self._relay()
        
    def do_CONNECT(self):
        if self.debuglevel > 0:
            print("do_CONNECT [%s]" % self.requestline)
        logger.info("connecting %s" % self.requestline)
        
        host, port = self._get_hostport(self.path)
        
        self.shadowsocks = self._tunnel(host, port)

        if self.shadowsocks:
            self.send_response_only(HTTPStatus.OK)
            self.end_headers()
            self._blind_relay()
            self.shadowsocks.close()
        else:
            self.send_error(HTTPStatus.BAD_GATEWAY, message="Unable to connect to (%s, %d)" % (host, port))
        
        self.close_connection = True