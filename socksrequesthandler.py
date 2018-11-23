import socket
import socketserver
import select
import logging
import socks
import http.client
import queue
import email.parser

HTTP_VER = 'HTTP/1.1'
FORWARDED_BY = b'Z-Forwarded-By:Socks Proxy Server 0.1\r\n'

logger = logging.getLogger('SocksRequestHandler')

class SocksRequestHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.shadowsocks = None
        self.blocksize = 4096
        self.debuglevel = 0
        super(SocksRequestHandler, self).__init__(request, client_address, server)

    def handle(self):
        data = self._recvall(self.request)
        if self.debuglevel > 0: print("send:", data)
        if len(data) == 0: return
        self.requestline = data.split(b'\r\n')[0].decode("iso-8859-1")
        logger.info("entering [%d][%s]" % (self.request.fileno(), self.requestline))

        host, port = self._get_hostport(self.requestline)

        proxyhost, porxyport = self.server.socksproxy
        self.shadowsocks = socks.socksocket()
        if proxyhost and porxyport:
            self.shadowsocks.setproxy(proxyhost, porxyport)
        # self.shadowsocks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self._connect(host, port)
        except Exception as err:
            logger.warning("Failed to tunnel to %s:%d : %s" % (host, port, str(err)))
            self.shadowsocks.close()
            self._fail(str(err))
            return
        
        method = self._get_method(self.requestline)
        
        if method == 'CONNECT':
            # if https, send response code 200 to client
            data = HTTP_VER + ' 200 Connection established\r\n\r\n'
            data = data.encode("utf-8")
            self.request.send(data)

            self._secure_socket_forward()
        else:
            # if http, send the data from client to destination
            self.shadowsocks.send(data)
            will_close, status = True, None
            fp = self.shadowsocks.makefile('rb')
            try:
                will_close, status = self._socket_forward(fp, debuglevel=self.debuglevel, _method=method)
                self.request.send(b'\r\n')
            except Exception as err:
                logger.exception("Unable to forward [%s] : %s" % (self.requestline, str(err)))

            if status == 401 or not will_close: # make it persistent
                self._secure_socket_forward()

            fp.close()

    def finish(self):
        if self.shadowsocks and self.shadowsocks.fileno() != -1:
            # logger.debug("close %d" % self.shadowsocks.fileno())
            self.shadowsocks.close()
        if hasattr(self, 'requestline'):
            logger.info("leaving [%d][%s]" % (self.request.fileno(), self.requestline))
        super(SocksRequestHandler, self).finish()

    def _fail(self, err=''):
        data = HTTP_VER + ' 502 Bad Gateway\r\n\r\n' + err
        data = data.encode("utf-8")
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
        logger.debug("connecting %s:%d from %s:%d" % (host, port, self.client_address[0], self.client_address[1]))
        self.shadowsocks.connect((host, port))

    def _secure_socket_forward(self):
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
        wlist = []
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
                    logger.debug('RECV from [%d] : %s' % (fd.fileno(), len(data)))
                if data:
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
                    data = q.get()
                    try:
                        fd.send(data)
                    except Exception as err:
                        logger.error("%s" % str(err))
                        pass
                    else:
                        logger.debug('SEND from [%d] : %d' % (fd.fileno(), len(data)))

    def _socket_forward(self, fp, debuglevel=0, _method=None):
        """Copy from http.client.HTTPResponse()
        parse the http heads to determine the bytes to read, this is blocking read
        """
        _UNKNOWN = 'UNKNOWN'

        MAXAMOUNT = 1048576
        _MAXLINE = 65536
        _MAXHEADERS = 100

        CONTINUE = 100
        NO_CONTENT = 204
        NOT_MODIFIED = 304

        chunked = _UNKNOWN
        self.chunk_left = _UNKNOWN
        length = _UNKNOWN

        will_close = _UNKNOWN 

        sock = self.request

        def _read_status(fp):
            line = str(fp.readline(_MAXLINE + 1), "iso-8859-1")
            if debuglevel > 0:
                print("reply:", repr(line))
            if not line:
                raise Exception("Remote end closed connection without response")
            
            return line
        
        def _parse_status(line):
            try:
                version, status, reason = line.split(None, 2)
            except ValueError:
                try:
                    version, status = line.split(None, 1)
                    reason = ""
                except ValueError:
                    version = ""
            
            try:
                status = int(status)
            except ValueError:
                status = -1
            
            return version, status, reason

        def parse_headers(fp, _class=http.client.HTTPMessage):
            """Parses only RFC2822 headers from a file pointer.

            email Parser wants to see strings rather than bytes.
            But a TextIOWrapper around self.rfile would buffer too many bytes
            from the stream, bytes which we later need to read as bytes.
            So we read the correct bytes here, as bytes, for email Parser
            to parse.

            """
            headers = []
            while True:
                line = fp.readline(_MAXLINE + 1)
                if len(line) > _MAXLINE:
                    raise Exception("header line")
                headers.append(line)
                if len(headers) > _MAXHEADERS:
                    raise Exception("got more than %d headers" % _MAXHEADERS)
                if line in (b'\r\n', b'\n', b''):
                    break
            hstring = b''.join(headers).decode("iso-8859-1")
            return email.parser.Parser(_class=_class).parsestr(hstring)

        def _check_close(version):
            conn = headers.get("connection")
            if version == 11:
                # An HTTP/1.1 proxy is assumed to stay open unless
                # explicitly closed.
                conn = headers.get("connection")
                if conn and "close" in conn.lower():
                    return True
                return False

            # Some HTTP/1.0 implementations have support for persistent
            # connections, using rules different than HTTP/1.1.

            # For older HTTP, Keep-Alive indicates persistent connection.
            if headers.get("keep-alive"):
                return False

            # At least Akamai returns a "Connection: Keep-Alive" header,
            # which was supposed to be sent by the client.
            if conn and "keep-alive" in conn.lower():
                return False

            # Proxy-Connection is a netscape hack.
            pconn = headers.get("proxy-connection")
            if pconn and "keep-alive" in pconn.lower():
                return False

            # otherwise, assume it will close
            return True

        def _read_next_chunk_size():
            line = fp.readline(_MAXLINE + 1)
            i = line.find(b";")
            if i > 0:
                line = line[:i]
            try:
                return int(line, 16)
            except ValueError:
                raise

        def _read_and_discard_trailer():
            while True:
                line = fp.readline(_MAXLINE + 1)
                if not line: break
                if line in (b'\r\n', b'\n', b''):
                    break

        def _safe_read(amt):
            s = []
            while amt > 0:
                chunk = fp.read(min(amt, MAXAMOUNT))
                if not chunk:
                    raise Exception("IncompleteRead")
                s.append(chunk)
                amt -= len(chunk)
            return b"".join(s)

        def _get_chunk_left():
            chunk_left = self.chunk_left
            if not self.chunk_left: # Can be 0 or None
                if chunk_left is not None:
                    # We are at the end of the chunk. dirchard chunk end
                    _safe_read(2) # toss the CRLF at the end of the chunk
                try:
                    chunk_left = _read_next_chunk_size()
                except ValueError:
                    raise Exception("IncompleteRead")
                if chunk_left == 0:
                    # last chunk: 1*("0") [ chunk-extention ] CRLF
                    _read_and_discard_trailer()
                    # we read everything; close the "file"
                    chunk_left = None
                self.chunk_left = chunk_left
            return chunk_left

        status_line = ""
        while True:
            status_line = _read_status(fp)
            version, status, _ = _parse_status(status_line)
            if status != CONTINUE: break
            
            # skip the head from the 100 response
            while True:
                skip = fp.readline(_MAXLINE + 1)
                skip = skip.strip()
                if not skip: break
                if debuglevel > 0:
                    print("header:", skip)
        
        # forward status line
        sock.send(status_line.encode("iso-8859-1"))

        headers = parse_headers(fp)
        
        # forward the headers
        for hdr in headers:
            val = headers.get(hdr)
            data = "%s: %s\r\n" % (hdr, val)
            data = data.encode("utf-8")
            sock.send(data)
            if debuglevel > 0: print(data)
        
        sock.send(FORWARDED_BY)
        # header done
        sock.send(b"\r\n")
        
        tr_enc = headers.get("transfer-encoding")
        if tr_enc and tr_enc.lower() == "chunked":
            chunked = True
            self.chunk_left = None
        else:
            chunked = False

        # will the connection close at the end of the response?
        will_close = _check_close(version)

        # do we have a Conent-Length?
        length = headers.get("content-length")

        # are we using the chunked-sytle of transfer encoding?
        tr_enc = headers.get("transfer-encoding")

        if length and not chunked:
            try:
                length = int(length)
            except ValueError:
                length = None
            else:
                if length < 0: length = None
        else:
            length = None
        
        if (status == NO_CONTENT or status == NOT_MODIFIED or 
            100 <= status < 200 or _method == "HEAD"):
            length = 0

        if (not will_close and
            not chunked and
            length is None):
            will_close = True

        if debuglevel > 0:
            print("chunked:", chunked)
            print("Content-Length:", length)
            print("will_close:", will_close)

        # read()
        if _method == "HEAD":
            return
        # _readall_chunked()
        size = 0
        if chunked:
            while True:
                chunk_left = _get_chunk_left()
                if debuglevel > 0:
                    print("chunk_left =", chunk_left)
                if chunk_left is None: break
                data = "%x\r\n" % chunk_left
                data = data.encode("utf-8")
                if debuglevel > 0:
                    print("chunk_left =", chunk_left)
                sock.send(data)
                data = _safe_read(chunk_left)
                sock.send(data + b'\r\n')
                size += chunk_left
                self.chunk_left = 0
            # last chunk: 1*("0") [ chunk-extention ] CRLF
            sock.send(b'0\r\n')
        else:       
            if length is None:
                s = fp.read()
            else:
                s = _safe_read(length)
            if debuglevel > 0: print(len(s))
            size += len(s)
            sock.send(s)
        logger.debug("TRAN [%d] => [%d] : %d" % (fp.fileno(), self.request.fileno(), size))

        return will_close, status