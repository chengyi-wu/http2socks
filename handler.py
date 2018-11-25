from socketserver import StreamRequestHandler
from http.server import BaseHTTPRequestHandler
import sys
from http import HTTPStatus
import http.client
import socket
import html
import email.parser
import time
import select
from queue import Queue
from urllib.parse import urlparse
import io
from http.client import BadStatusLine, LineTooLong, RemoteDisconnected, UnknownProtocol, parse_headers, IncompleteRead, ResponseNotReady
import socks

_UNKNOWN = 'UNKNOWN'

# maximal amount of data to read at one time in _safe_read
MAXAMOUNT = 1048576

# maximal line length when calling readline().
_MAXLINE = 65536
_MAXHEADERS = 100

class BaseProxyRequestHandler(StreamRequestHandler):
    """

    """
    error_message_format = """\
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: %(code)d</p>
        <p>Message: %(message)s.</p>
        <p>Error code explanation: %(code)s - %(explain)s.</p>
    </body>
</html>
"""
    error_content_type = "text/html;charset=utf-8"

    # The default request version.  This only affects responses up until
    # the point where the request line is parsed, so it mainly decides what
    # the client gets back when sending a malformed request line.
    # Most web servers default to HTTP 0.9, i.e. don't send a status line.
    default_request_version = "HTTP/0.9"

    def parse_requestline(self):
        """Parse a request line (internal).

        The request should be stored in self.raw_requestline; the results
        are in self.command, self.path, self.request_version.

        Return True for success, False for failure; on failure, an
        error is sent back.

        """
        self.command = None  # set in case of error on the first line
        self.request_version = version = self.default_request_version
        self.close_connection = True
        requestline = str(self.raw_requestline, 'iso-8859-1')
        requestline = requestline.rstrip('\r\n')
        self.requestline = requestline
        words = requestline.split()
        if len(words) == 3:
            command, path, version = words
            try:
                if version[:5] != 'HTTP/':
                    raise ValueError
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                # RFC 2145 section 3.1 says there can be only one "." and
                #   - major and minor numbers MUST be treated as
                #      separate integers;
                #   - HTTP/2.4 is a lower version than HTTP/2.13, which in
                #      turn is lower than HTTP/12.3;
                #   - Leading zeros MUST be ignored by recipients.
                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad request version (%r)" % version)
                return False
            if version_number >= (1, 1) and self.protocol_version >= "HTTP/1.1":
                self.close_connection = False
            if version_number >= (2, 0):
                self.send_error(
                    HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
                    "Invalid HTTP version (%s)" % base_version_number)
                return False
        elif len(words) == 2:
            command, path = words
            self.close_connection = True
            if command != 'GET':
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad HTTP/0.9 request type (%r)" % command)
                return False
        elif not words:
            return False
        else:
            self.send_error(
                HTTPStatus.BAD_REQUEST,
                "Bad request syntax (%r)" % requestline)
            return False
        self.command, self.path, self.request_version = command, path, version

    def parse_request(self):
        """Parse a request headers (internal).

        The request should be stored in self.raw_requestline; the result is
        self.headers.

        Return True for success, False for failure; onhal failure, an
        error is sent back.

        """
        # Examine the headers and look for a Connection directive.
        try:
            self.headers = http.client.parse_headers(self.rfile,
                                                     _class=self.MessageClass)
        except http.client.LineTooLong as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Line too long",
                str(err))
            return False
        except http.client.HTTPException as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Too many headers",
                str(err)
            )
            return False

        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = True
        elif (conntype.lower() == 'keep-alive' and
              self.protocol_version >= "HTTP/1.1"):
            self.close_connection = False
        # Examine the headers and look for an Expect directive
        expect = self.headers.get('Expect', "")
        if (expect.lower() == "100-continue" and
                self.protocol_version >= "HTTP/1.1" and
                self.request_version >= "HTTP/1.1"):
            if not self.handle_expect_100():
                return False
        return True

    def handle_expect_100(self):
        """Decide what to do with an "Expect: 100-continue" header.

        If the client is expecting a 100 Continue response, we must
        respond with either a 100 Continue or a final response before
        waiting for the request body. The default is to always respond
        with a 100 Continue. You can behave differently (for example,
        reject unauthorized requests) by overriding this method.

        This method should either return True (possibly after sending
        a 100 Continue response) or send an error response and return
        False.

        """
        self.send_response_only(HTTPStatus.CONTINUE)
        self.end_headers()
        return True

    def handle_one_request(self):
        """Handle a single HTTP request.

        You normally don't need to override this method; see the class
        __doc__ string for information on how to handle specific HTTP
        commands such as GET and POST.

        """
        try:
            self.raw_requestline = self.rfile.readline(_MAXLINE + 1)
            if len(self.raw_requestline) > _MAXLINE:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)
                return
            if not self.raw_requestline:
                return
            self.parse_requestline()
            if not self.command: return
            mname = 'do_' + self.command
            if not hasattr(self, mname):
                self.send_error(
                    HTTPStatus.NOT_IMPLEMENTED,
                    "Unsupported method (%r)" % self.command)
                return
            method = getattr(self, mname)
            if self.command != 'CONNECT': # CONNECT has no message-body
                if not self.parse_request():
                    # An error code has been sent, just exit
                    return
            method()
            self.wfile.flush() #actually send the response if not already done.
        except socket.timeout as e:
            #a read or a write timed out.  Discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = True
            return

    def handle(self):
        """Handle multiple requests if necessary."""
        self.close_connection = True

        self.handle_one_request()
        while not self.close_connection:
            self.handle_one_request()

    def send_error(self, code, message=None, explain=None):
        """Send and log an error reply.

        Arguments are
        * code:    an HTTP error code
                   3 digits
        * message: a simple optional 1 line reason phrase.
                   *( HTAB / SP / VCHAR / %x80-FF )
                   defaults to short entry matching the response code
        * explain: a detailed message defaults to the long entry
                   matching the response code.

        This sends an error response (so it must be called before any
        output has been generated), logs the error, and finally sends
        a piece of HTML explaining the error to the user.

        """

        try:
            shortmsg, longmsg = self.responses[code]
        except KeyError:
            shortmsg, longmsg = '???', '???'
        if message is None:
            message = shortmsg
        if explain is None:
            explain = longmsg
        self.log_error("code %d, message %s", code, message)
        self.send_response(code, message)
        self.send_header('Connection', 'close')

        try:
            # Message body is omitted for cases described in:
            #  - RFC7230: 3.3. 1xx, 204(No Content), 304(Not Modified)
            #  - RFC7231: 6.3.6. 205(Reset Content)
            body = None
            if (code >= 200 and
                code not in (HTTPStatus.NO_CONTENT,
                            HTTPStatus.RESET_CONTENT,
                            HTTPStatus.NOT_MODIFIED)):
                # HTML encode to prevent Cross Site Scripting attacks
                # (see bug #1100201)
                content = (self.error_message_format % {
                    'code': code,
                    'message': html.escape(message, quote=False),
                    'explain': html.escape(explain, quote=False)
                })
                body = content.encode('UTF-8', 'replace')
                self.send_header("Content-Type", self.error_content_type)
                self.send_header('Content-Length', int(len(body)))
            self.end_headers()

            if self.command != 'HEAD' and body:
                self.wfile.write(body)
        except BrokenPipeError:
            pass

    def send_response(self, code, message=None):
        """Add the response header to the headers buffer and log the
        response code.

        Also send two standard headers with the server software
        version and the current date.

        """
        self.log_request(code)
        self.send_response_only(code, message)
        # self.send_header('Server', self.version_string())
        self.send_header('Date', self.date_time_string())

    def send_response_only(self, code, message=None):
        """Send the response header only."""
        if self.request_version != 'HTTP/0.9':
            if message is None:
                if code in self.responses:
                    message = self.responses[code][0]
                else:
                    message = ''
            if not hasattr(self, '_headers_buffer'):
                self._headers_buffer = []
            self._headers_buffer.append(("%s %d %s\r\n" %
                    (self.protocol_version, code, message)).encode(
                        'latin-1', 'strict'))

    def send_header(self, keyword, value):
        """Send a MIME header to the headers buffer."""
        if self.request_version != 'HTTP/0.9':
            if not hasattr(self, '_headers_buffer'):
                self._headers_buffer = []
            self._headers_buffer.append(
                ("%s: %s\r\n" % (keyword, value)).encode('latin-1', 'strict'))

        if keyword.lower() == 'connection':
            if value.lower() == 'close':
                self.close_connection = True
            elif value.lower() == 'keep-alive':
                self.close_connection = False

    def end_headers(self):
        """Send the blank line ending the MIME headers."""
        if self.request_version != 'HTTP/0.9':
            self._headers_buffer.append(b"\r\n")
            self.flush_headers()

    def flush_headers(self):
        if hasattr(self, '_headers_buffer'):
            self.wfile.write(b"".join(self._headers_buffer))
            self._headers_buffer = []

    def log_request(self, code='-', size='-'):
        """Log an accepted request.

        This is called by send_response().

        """
        if isinstance(code, HTTPStatus):
            code = code.value
        self.log_message('"%s" %s %s',
                         self.requestline, str(code), str(size))

    def log_error(self, format, *args):
        """Log an error.

        This is called when a request cannot be fulfilled.  By
        default it passes the message on to log_message().

        Arguments are the same as for log_message().

        XXX This should go to the separate error log.

        """

        self.log_message(format, *args)

    def log_message(self, format, *args):
        """Log an arbitrary message.

        This is used by all other logging functions.  Override
        it if you have specific logging wishes.

        The first argument, FORMAT, is a format string for the
        message to be logged.  If the format string contains
        any % escapes requiring parameters, they should be
        specified as subsequent arguments (it's just like
        printf!).

        The client ip and current date/time are prefixed to
        every message.

        """

        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format%args))

    # def version_string(self):
    #     """Return the server software version string."""
    #     return self.server_version + ' ' + self.sys_version

    def date_time_string(self, timestamp=None):
        """Return the current date and time formatted for a message header."""
        if timestamp is None:
            timestamp = time.time()
        return email.utils.formatdate(timestamp, usegmt=True)

    def log_date_time_string(self):
        """Return the current time formatted for logging."""
        now = time.time()
        year, month, day, hh, mm, ss, x, y, z = time.localtime(now)
        s = "%02d/%3s/%04d %02d:%02d:%02d" % (
                day, self.monthname[month], year, hh, mm, ss)
        return s

    weekdayname = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

    monthname = [None,
                 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    def address_string(self):
        """Return the client address."""

        return self.client_address[0]

    # Essentially static class variables

    # The version of the HTTP protocol we support.
    # Set this to HTTP/1.1 to enable automatic keepalive
    protocol_version = "HTTP/1.0"

    # MessageClass used to parse headers
    MessageClass = http.client.HTTPMessage

    # hack to maintain backwards compatibility
    responses = {
        v: (v.phrase, v.description)
        for v in HTTPStatus.__members__.values()
    }

class SocksRequestHandler(BaseProxyRequestHandler):
    def __init__(self, request, classmethod, server, debuglevel=1):
        self.protocol_version = 'HTTP/1.1' # support persistent connection
        self.shadowsocks = None
        self.debuglevel = debuglevel
        self.idle_timeout = 30 # keep-alive timeout for https
        super(SocksRequestHandler, self).__init__(request, classmethod, server)

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
        shadowsock.setproxy('raspberrypi', 1080)
        try:
            shadowsock.connect((host, port))
        except:
            shadowsock.close()
            return None
        
        return shadowsock

    def _socket_forward(self):
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
                    data = fd.recv(_MAXLINE)
                except Exception as err:
                    print("%s" % str(err))
                # else:
                #     print('RECV from [%d] : %s' % (fd.fileno(), data))
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
                    count = 0 # reset timer
                    data = q.get()
                    try:
                        fd.send(data)
                    except Exception as err:
                        print("%s" % str(err))
                    # else:
                    #     print('SEND from [%d] : %s' % (fd.fileno(), data))
            if count == self.idle_timeout:
                # idle timeout
                time_elapsed = time.time() - start_time
                print('idle timeout for [%s] : %.4f' % (self.requestline, time_elapsed))
                break

    def _forward_request(self, requestline, debuglevel=0):
        data = requestline

        content_length, chunked = None, None
        for hdr in self.headers:
            val = self.headers.get(hdr)
            if hdr.lower() == 'content-length':
                content_length = int(val)
            if hdr.lower() == 'trnsfer-encoding':
                if val == 'chunked': chunked = True
            buf = "%s:%s\r\n" % (hdr, val)
            data += buf.encode("ascii")
        
        data += b'\r\n'
        if debuglevel > 0: print("send:", data)
        self.shadowsocks.send(data)
        data = None

        # data in the POST
        if content_length:
            data = self.rfile.read(content_length)
            if debuglevel > 0: print("send:", data)
            self.shadowsocks.send(data)

    def _forward_response(self, debuglevel=0):
        resp = http.client.HTTPResponse(self.shadowsocks, debuglevel=debuglevel, method=self.command)

        resp.begin()

        self.send_response_only(resp.code, resp.reason)

        if resp.headers:
            for hdr in resp.headers:
                val = resp.headers[hdr]
                if debuglevel > 0: print("response header:", (hdr, val))
                self.send_header(hdr, val)
        self.end_headers()
        
        resp_body = resp.read()
        if resp.chunked:
            resp_size = len(resp_body)
            data = "%x\r\n" % resp_size
            data = data.encode("utf-8")
            self.request.send(data)
            self.request.send(resp_body + b'\r\n')
            if debuglevel > 0: print("response body: %x" % len(resp_body))
            self.request.send(b'0\r\n')
        else:
            self.request.send(resp_body)
            if debuglevel > 0: print("response body: %d" % len(resp_body))
        self.request.send(b'\r\n')

        # close the connection for the remot host
        self.shadowsocks.close() 

        # self.close_connection = resp.will_close
        self.close_connection = True
        print("[_forward_response]", (resp.code, resp.reason, self.requestline))

    def _forward(self):

        result = urlparse(self.path)
        netloc, path, query, fragment = result.netloc, result.path, result.query, result.fragment

        if not path: path = '/'
        if query: path += '?' + query

        new_requestline = "%s %s %s\r\n" % (self.command, path, self.request_version)
        new_requestline = new_requestline.encode('ascii')

        print("[_forward]", new_requestline)

        host, port = self._get_hostport(netloc)

        if not self.shadowsocks or self.shadowsocks.fileno() == -1:
            self.shadowsocks = self._tunnel(host, port)
        
        if not self.shadowsocks:
            self.send_error(HTTPStatus.BAD_GATEWAY)
            self.close_connection = True
            return    

        try:
            self._forward_request(new_requestline, debuglevel=self.debuglevel)
            self._forward_response(debuglevel=self.debuglevel)
        except Exception as err:
            if self.debuglevel > 0: print(err)
            try:
                self.send_error(HTTPStatus.BAD_GATEWAY, message=repr(err))
            except:
                pass

    def do_GET(self):
        self._forward()
        
    def do_POST(self):
        self._forward()

    def do_HEAD(self):
        self._forward()
        
    def do_CONNECT(self):
        if self.debuglevel > 0:
            print("do_CONNECT [%s]" % self.requestline)
        
        host, port = self._get_hostport(self.path)
        
        self.shadowsocks = self._tunnel(host, port)

        self.send_response_only(200)
        self.end_headers()

        if self.shadowsocks:
            self._socket_forward()
        else:
            self.send_error(HTTPStatus.BAD_GATEWAY)
