"""Code piece from SocksiPy - Python SOCKS module.

"""

import socket
import struct
import logging

logger = logging.getLogger('socksocket')

_generalerrors = ("success",
		   "invalid data",
		   "not connected",
		   "not available",
		   "bad proxy type",
		   "bad input")

class socksocket(socket.socket):
    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, fileno=None):
        self.socksproxy = None
        self.proxycred = None
        self.addr = None
        super(socksocket, self).__init__(
            family=family,
            type=type,
            proto=proto,
            fileno=fileno
        )

    def set_proxy(self, host, port, username = None, password = None):
        if host:
            if not port:
                port = 1080
            self.socksproxy = (host, port)
        if username and password:
            self.proxycred = (username, password)
    
    def connect(self, address):
        self.addr = address
        if self.socksproxy:
            super(socksocket, self).connect(self.socksproxy)
            self.__negotiatesocks5(address)
        else:
            super(socksocket, self).connect(address)

    def __negotiatesocks5(self, address):
        host, port = address
        if self.proxycred:
            self.send(b'\x05\x02\x00\x02')
        else:
            self.send(b'\x05\x01\x00')
        chosenauth = self.recv(2)
        if chosenauth[0] != 5:
            self.close()
            raise Exception(_generalerrors[1])
        if chosenauth[1] == 0:
            # No authentication is required
            pass
        elif chosenauth[1] == 2:
            # basic username/password authentication
            username, password = self.proxycred
            username = bytes(username, 'utf-8')
            password = bytes(password, 'utf-8')
            self.send(b"\x01" + bytes(chr(len(username))) + username + chr(len(password)) + password)
            authstat = self.recv(2)
            if authstat[0] != 1:
                # Bad response
                self.close()
                raise Exception(_generalerrors[1])
            if authstat[1] != 0:
                # Authentication failed
                self.close()
                raise Exception("Authentication failure")
            # Authentication succeeded
        else:
            self.close()
            raise Exception(_generalerrors[1])
        req = b"\x05\x01\x00"
        req += b"\x03" + bytes(chr(len(host)) + host, 'utf-8')
        req += struct.pack(">H",port)
        logger.debug(req)
        self.send(req)
        resp = self.recv(4)
        if resp[0] != 5:
            self.close()
            raise Exception(_generalerrors[1])
        elif resp[1] != 0:
            self.close()
            raise Exception("Connection failed")
        elif resp[3] == 1:
            boundaddr = self.recv(4)
        elif resp[3] == 3:
            resp = resp + self.recv(1)
            boundaddr = self.recv(resp[4])
        else:
            self.close()
            raise Exception(_generalerrors[1])
        boundport = self.recv(2)
        boundport = struct.unpack(">H",boundport)[0]
        # print(boundaddr, boundport)