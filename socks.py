import socket
import struct

class socksocket(socket.socket):
    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, fileno=None):
        super(socksocket, self).__init__(
            family=family,
            type=type,
            proto=proto,
            fileno=fileno
        )
    
    def connect(self, address):
        super(socksocket, self).connect(('127.0.0.1', 1080))
        # self.setblocking()
        print("connect::", address)
        self.__negotiatesocks5(address)

    def __negotiatesocks5(self, address):
        host, port = address
        self.sendall(b'\x05\x02\x00\x02')
        chosenauth = self.recv(2)
        # print(chosenauth)
        req = b"\x05\x01\x00"
        req += b"\x03" + bytes(chr(len(host)) + host, 'utf-8')
        req += struct.pack(">H",port)
        # print(req)
        self.sendall(req)
        resp = self.recv(4)
        # print(resp)
        if resp[3] == 1:
            boundaddr = self.recv(4)
        boundport = self.recv(2)
        # print(boundport)
        boundport = struct.unpack(">H",boundport)[0]
        # print(boundaddr, boundport)