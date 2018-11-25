import socket
from socketserver import ThreadingMixIn
from handler import SocksRequestHandler
import logging
import sys
import time, threading
from http.server import HTTPServer

logger = logging.getLogger('SocksProxyServer')

class SocksProxyServer(ThreadingMixIn, HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        self.requests = set()
        super(SocksProxyServer, self).__init__(server_address, RequestHandlerClass, bind_and_activate)

    def process_request(self, request, client_address):
        """Overridden
        same as ThreadingTCPServer.process_request
        """
        self.requests.add(request.fileno())
        super(SocksProxyServer, self).process_request(request, client_address)

    def close_request(self, request):
        """Overridden
        same as ThreadingTCPServer.close_request
        """
        self.requests.remove(request.fileno())
        super(SocksProxyServer, self).close_request(request)

    def server_activate(self):
        """Overridden
        adding a timer thread wakes up every one second and print status
        """
        self.timer = threading.Thread(target=self._timer_event)
        self.timer.daemon = True
        self.timer_timeout = 10
        self.timer.start()

        super(SocksProxyServer, self).server_activate()

    def _timer_event(self):
        """timer
        wakes up every second and print the stauts of the server
        """
        while True:
            time.sleep(self.timer_timeout)
            print("[SocksProxyServer] [%s] requests = %d, threads = %d, %s" % (time.strftime("%H:%M:%S"), len(self.requests), threading.activeCount(), repr(self.requests)))

def main(host:str, port:int, proxyhost=None, proxyport=None, level=logging.INFO):
    logging.basicConfig(level=level)
    svr_class = SocksProxyServer
    svr_class.allow_reuse_address = True
    # svr = socketserver.TCPServer((host, port), sockshandler.SocksHandler)
    svr = svr_class((host, port), SocksRequestHandler)
    # svr.request_queue_size = 128
    svr.socksproxy = (proxyhost, proxyport)
    logger.info("running @ %s:%d" %(host, port))
    try:
        svr.serve_forever()
    except KeyboardInterrupt:
        svr.shutdown()
    except Exception as e:
        logger.error(str(e))
        svr.shutdown()
    svr.shutdown()
    svr.server_close()

if __name__ == '__main__':
    argv = sys.argv[1:]
    host = '127.0.0.1'
    port = 8080
    proxy = proxyhost = proxyport = None
    if len(argv) % 2 != 0:
        print("Incorrect parameneters")
    for i in range(0, len(argv), 2):
        k, v = argv[i].lower(), argv[i + 1]
        if k == '-h':
            host = v
        if k == '-p':
            proxy = v
    if ':' in host:
        port = int(host[host.index(':') + 1:])
        host = host[:host.index(':')]
    if proxy and ':' in proxy:
        proxyport = int(proxy[proxy.index(':') + 1:])
        proxyhost = proxy[:proxy.index(':')]
    main(host, port, proxyhost=proxyhost, proxyport=proxyport, level=logging.INFO)
    