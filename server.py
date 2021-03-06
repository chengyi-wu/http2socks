import socket
from socketserver import ThreadingMixIn
from handler import RelayRequestHandler
import logging
import sys
import time
import threading
from http.server import HTTPServer

logger = logging.getLogger('RelayProxyServer')

# class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
#     daemon_threads = True
class RelayProxyServer(ThreadingMixIn, HTTPServer):
    '''Copy of Python 3.7 ThreadingHTTPServer
    '''
    daemon_threads = True
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        self.openrequests = []
        self.debuglevel = 0
        self.proxy = None
        super(RelayProxyServer, self).__init__(server_address, RequestHandlerClass, bind_and_activate)

    def process_request(self, request, client_address):
        """Overridden
        same as ThreadingTCPServer.process_request
        """
        self.openrequests.append(request.fileno())
        super(RelayProxyServer, self).process_request(request, client_address)

    def close_request(self, request):
        """Overridden
        same as ThreadingTCPServer.close_request
        """
        self.openrequests.remove(request.fileno())
        super(RelayProxyServer, self).close_request(request)

    def server_activate(self):
        """Overridden
        adding a timer thread wakes up every one second and print status
        """
        self.timer = threading.Thread(target=self._timer_event)
        self.timer.daemon = True
        self.timer_timeout = 10
        self.timer.start()

        super(RelayProxyServer, self).server_activate()

    def _timer_event(self):
        """timer
        wakes up every second and print the stauts of the server
        """
        while True:
            time.sleep(self.timer_timeout)
            print("[RelayProxyServer] [%s] Open Requests = %d : %s" % (time.strftime("%H:%M:%S"), len(self.openrequests), repr(self.openrequests)))

def main(host:str, port:int, proxy = None, level=logging.INFO, debuglevel=0):
    logging.basicConfig(level=level)
    svr_class = RelayProxyServer
    svr_class.allow_reuse_address = True
    # svr = socketserver.TCPServer((host, port), sockshandler.SocksHandler)
    svr = svr_class((host, port), RelayRequestHandler)
    
    svr.debuglevel = debuglevel
    svr.proxy = proxy
    logger.info("Listening @ %s:%d" %(host, port))
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
    debuglevel = 0
    for arg in argv:
        if arg.lower() == '-d':
            argv.remove(arg)
            debuglevel = 1
            break
    if debuglevel > 0:
        print("Lauch in debug mode")
    if len(argv) % 2 != 0:
        print("Incorrect parameneters")
        exit(-1)
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
    main(host, port, proxy = (proxyhost, proxyport), level=logging.INFO, debuglevel=debuglevel)
    