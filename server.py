import socket
import socketserver
import socksrequesthandler
import logging
import sys

logger = logging.getLogger('server')

def main(host:str, port:int, proxyhost=None, proxyport=None, level=logging.INFO):
    logging.basicConfig(level=level)
    # svr = socketserver.TCPServer((host, port), sockshandler.SocksHandler)
    svr = socketserver.ThreadingTCPServer((host, port), socksrequesthandler.SocksRequestHandler)
    svr.request_queue_size = 128
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
    main(host, port, proxyhost=proxyhost, proxyport=proxyport, level=logging.DEBUG)
    