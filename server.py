import socket
import socketserver
import socksrequesthandler
import logging

def main(level=logging.INFO):
    logging.basicConfig(level=level)
    host = '0.0.0.0'
    port = 2080
    # svr = socketserver.TCPServer((host, port), sockshandler.SocksHandler)
    svr = socketserver.ThreadingTCPServer((host, port), socksrequesthandler.SocksRequestHandler)
    svr.request_queue_size = 128
    logging.info("running @ %s:%d" %(host, port))
    try:
        svr.serve_forever()
    except KeyboardInterrupt:
        svr.shutdown()
    except Exception as e:
        logging.error(str(e))
        svr.shutdown()
    svr.shutdown()
    svr.server_close()

if __name__ == '__main__':
    main(logging.INFO)
    