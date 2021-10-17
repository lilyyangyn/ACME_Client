from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl
from threading import Thread

PORT = 5001

class HTTPSCertServer:
    def __init__(self, certfile, keyfile, address="", port=PORT):
        self.server = HTTPServer((address, port), SimpleHTTPRequestHandler)
        self.server.socket = ssl.wrap_socket(
            self.server.socket, 
            certfile=certfile, 
            keyfile=keyfile, 
            server_side=True
        )
    
    def start_thread(self):
        self.thread = Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        if self.isAlive():
            self.server.shutdown()

    def isAlive(self):
        return self.thread.is_alive()
            