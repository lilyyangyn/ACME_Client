from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

PORT = 5002

class HTTPChallengeRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        challenges = self.server.challenges
        
        self.protocol_version = "HTTP/1.1"
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.end_headers()

        for challenge in challenges:
            if self.path == ('/.well-known/acme-challenge/' + challenge["token"]):
                self.wfile.write(bytes(challenge["keyAuth"], "utf8"))

class HTTPChallengeServer:
    def __init__(self, challenges, address="", port=PORT):
        self.server = HTTPServer((address, port), HTTPChallengeRequestHandler)
        self.server.challenges = challenges
    
    def start_thread(self):
        self.thread = Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        
    def stop(self):
        if self.isAlive():
            self.server.shutdown()

    def isAlive(self):
        return self.thread.is_alive()