from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

PORT = 5003

class ShutdownRequestHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		self.send_response(200, "Shutdown initiated")

		if self.path == "/shutdown":
			def server_shutdown(server):
				server.shutdown()
			Thread(target=server_shutdown, args = (self.server, ))
		

class HTTPShutdownServer:
	def __init__(self, address="", port=PORT):
		self.server = HTTPServer((address, port), ShutdownRequestHandler)
	
	def run(self):
		self.server.serve_forever()
