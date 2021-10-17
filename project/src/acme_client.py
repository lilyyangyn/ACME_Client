from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography import x509
from cryptography.x509.oid import NameOID

import json
import base64
import requests
import hashlib
import time 

from dns_server import DNSACMEServer
from http_challenge_server import HTTPChallengeServer
from https_cert_server import HTTPSCertServer
from http_shutdown_server import HTTPShutdownServer

import argparse
import os

ELLIPTI_CURVE = "P-256"
X_Y_LENGTH = 32
R_S_LENGTH = 32

CHALLENGE_TYPE_DNS01 = "dns01"
CHALLENGE_TYPE_HTTP01 = "http01"

CHALLENGE_TYPE_MAPPING = {
	CHALLENGE_TYPE_DNS01: "dns-01",
	CHALLENGE_TYPE_HTTP01: "http-01"
}

CERT_FILE = os.path.join( os.getcwd(), 'certificate.pem' )
KEY_FILE = os.path.join( os.getcwd(), 'privKey.pem' )
PEBBLE_CERT_FILE = os.path.join( os.getcwd(), 'pebble.minica.pem' )

def _KeyGen():
	# Generate key-pair based on Elliptic Curve NIST P-256
	priv_key = ec.generate_private_key(ec.SECP256R1())
	return priv_key

def _base_64_encode(raw_text):
	# base64url-encode, url-safe
	# Trailing '=' characters MUST be stripped
	text_url_safe_encoded = base64.urlsafe_b64encode(raw_text).decode("utf8")
	return text_url_safe_encoded.rstrip('=')

def _sign_JSON(priv_key, sig_alg, message):
	DER_signature = priv_key.sign(message, sig_alg)
	r, s = decode_dss_signature(DER_signature)
	# 64 bytes signature for P-256
	r_bytes = r.to_bytes(R_S_LENGTH, byteorder="big")
	s_bytes = s.to_bytes(R_S_LENGTH, byteorder="big")
	return r_bytes+s_bytes


class ACMEClient(object):
	def __init__(self, challenge_type, dir_url, record, domains, revoke):
		self.challenge_type = challenge_type
		self.dir_url = dir_url
		self.record = record
		self.domain_list = domains
		self.should_revoke = revoke

		self.client_header = { "User-Agent": "NetSec-ACME-Client" }
		self.jose_header = { "Content-Type": "application/jose+json" }
		self.jose_header.update(self.client_header)

	def run(self):
		# Get the url directory
		print("Fetching the ACME directory...")
		self.get_directory()
		print("Fetching the ACME directory. Success.")
		# Get the nonce for initial request
		print("Getting the initial nonce...")
		self.get_nonce()
		print("Getting the initial nonce. Success.")

		# Create a new account
		print("Creating a new ACME account...")
		new_account_resp = self.create_account()
		assert new_account_resp.status_code in [200, 201], "Fail to create a new account!"
		if new_account_resp.status_code == 200:
			print("The account already exist")
		elif new_account_resp.status_code == 201:
			print("A new account created!")
		self.account_url = new_account_resp.headers["Location"]
		print("Creating a new ACME account. Success.")

		# Submit a new order
		print("Submitting a new order...")
		new_order_resp = self.submit_order("dns")
		assert new_order_resp.status_code == 201, "Fail to submit a new order!"
		print("Submit the order successfully!")
		order_url = new_order_resp.headers["Location"]
		new_order_json = new_order_resp.json()
		if new_order_json["status"] == "pending":
			# TODO: check how to deal with other status
			authorizations = new_order_json["authorizations"]
			finalize_url = new_order_json["finalize"]
		print("Submitting a new order. Success.")
		
		# Solve Challenges
		print("Solving challenges...")
		challenges = []
			# Fetch challenges and pre-process
		for authorization_url in authorizations:
			challenge_fetch_resp = self._signed_and_send_request(
				url=authorization_url,
				kid=self.account_url,
			)
			assert challenge_fetch_resp.status_code == 200, "Fail to fetch challenges from {}".format(authorization_url)
			challenge = {"domain": challenge_fetch_resp.json()["identifier"]["value"]}
			for c in challenge_fetch_resp.json()["challenges"]:
				if c["type"] == CHALLENGE_TYPE_MAPPING[self.challenge_type]:
					challenge["token"] = c["token"]
					challenge["url"] = c["url"]
					break
			challenges.append(challenge)
			# solve challenges
		self.solve_challenge(challenges)
		print("Solving challenges. Success.")

		# Finalize the order
		print("Finalizing the order...")
		finalize_order_resp = self.finalize_order(finalize_url)
		assert finalize_order_resp.status_code == 200, "CSR is rejected!"
		order_status = finalize_order_resp.json()["status"]
		order_check_resp = finalize_order_resp
		while order_status != "valid":
			assert order_status != "invalid", "Invalid Order. The certificate will not be issued!"
			time.sleep(3)
			order_check_resp = self._signed_and_send_request(url=order_url, kid=self.account_url)
			order_status = order_check_resp.json()["status"]
		cert_url = order_check_resp.json()["certificate"]
		print("Finalizing the order. Success!")

		# Download Cert
		print("Downloading the certificate...")
		cert_resp = self._signed_and_send_request(url=cert_url, kid=self.account_url)
		cert = cert_resp.text.encode('utf-8')
		print("Downloading the certificate. Success.")
			# Writing the cert to the file
		print("Wrting the certificate to the file...")
		with open(CERT_FILE, "wb+") as cert_file:
			cert_file.write(cert)
		print("Wrting the certificate to the file. Success.")
			# Revoke Cert if required
		if self.should_revoke:
			print("Revoking the certificate...")
			revoke_resp = self.revoke_cert(cert)
			assert revoke_resp.status_code == 200, "Fail to revoke the certificate!"
			print("Revoking the certificate. Success.")

			

	def get_directory(self):
		resp = requests.get(
			url=self.dir_url,
			headers=self.client_header,
			verify=PEBBLE_CERT_FILE
		)
		self.directory_data = resp.json()
		return self.directory_data
		
	def get_nonce(self, url=None):
		if not url:
			url = self.directory_data["newNonce"]
		resp = requests.head(
			url=url, 
			headers=self.client_header,
			verify=PEBBLE_CERT_FILE
		)
		self.nonce = resp.headers['Replay-Nonce']
		return resp.headers['Replay-Nonce']

	def create_account(self, url=None):
		if not url:
			url = self.directory_data['newAccount']

		self.priv_key = _KeyGen()
		self.sig_alg = ec.ECDSA(hashes.SHA256())
		# pub_key = self.priv_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
		# # The first octet of the OCTET STRING indicates whether the key is compressed or uncompressed
		# # The uncompressed form is indicated by 0x04
		# Q_x = pub_key[1:33]
		# Q_y = pub_key[33:65]
		pub_num = self.priv_key.public_key().public_numbers()
		Q_x = _base_64_encode(pub_num.x.to_bytes(X_Y_LENGTH, byteorder="big"))
		Q_y = _base_64_encode(pub_num.y.to_bytes(X_Y_LENGTH, byteorder="big"))

		jwk = {
			"kty": "EC",
			"crv": ELLIPTI_CURVE,
			"x": Q_x,
			"y": Q_y,
			"use": "sig"
		}
		payload = {
			"termsOfServiceAgreed": True,
		}
		self.thumbprint = _base_64_encode(hashlib.sha256(json.dumps({
			"crv": "P-256",
			"kty": "EC",
			"x": Q_x,
			"y": Q_y
		}, separators=(',',':')).encode('utf8')).digest())


		return self._signed_and_send_request(
			url=url, 
			jwk=jwk,
			payload=payload
		)

	def submit_order(self, challenge_type, url=None):
		if not url:
			url = self.directory_data["newOrder"]

		identifiers = []
		for domain in self.domain_list:
			identifiers.append({
				"type": challenge_type,
				"value": domain
			})
		payload = { "identifiers": identifiers }

		return self._signed_and_send_request(
			url=url,
			kid=self.account_url,
			payload=payload
		)
	
	def solve_challenge(self, challenges):
		pending_for_poll = []
		challInfo = []
		for challenge in challenges:
			key_auth = "{0}.{1}".format(challenge["token"], self.thumbprint)

			if self.challenge_type == CHALLENGE_TYPE_DNS01:
				challInfo.append({
					"domain": challenge["domain"],
					"keyAuthDigest": _base_64_encode(hashlib.sha256(key_auth.encode('utf8')).digest())
				})
			elif self.challenge_type == CHALLENGE_TYPE_HTTP01:
				challInfo.append({
					"domain": challenge["domain"],
					"token": challenge["token"],
					"keyAuth": key_auth
				})

		if self.challenge_type == CHALLENGE_TYPE_DNS01:
			self.dns_server = DNSACMEServer(self.domain_list, self.record, challInfo)
			self.dns_server.start_thread()
			self.http_challenge_server = None
		elif self.challenge_type == CHALLENGE_TYPE_HTTP01:
			self.dns_server = DNSACMEServer(self.domain_list, self.record)
			self.dns_server.start_thread()
			self.http_challenge_server = HTTPChallengeServer(challInfo, address=self.record)
			self.http_challenge_server.start_thread()
		
		for challenge in challenges:
			status_resp = self._signed_and_send_request(
				url=challenge["url"],
				payload={},
				kid=self.account_url
			)
			assert status_resp.status_code == 200, "Fail to respond the challenge"
			assert status_resp.json()["status"] != "invalid", "Invalid challenge! The certificate will not be issued."
			if status_resp.json()["status"] != "valid":
				pending_for_poll.append(challenge["url"])
		
		idx = -1
		while len(pending_for_poll) > 0:
			time.sleep(1)
			idx = (idx + 1) % len(pending_for_poll)
			status_resp = self._signed_and_send_request(
				url=pending_for_poll[idx],
				kid=self.account_url
			)
			assert status_resp.status_code == 200, "Fail to respond the challenge"
			assert status_resp.json()["status"] != "invalid", "Invalid challenge! The certificate will not be issued."
			if status_resp.json()["status"] == "valid":
				pending_for_poll.remove(pending_for_poll[idx])
		
		# Clean Up
		self._shutdown_challenge_servers()
	
	def finalize_order(self, url):
		cert_priv_key = _KeyGen()
		# write privkey to file
		print("Wrting the cert private key to the file...")
		with open(KEY_FILE, "wb+") as key_file:
			key_file.write(cert_priv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
		print("Wrting the cert private key to the file. Success.")

		csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name({
			x509.NameAttribute(NameOID.COMMON_NAME, self.domain_list[0])
		})).add_extension(
			x509.SubjectAlternativeName([x509.DNSName(d) for d in self.domain_list]),
			critical=False
		).sign(cert_priv_key, hashes.SHA256())
		
		return self._signed_and_send_request(
			url=url,
			payload={"csr": _base_64_encode(csr.public_bytes(serialization.Encoding.DER))},
			kid=self.account_url
		)
	
	def revoke_cert(self, cert, url=None):
		if not url:
			url = self.directory_data["revokeCert"]

		cert_pem = x509.load_pem_x509_certificate(cert)
		payload = {
			"certificate": _base_64_encode(cert_pem.public_bytes(serialization.Encoding.DER))
		}
		return self._signed_and_send_request(
			url=url, 
			payload=payload,
			kid=self.account_url
		)
	
	def _shutdown_challenge_servers(self):
		if self.challenge_type:
			self.dns_server.stop()
			self.dns_server = None
		if self.http_challenge_server:
			self.http_challenge_server.stop()
			self.http_challenge_server = None

	def _signed_and_send_request(self, url, jwk=None, kid=None, payload=""):
		protected = {
			"alg": "ES256",
			"nonce": self.nonce,
			"url": url
		}
		if jwk:
			protected["jwk"] = jwk
		elif kid:
			protected["kid"] = kid
		else:
			# Must provide jwk / kid
			raise Exception('No jwk or kid found!')

		protected_encoded = _base_64_encode(json.dumps(protected).encode("utf8"))
		if payload == "":
			payload_encoded = ""
		else:
			payload_encoded = _base_64_encode(json.dumps(payload).encode("utf8"))
		signature = _sign_JSON(
			self.priv_key, 
			self.sig_alg,
			"{0}.{1}".format(protected_encoded, payload_encoded).encode("utf8")
		)
		
		jose = {
			"protected": protected_encoded, 
			"payload": payload_encoded,
			"signature": _base_64_encode(signature)
		}

		resp = requests.post(
			url=url,
			json=jose,
			headers=self.jose_header,
			verify=PEBBLE_CERT_FILE
		)
		# print(resp.headers)
		# print(resp.text)
		self.nonce = resp.headers["Replay-Nonce"]

		return resp
		


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="ACME Client")
	parser.add_argument('challenge_type', 
		choices=['dns01', 'http01'], 
		help="(required) The ACME challenge type the client should perform")
	parser.add_argument('--dir', 
		required=True, 
		metavar="DIR_URL",
		help="(required) The directory URL of the ACME server that should be used")
	parser.add_argument('--record', 
		required=True, 
		metavar="IPv4_ADDRESS",
		help="(required) The IPv4 address which must be returned by the DNS server for all A-record queries")
	parser.add_argument('--domain', 
		required=True, 
		action='append',
		metavar="DOMAIN(s)",
		help="(required, multiple) The domain for which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains will be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net")
	parser.add_argument('--revoke',
		action='store_const', 
		const=True, default=False, 
		help="(optional) If present, the application immediately revokes the certificate after obtaining it")

	params = parser.parse_args()

	acme_client = ACMEClient(
		challenge_type=params.challenge_type,
		dir_url=params.dir,
		record=params.record,
		domains=params.domain,
		revoke=params.revoke)
	acme_client.run()

	cert_server = HTTPSCertServer(CERT_FILE, KEY_FILE)
	cert_server.start_thread()

	HTTPShutdownServer().run()
	cert_server.stop()