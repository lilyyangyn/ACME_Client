from dnslib.server import DNSServer
from dnslib.fixedresolver import BaseResolver
from dnslib import RR, TXT, A, QTYPE

import copy

PORT = 10053

class DNSFixedResolver(BaseResolver):
    def __init__(self, domains, ip_record, challenges):
        super().__init__()
        self.rrs = []
        for domain in domains:
            self.rrs.append(RR(
                domain,
                rdata=A(ip_record)
            ))
        for challenge in challenges:
            self.rrs.append(RR(
                "_acme-challenge.{0}".format(challenge["domain"]),
                QTYPE.TXT,
                rdata=TXT(challenge["keyAuthDigest"])
            ))
    
    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        # Replace labels with request label
        for rr in self.rrs:
            a = copy.copy(rr)
            a.rname = qname
            reply.add_answer(a)
        return reply
        # reply = request.reply()
        # reply.add_answer(*self.rrs)
        # return reply


class DNSACMEServer:
    def __init__(self, domains, ip_record, challenges=[], address='', port=PORT):
        resolver = DNSFixedResolver(domains, ip_record, challenges)
        self.server = DNSServer(resolver, port=port, address=address)
    
    def start_thread(self):
        self.server.start_thread()
    
    def stop(self):
        if self.isAlive():
            self.server.stop()

    def isAlive(self):
        return self.server.isAlive()

