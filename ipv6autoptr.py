#!/usr/bin/env python3
"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0


Copyright 2023 Dmitriy Terehin https://github.com/meatlayer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
import argparse
import datetime
import sys
import time
import threading
import traceback
import ipaddress
import socketserver
import struct
import logging
try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)

class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)

IPV6AUTOPTR_VERSION = "0.1"

# Set up subnets for auto ipv6 ptr
subnets = ['2a0a:XXXX::/48', '2a0a:XXXX:0:a000::/64']

D = DomainName('ip6.mydomain.net.')
IP = '122.123.124.125'
IP6 = '2a0a:XXXX:0:a000::125'

TTL = 60 * 5

soa_record = SOA(
    mname=D.ns1,  # primary name server
    rname=D.robot,  # email of the domain administrator
    times=(
        2023120829,  # serial number
        60 * 60 * 1,  # refresh
        60 * 60 * 3,  # retry
        60 * 60 * 24,  # expire
        60 * 60 * 1,  # minimum
    )
)
ns_records = [NS(D.ns1), NS(D.ns2)]
records = {
    D: [A(IP), AAAA(IP6), MX(D.mail), soa_record] + ns_records,
    D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
    D.ns2: [A(IP)],
    D.mail: [A(IP)],
    D.robot: [CNAME(D)],
}

# same func for ipv6 ptr
def dns_response_ipv6ptr(data):
    request = DNSRecord.parse(data)
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    ptrdomain_name = str(request.q.qname).rstrip('.ip6.arpa.')[::-1]
    ptrdomain_name = ptrdomain_name.replace('.', '')
    ipv6_domain = D
    ptr_answerd = str(ptrdomain_name+'.'+ipv6_domain)
    request = DNSRecord.parse(data)

    #if req type = PTR
    if '.ip6.arpa' in qn:
        #print("OK ip6.arpa found")

        if request.q.qtype == '12' or request.q.qtype == QTYPE.PTR or request.q.qtype == 'PTR':

            # IPv6 PTR record name
            ptr_name = str(request.q.qname).rstrip('.ip6.arpa.')[::-1]

            # Split the PTR record name into its individual segments
            segments = ptr_name.split(".")

            # Convert the hexadecimal segments to bytes and join them together
            hex_string = "".join(segments[::1])
            byte_string = bytes.fromhex(hex_string)

            # Create an IPv6 address object from the byte string
            ipv6_addr = ipaddress.IPv6Address(byte_string)

            logging.info("CLIENT REQUEST: " + qn)

            # Search the subnets for a match
            match = False
            for subnet_str in subnets:
                subnet = ipaddress.IPv6Network(subnet_str)
                if ipv6_addr in subnet:
                    match = True
                    logging.info(f"IPV6: {ipv6_addr} found in subnet {subnet} and resolv answer as: {ptr_answerd}")
                    logging.info("SERVER ANSWER: " + ptr_answerd)
                    reply.add_answer(RR(rname=qname, rtype=QTYPE.PTR, rdata=PTR(ptr_answerd), ttl=60))
                    break

            else:
                # If IPV6 found in subnets, return Non-existent Internet Domain Names Definition
                logging.info(f"{ipv6_addr} is not in any of the subnets")
                reply.header.rcode = RCODE.NXDOMAIN

    else:
        # Query not ip6.arpa, return Non-existent Internet Domain Names Definition
        reply.header.rcode = RCODE.NXDOMAIN

    return reply.pack()


def dns_response(data):
    request = DNSRecord.parse(data)
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    if qn == D or qn.endswith('.' + D):

        for name, rrs in records.items():
            if name == qn:
                for rdata in rrs:
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))

        for rdata in ns_records:
            reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

        reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    print("---- Reply:\n", reply)

    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        #print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
        #                                       self.client_address[1]))
        logging.info("%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0], self.client_address[1]))
        #print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

        try:
            data = self.get_data()
            #print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response_ipv6ptr(data))
            #self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0]

    #def get_data(self):
    #    return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Start a IPV6AUTOPTR implemented in Python.')
    parser.add_argument('--port', default=5353, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    parser.add_argument("--verbose", action = "count", default=0, help="Increase verbosity")
    #parser.add_argument('--d', default=logging.INFO, action='store_true', help='Debug mode. Example --d logging.DEBUG, default=logging.INFO')

    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    print("Starting ...")

    servers = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer(('::0', args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer(('::0', args.port), TCPRequestHandler))

    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    else:
        level = logging.WARN

    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=level,
    )

    #if args.d: logging.basicConfig(level=args.d, format='%(asctime)s :: %(levelname)s :: %(message)s')
    #if args.d: logging.basicConfig(level=logging.DEBUG, format='%(asctime)s :: %(levelname)s :: %(message)s')

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':

    header  = "     ___ ______     ____     _   _   _ _____ ___  ____ _____ ____  \n"
    header += "    |_ _|  _ \ \   / / /_   / \ | | | |_   _/ _ \|  _ \_   _|  _ \  \n"
    header += "     | || |_) \ \ / / '_ \ / _ \| | | | | || | | | |_) || | | |_) | \n"
    header += "     | ||  __/ \ V /| (_) / ___ \ |_| | | || |_| |  __/ | | |  _ < \n"
    header += "    |___|_|     \_/  \___/_/   \_\___/  |_| \___/|_|    |_| |_| \_\ \n"
    header += "     powered by Dmitriy Terehin | https://github.com/meatlayer | v %s  \n" %IPV6AUTOPTR_VERSION

    print(header)
    main()
