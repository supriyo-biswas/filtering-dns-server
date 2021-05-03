#!/usr/bin/env python3

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import json
import math
import os
import pickle
import redis
import socket
import socketserver
import struct
import sys
import threading
import time

allowed_rdtypes = [
    dns.rdatatype.A,
    dns.rdatatype.AAAA,
    dns.rdatatype.MX,
    dns.rdatatype.NS,
    dns.rdatatype.SOA,
    dns.rdatatype.SRV,
    dns.rdatatype.CNAME,
    dns.rdatatype.PTR,
    dns.rdatatype.CAA,
]


def setup_nameservers():
    if 'nameservers' in config:
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = config['nameservers']


def get_config(conf=None):
    if conf is None:
        config = {}
    else:
        with open(conf) as f:
            config = json.load(f)

    for entry in ['blacklist', 'whitelist']:
        if entry not in config:
            config[entry] = set()
        else:
            config[entry] = {i + '.' for i in config[entry]}

    if 'redis_socket_file' not in config:
        for sockfile in [
            '/var/run/redis/redis.sock',
            '/var/run/redis/redis-server.sock',
        ]:
            if os.path.exists(sockfile):
                config['redis_socket_file'] = sockfile
                break
        else:
            raise Exception('Unable to find redis socket path')

    config.setdefault('ratelimits', {})
    config.setdefault('port', 53)

    config['ratelimits'].setdefault('limit', 20)
    config['ratelimits'].setdefault('limit_burst', 4)
    config['ratelimits'].setdefault('enabled', True)

    return config


def is_blacklisted_host(host):
    while host:
        if host in config['whitelist']:
            return False

        if host in config['blacklist']:
            return True

        index = host.find('.')
        host = host[index + 1 :]

    return False


def ratelimited(ip):
    if '.' in ip[-4:]:
        # convert IPv6-mapped IPv4 address to pure IPv4 address.
        key = 'dns:r:4:%s' % ip[ip.rfind(':') + 1 :]
    else:
        # IPv6 /112 subnet
        key = 'dns:r:6:%s' % socket.inet_pton(socket.AF_INET6, ip)[:-2]

    limit = config['ratelimits']['limit']
    limit_burst = config['ratelimits']['limit_burst']
    ratio = limit / limit_burst

    rl_params = redis_conn.get(key)
    current_time = time.time()

    if rl_params:
        access_time, tokens = pickle.loads(rl_params)
        tokens = min(limit, tokens + limit_burst * (current_time - access_time))
    else:
        access_time, tokens = current_time, limit

    redis_conn.set(key, pickle.dumps((current_time, max(0, tokens - 1))))
    redis_conn.expire(key, math.ceil(ratio))
    return tokens < 1


def dns_query(name, rdclass, rdtype):
    if rdclass != dns.rdataclass.IN or rdtype not in allowed_rdtypes:
        return (dns.rcode.REFUSED, [], [], [])

    try:
        key = 'dns:q:%s:%i' % (name, rdtype)
        cached_result = redis_conn.get(key)
        if cached_result is not None:
            return pickle.loads(cached_result)

        if is_blacklisted_host(name):
            rv = (dns.rcode.NXDOMAIN, [], [], [])
            expiration = 3600
        else:
            result = dns.resolver.query(name, rdtype, raise_on_no_answer=False)
            response = result.response
            rv = (
                response.rcode(),
                response.answer,
                response.authority,
                response.additional,
            )
            expiration = max(60, min(int(time.time() - result.expiration), 3600))
    except dns.exception.DNSException as e:
        expiration = 60
        if isinstance(e, dns.resolver.NXDOMAIN):
            rcode = dns.rcode.NXDOMAIN
        elif isinstance(e, dns.resolver.NoMetaqueries):
            rcode = dns.rcode.REFUSED
        else:
            rcode = dns.rcode.SERVFAIL
        rv = (rcode, [], [], [])

    redis_conn.set(key, pickle.dumps(rv))
    redis_conn.expire(key, expiration)
    return rv


def make_response(query):
    response = dns.message.Message(query.id)
    response.flags = dns.flags.QR | dns.flags.RA | (query.flags & dns.flags.RD)
    response.set_opcode(query.opcode())
    response.question = list(query.question)
    return response


def handle_query(raw_data, client_ip):
    try:
        query = dns.message.from_wire(raw_data)
    except dns.exception.DNSException:
        return

    if len(query.question) != 1:
        return

    if config['ratelimits']['enabled'] and ratelimited(client_ip):
        return

    name = str(query.question[0].name).lower()
    rdtype = query.question[0].rdtype
    rdclass = query.question[0].rdclass
    result = dns_query(name, rdclass, rdtype)
    response = make_response(query)
    response.set_rcode(result[0])
    response.answer = result[1]
    response.authority = result[2]
    response.additional = result[3]

    return response


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        raw_data, socket = self.request
        response = handle_query(raw_data, self.client_address[0])

        if response is None:
            return

        raw_response = response.to_wire()
        if len(raw_response) <= 512:
            socket.sendto(raw_response, self.client_address)
        else:
            response.flags |= dns.flags.TC
            socket.sendto(response.to_wire()[:512], self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        socket = self.request

        try:
            query_length_bytes = socket.recv(2)
            query_length = struct.unpack('!H', query_length_bytes)
            raw_data = socket.recv(query_length[0])
            response = handle_query(raw_data, self.client_address[0])

            if response is not None:
                raw_response = response.to_wire()
                response_length_bytes = struct.pack('!H', len(raw_response))
                socket.send(response_length_bytes + raw_response)
        except (struct.error, OSError):
            pass
        finally:
            socket.close()


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    pass


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def run_server():
    for server_class in [ThreadedUDPServer, ThreadedTCPServer]:
        server_class.allow_reuse_address = True
        server_class.address_family = socket.AF_INET6

    udp_server = ThreadedUDPServer(('', config['port']), UDPHandler)
    tcp_server = ThreadedTCPServer(('', config['port']), TCPHandler)
    udp_server_thread = threading.Thread(target=udp_server.serve_forever)
    tcp_server_thread = threading.Thread(target=tcp_server.serve_forever)
    try:
        for thread in [udp_server_thread, tcp_server_thread]:
            thread.start()

        for thread in [udp_server_thread, tcp_server_thread]:
            thread.join()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        for server in [udp_server, tcp_server]:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        config = get_config()
    else:
        config = get_config(sys.argv[1])

    redis_conn = redis.StrictRedis(unix_socket_path=config['redis_socket_file'])
    setup_nameservers()
    run_server()
