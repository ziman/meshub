#!/usr/bin/env python3

import os
import sys
import json
import time
import fcntl
import base64
import socket
import struct
import select
import random
import logging
import argparse
import datetime
import subprocess
import collections
import configparser
from cryptography.fernet import Fernet, InvalidToken

import protocol

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

def str_mac(addr):
    return ':'.join('%02x' % x for x in addr)

def get_address(config, proto):
    address_s = config['tun'].get(proto + '_address')
    if not address_s:
        return None, None

    address, prefix_length_s = address_s.split('/')
    prefix_length = int(prefix_length_s)

    return address, prefix_length

class NullEncryption:
    def encrypt(self, data):
        return data

    def decrypt(self, data):
        return data

class FernetEncryption:
    def __init__(self, key):
        self.fernet = Fernet(key)

    def encrypt(self, data):
        return base64.urlsafe_b64decode(self.fernet.encrypt(data))

    def decrypt(self, data):
        return self.fernet.decrypt(base64.urlsafe_b64encode(data))

class Host:

    STATE_STUN      = 'STUN'
    STATE_AUTH      = 'AUTH'
    STATE_CONNECTED = 'CONN'

    def __init__(self, client, config, sock, tun, routes, peer):
        self.config = config
        self.client = client
        self.sock = sock
        self.tun = tun
        self.routes = routes
        self.peer = peer  # (address, port)
        self.ts_last_packet = datetime.datetime.now()
        self.ts_last_ping = datetime.datetime.now()
        self.state = Host.STATE_STUN

        self.ping_interval = config['vpn'].getfloat('ping_interval_sec', 30)

        enc_scheme = config['encryption'].get('scheme', fallback='fernet')
        if enc_scheme == 'fernet':
            self.cipher = FernetEncryption(config['encryption']['psk'])
        elif enc_scheme == 'null':
            log.warn('using null encryption scheme')
            self.cipher = NullEncryption()
        else:
            raise Exception('unknown encryption scheme: %s' % enc_scheme)

        self.name = None
        self.ipv4_address = None  # bytes, not string
        self.ipv6_address = None  # bytes, not string
        self.rnode = None  # routing node
        self.session_id = None  # remote host's session id

        self.log = logging.getLogger(str(self))

    def __str__(self):
        return self.name or ('%s:%d' % self.peer)

    def seen_packet(self):
        self.ts_last_packet = datetime.datetime.now()

    def process_advertisement(self, packet_payload):
        #self.log.debug('state = %s' % self.state)
        #self.log.debug('advertisement from %s:%d' % self.peer)
        self.seen_packet()

        if packet_payload.session_id != self.session_id:
            self.log.debug('connection needs refreshing, sending auth packet...')
            # remote host has restarted, needs active connection re-establishment
            self.send_auth_packet()
        else:
            #self.log.debug('just iterating')
            # either already connected or a re-try of initial connection
            # just make sure everything is taken care of
            self.iteration()

    def process_packet(self, packet):
        self.seen_packet()

        if packet.magic == protocol.PACKET_C2C_PING:
            #self.log.debug('PING received')

            self.send_packet(protocol.PACKET_C2C_PONG)

        elif packet.magic == protocol.PACKET_C2C_PONG:
            self.log.debug('PONG received')

            if self.state == Host.STATE_STUN:
                self.log.info('starting authentication...')

                self.state = Host.STATE_AUTH
                self.send_auth_packet()

        elif packet.magic == protocol.PACKET_C2C_AUTH:
            self.log.debug('auth packet from %s', packet.peer)
            try:
                plaintext = self.cipher.decrypt(packet.payload.payload_enc)
            except InvalidToken:
                self.log.warn('could not decrypt auth packet')
                return

            doc = json.loads(plaintext.decode('ascii'))

            proto_version = doc.get('version', 0)
            if proto_version != protocol.VERSION:
                log.warn('rejecting AUTH: wrong proto version from %s (got %d, expected %d)' % (
                    doc.get('hostname', str(self)),
                    proto_version,
                    protocol.VERSION,
                ))
                return

            expected_mode = 'tap' if self.client.is_tap else 'tun'
            if doc.get('mode') != expected_mode:
                log.warn(
                    'rejecting AUTH: wrong mode %s (expected %s)',
                    doc.get('mode'),
                    expected_mode
                )
                return

            self.name = doc['hostname']
            self.ipv4_address = doc['address'].get('ipv4') \
                    and socket.inet_pton(socket.AF_INET, doc['address'].get('ipv4'))
            self.ipv6_address = doc['address'].get('ipv6') \
                    and socket.inet_pton(socket.AF_INET6, doc['address'].get('ipv6'))

            if (self.state != Host.STATE_CONNECTED) or (doc['session_id'] != self.session_id):
                # other party's details updated, switch to STATE_CONNECTED
                self.state = Host.STATE_CONNECTED
                self.session_id = doc['session_id']
            
                if not self.client.is_tap:
                    if self.ipv4_address:
                        self.routes[self.ipv4_address] = self

                    if self.ipv6_address:
                        self.routes[self.ipv6_address] = self

                self.log = logging.getLogger(str(self))
                self.log.info('connected!')

            if doc['expected_session_id'] != self.client.session_id:
                # remote host does not seem to have up-to-date info about us
                self.send_auth_packet()

        elif packet.magic == protocol.PACKET_C2C_DATA:
            if self.state != Host.STATE_CONNECTED:
                log.info('data packet from non-connected host %s:%d, refreshing connection' % packet.peer)
                self.send_auth_packet()
                return

            if packet.payload.is_encrypted:
                try:
                    plaintext = self.cipher.decrypt(packet.payload.payload)
                except InvalidToken:
                    self.log.warn('could not decrypt data packet')
                    return
            else:
                plaintext = packet.payload.payload

            # for switched networks, remember that this MAC address belongs to this host
            # see process_tap_packet() for packet format reference
            if self.client.is_tap:
                addr_src = plaintext[6:12]
                #self.log.debug('SRC address ' + str_mac(addr_src))
                self.client.routes[addr_src] = self

            #log.debug('writing to interface: %s', str_mac(plaintext))
            self.tun.write(plaintext)

        elif packet.magic == protocol.PACKET_C2H:
            #log.debug('LAN broadcast received from %s', packet.peer)
            self.process_advertisement(packet.payload)

        else:
            log.warn('unknown packet magic: 0x%02x' % packet.magic)

    def send_packet(self, magic, packet=None):
        protocol.sendto(self.sock, self.peer, magic, packet)

    def ping(self):
        self.log.debug('PING %s' % self)
        self.send_packet(
            protocol.PACKET_C2C_PING,
            protocol.Packet_ping(payload=b'')
        )
        self.ts_last_ping = datetime.datetime.now()

    def send_data_packet(self, data, encrypt=True):
        self.send_packet(protocol.PACKET_C2C_DATA,
            protocol.Packet_data(
                is_encrypted=encrypt,
                payload=
                    self.cipher.encrypt(data)
                    if encrypt else
                    data
            )
        )

    def send_auth_packet(self):
        self.log.debug('sending AUTH in state %s to peer %s', self.state, self.peer)

        hostname = self.config['vpn'].get('hostname', fallback='client')
        ipv4_address, _prefix_length = get_address(self.config, 'ipv4')
        ipv6_address, _prefix_length = get_address(self.config, 'ipv6')

        payload = json.dumps({
            'version': protocol.VERSION,
            'hostname': hostname,
            'address': {
                'ipv4': ipv4_address,
                'ipv6': ipv6_address,
            },
            'mode': 'tap' if self.client.is_tap else 'tun',
            'expected_session_id': self.session_id,
            'session_id': self.client.session_id,
        }).encode('ascii')

        self.send_packet(
            protocol.PACKET_C2C_AUTH,
            protocol.Packet_auth_enc(
                payload_enc=self.cipher.encrypt(payload)
            )
        )

    def iteration(self):
        #self.log.debug('iteration, state=%s' % self.state)

        if self.state == Host.STATE_STUN:
            for _ in range(4):
                self.ping()

        elif self.state == Host.STATE_AUTH:
            self.send_auth_packet()

        elif self.state == Host.STATE_CONNECTED:
            if (datetime.datetime.now() - max(self.ts_last_ping, self.ts_last_packet)).total_seconds() > self.ping_interval:
                self.ping()

    def close_connection(self):
        self.log.info("closing connection %s:%d" % self.peer)
        if self.ipv4_address in self.routes:
            del self.routes[self.ipv4_address]
        if self.ipv6_address in self.routes:
            del self.routes[self.ipv6_address]

class Tun(object):
    def __init__(self, name='tun', tap=False):
        if name.startswith('/'):
            self.fd = os.open(name, os.O_RDWR)
            self.ifname = name.split('/')[-1]
        else:
            mode = IFF_TAP if tap else IFF_TUN
            self.fd = os.open("/dev/net/tun", os.O_RDWR)
            ifs = fcntl.ioctl(self.fd, TUNSETIFF, struct.pack("16sH", name.encode('ascii'), mode | IFF_NO_PI))
            self.ifname = ifs[:16].strip(b"\x00").decode('ascii')

        log.debug("tun interface %s created" % self.ifname)

    def __str__(self):
        return self.ifname

    def write(self, data):
        length = os.write(self.fd, data)
        if length != len(data):
            raise Exception('could only write %d bytes of %d' % (length, len(data)))

    def read(self):
        return os.read(self.fd, protocol.MAX_PACKET_SIZE)

    def close(self):
        os.close(self.fd)

class Client:
    def __init__(self, config, sock, tun, peer_hub):
        self.config = config
        self.sock    = sock
        self.peer_hub = peer_hub
        self.hosts_by_peer = dict()  # peer -> Host
        self.routes = dict()  # vpn address (ipv4 or ipv6) -> Host
        self.tun = tun
        self.is_tap = (config['tun'].get('type', 'tun') == 'tap')
        self.ts_last_advert = datetime.datetime.now()
        self.ts_last_maintenance = datetime.datetime.now()
        self.session_id = random.getrandbits(32)

        self.maintenance_interval_sec = config['vpn'].getfloat('maintenance_interval_sec', 10)

        self.unencrypted_tcp_ports = set()
        for port_s in config['encryption'].get('unencrypted_tcp_ports', '').split(','):
            if port_s.strip():
                self.unencrypted_tcp_ports.add(int(port_s.strip()))

    def advertise_hub(self):
        protocol.sendto(
            self.sock,
            self.peer_hub,
            protocol.PACKET_C2H,
            protocol.Packet_c2h(
                protocol_version=protocol.VERSION,
                session_id=self.session_id
            ),
        )

    def advertise_lan(self):
        for port_s in self.config['socket'].get('lan_advert_ports', fallback='').split(','):
            if port_s:
                port = int(port_s.strip())
            else:
                continue

            protocol.sendto(
                self.sock,
                ('255.255.255.255', port),
                protocol.PACKET_C2H,
                protocol.Packet_c2h(
                    protocol_version=protocol.VERSION,
                    session_id=self.session_id
                ),
            )

    def advertise_if_needed(self):
        interval = self.config['hub'].getfloat('advert_interval_sec', fallback=60)
        if (datetime.datetime.now() - self.ts_last_advert).total_seconds() > interval:
            self.advertise_hub()
            self.advertise_lan()
            self.ts_last_advert = datetime.datetime.now()

    def get_host(self, peer):
        host = self.hosts_by_peer.get(peer)

        if host is None:
            host = Host(self, self.config, self.sock, self.tun, self.routes, peer)
            self.hosts_by_peer[peer] = host

        return host

    def process_packet(self, packet):
        if packet.magic == protocol.PACKET_H2C:
            peer = (packet.payload.src_addr, packet.payload.src_port)
            host = self.get_host(peer)
            host.process_advertisement(packet.payload)

        else:
            host = self.get_host(packet.peer)
            host.process_packet(packet)

    def purge_dead_hosts(self):
        now = datetime.datetime.now()
        timeout = self.config['vpn'].getfloat('ping_timeout_sec', 300)
        for host in list(self.hosts_by_peer.values()):
            if (now - host.ts_last_packet).total_seconds() > timeout:
                log.debug('closing host %s for inactivity' % host)
                host.close_connection()
                del self.hosts_by_peer[host.peer]

    def process_udp_packet(self, packet):
        #log.debug('packet: %s' % (packet,))
        try:
            self.process_packet(packet)
        except InvalidToken as e:
            self.log.warn('could not authenticate packet: %s' % e)

    def maintenance(self):
        self.purge_dead_hosts()

        for host in self.hosts_by_peer.values():
            host.iteration()

        self.advertise_if_needed()

    def process_tap_packet(self, packet):
        addr_dst = packet[:6]
        host = self.routes.get(addr_dst)
        if host:
            #log.debug('TAP packet for %s goes to %s', str_mac(addr_dst), host)
            host.send_data_packet(packet, encrypt=True)
        else:
            # dest unknown, broadcast it
            #log.debug('broadcast TAP packet for %s', str_mac(addr_dst))
            for host in self.hosts_by_peer.values():
                #log.debug('sending it to %s', host)
                host.send_data_packet(packet, encrypt=True)

    def process_tun_packet(self, packet):
        #log.debug('tun packet: %s' % packet)

        version = (packet[0] >> 4) & 0x0F  # IP version
        if version == 4:
            addr_dst = packet[16:20]
            #addr_s = socket.inet_ntop(socket.AF_INET, addr_dst)

            header_length = 4 * (packet[0] & 0x0F)  # in bytes
            is_tcp = (packet[9] == 0x06)
            if is_tcp:
                src_port, dst_port = struct.unpack('>HH', packet[header_length:header_length+4])
            else:
                src_port, dst_port = None, None
        elif version == 6:
            addr_dst = packet[24:40]
            #addr_s = socket.inet_ntop(socket.AF_INET6, addr_dst)

            is_tcp = (packet[6] == 0x06)
            if is_tcp:
                src_port, dst_port = struct.unpack('>HH', packet[40:44])
            else:
                src_port, dst_port = None, None
        else:
            log.warn('unknown IP version: 0x%02x' % version)
            return
        
        host = self.routes.get(addr_dst)
        #log.debug('routing packet for %s to %s' % (addr_s, host))
        if host:
            if is_tcp and ((src_port in self.unencrypted_tcp_ports) or (dst_port in self.unencrypted_tcp_ports)):
                host.send_data_packet(packet, encrypt=False)
            else:
                host.send_data_packet(packet, encrypt=True)

    def main_loop(self):
        select_timeout_sec = self.config['socket'].getfloat(
            'select_interval_sec', fallback=5
        )

        # first, advertise ourselves
        for _ in range(2):
            self.advertise_hub()
            self.advertise_lan()

        while True:
            rs, ws, xs = select.select(
                [self.tun.fd, self.sock.fileno()],
                [],[],
                select_timeout_sec
            )
            for fd in rs:
                if fd == self.sock.fileno():
                    # network traffic
                    packet = protocol.receive(self.sock)
                    self.process_udp_packet(packet)
                elif fd == self.tun.fd:
                    # tun traffic
                    packet = self.tun.read()
                    if self.is_tap:
                        self.process_tap_packet(packet)
                    else:
                        self.process_tun_packet(packet)
                else:
                    # generic timeout
                    pass

            now = datetime.datetime.now()
            if (now - self.ts_last_maintenance).total_seconds() > self.maintenance_interval_sec:
                self.ts_last_maintenance = now
                self.maintenance()

def setup_tun(config):
    tun_name = config['tun'].get('interface', fallback='tun%d')
    is_tap = (config['tun'].get('type', 'tun') == 'tap')

    tun = Tun(
        name=tun_name,
        tap=is_tap,
    )

    hostname = config['vpn'].get('hostname', fallback='client')

    script = config['scripts'].get('tun_setup')
    if script:
        subprocess.check_call(
            script,
            shell=True,
            env={
                'hostname': hostname,
                'iface': tun.ifname,
            }
        )

    script = config['scripts'].get('tun_setup_ipv4')
    if script:
        address, prefix_length = get_address(config, 'ipv4')

        subprocess.check_call(
            script,
            shell=True,
            env={
                'hostname': hostname,
                'iface': tun.ifname,
                'addr': address,
                'prefixlen': str(prefix_length),
            }
        )

    script = config['scripts'].get('tun_setup_ipv6')
    if script:
        address, prefix_length = get_address(config, 'ipv6')

        subprocess.check_call(
            script,
            shell=True,
            env={
                'hostname': hostname,
                'iface': tun.ifname,
                'addr': address,
                'prefixlen': str(prefix_length),
            }
        )

    return tun

def main(args):
    config = configparser.ConfigParser()
    config.read(args.config)
    if 'vpn' not in config:
        config['vpn'] = {}
    if 'socket' not in config:
        config['socket'] = {}

    tun = setup_tun(config)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if config['socket'].get('lan_advert_ports', fallback=''):
        # enable broadcast on socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind((
        config['socket'].get('address', fallback='0.0.0.0'),
        config['socket'].getint('port', fallback=3731),
    ))

    hub = (
        config['hub'].get('address'),
        config['hub'].getint('port', fallback=3731),
    )

    try:
        # restart the VPN after network outages etc.
        while True:
            try:
                client = Client(config, sock, tun, hub)
                client.main_loop()
            except OSError:
                # log error and restart the client
                log.exception("client died, restarting")

            log.info('sleeping before the next attempt...')
            time.sleep(config['vpn'].getfloat('restart_delay_sec', fallback=10))
    finally:
        tun.close()
        sock.close()

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('config')
    main(ap.parse_args())
