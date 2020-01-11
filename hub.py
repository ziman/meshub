#!/usr/bin/env python3

import os
import sys
import socket
import struct
import argparse
import logging
import datetime
import collections
from typing import Dict

import protocol

MAX_PACKET_SIZE = 8192
HOST_ADVERT_TIMEOUT_SEC = 60

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

def broadcast_peer(sock, src_peer, packet, hosts):
    log.debug('broadcasting: %s:%d' % src_peer)

    data = protocol.to_bytes(protocol.PACKET_H2C, protocol.Packet_h2c(
        src_addr=src_peer[0],
        src_port=src_peer[1],
        protocol_version=packet.protocol_version,
        session_id=packet.session_id,
    ))

    # make a copy because iteration may delete stale entries
    now = datetime.datetime.now()
    for peer, ts_last_advert in list(hosts.items()):
        if (now - ts_last_advert).total_seconds() > HOST_ADVERT_TIMEOUT_SEC:
            log.debug('deleting stale host %s:%d' % peer)
            del hosts[peer]
        elif peer == src_peer:
            pass  # don't echo the packet back to the sender
        else:
            log.debug('  -> %s:%d' % peer)
            sock.sendto(data, peer)

def main_loop(args, sock):
    # hosts map (addr,port) -> ts_last_packet
    hosts : Dict[protocol.Peer, datetime.datetime] = {}

    while True:
        try:
            packet = protocol.receive(sock)
        except protocol.MalformedPacket as e:
            log.debug('skipping malformed packet: %s' % e)
            continue

        if packet.magic != protocol.PACKET_C2H:
            log.debug('non-c2h packet, ignoring')
            continue

        hosts[packet.peer] = datetime.datetime.now()
        broadcast_peer(sock, packet.peer, packet.payload, hosts)

def main(args):
    log.info('starting server at [%s]:%s' % (args.addr, args.port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.addr, args.port))

    try:
        main_loop(args, sock)
    finally:
        log.info('closing server socket')
        sock.close()

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('-a', '--address', dest='addr', default='0.0.0.0')
    ap.add_argument('-p', '--port', type=int, default=3731)
    main(ap.parse_args())
