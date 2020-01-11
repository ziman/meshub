#!/usr/bin/env python3

import os
import sys
import socket
import struct
import argparse
import logging
import datetime
import collections
from typing import Dict, Any, Optional

import protocol

MAX_PACKET_SIZE = 8192
HOST_ADVERT_TIMEOUT_SEC = 60

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

def broadcast_peer(
    sock : socket.socket,
    src_peer : protocol.Peer,
    packet : protocol.Packet_c2h,
    hosts : Dict[protocol.Peer, datetime.datetime],
) -> None:
    log.debug('broadcasting: %s:%d' % src_peer)

    data = protocol.to_bytes(protocol.Magic.H2C, protocol.Packet_h2c(
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

def main_loop(args : Any, sock : socket.socket) -> None:
    # hosts map (addr,port) -> ts_last_packet
    hosts : Dict[protocol.Peer, datetime.datetime] = {}

    while True:
        try:
            packet = protocol.receive(sock)
        except protocol.MalformedPacket as e:
            log.debug('skipping malformed packet: %s' % e)
            continue

        if packet.magic is not protocol.Magic.C2H:
            log.debug('non-c2h packet, ignoring')
            continue

        hosts[packet.peer] = datetime.datetime.now()

        c2h = packet.payload
        assert c2h is not None
        assert isinstance(c2h, protocol.Packet_c2h)

        broadcast_peer(sock, packet.peer, c2h, hosts)

def main(args : Any) -> None:
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
