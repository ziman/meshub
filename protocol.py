import struct
import socket
import collections
from typing import NamedTuple, Tuple, Union, Optional

VERSION = 4

MAX_PACKET_SIZE = 8192

PACKET_C2H      = 0x01
PACKET_H2C      = 0x02
PACKET_C2C_PING = 0x04
PACKET_C2C_PONG = 0x05
PACKET_C2C_AUTH = 0x06
PACKET_C2C_DATA = 0x08

Peer = Tuple[str, int]

class Packet_h2c(NamedTuple):
    src_addr : str
    src_port : int
    protocol_version : int
    session_id : int

class Packet_c2h(NamedTuple):
    protocol_version : int
    session_id : int

class Packet_ping(NamedTuple):
    payload : bytes

class Packet_auth_enc(NamedTuple):
    payload_enc : bytes

class Packet_data(NamedTuple):
    is_encrypted : bool
    payload : bytes

Packet = Union[
    Packet_h2c,
    Packet_c2h,
    Packet_ping,
    Packet_auth_enc,
    Packet_data
]

class Packet_rx(NamedTuple):
    peer : Peer
    magic : int
    payload : Optional[Packet]

class MalformedPacket(Exception):
    pass

def _read_c_string(bs):
    nul = bs.find(0)
    if nul < 0:
        raise MalformedPacket('NUL byte not found')

    return bs[:nul].decode('ascii'), bs[nul+1:]

def to_bytes(magic, packet):
    if magic == PACKET_C2H:
        return \
            bytes([magic, packet.protocol_version]) \
            + struct.pack('>L', packet.session_id)

    elif magic == PACKET_H2C:
        return \
            bytes([magic]) \
            + socket.inet_aton(packet.src_addr) \
            + struct.pack('>H', packet.src_port) \
            + bytes([int(packet.protocol_version)]) \
            + struct.pack('>L', packet.session_id)

    elif magic == PACKET_C2C_PING:
        return \
            bytes([magic]) \
            + packet.payload

    elif magic == PACKET_C2C_PONG:
        return bytes([magic])

    elif magic == PACKET_C2C_AUTH:
        return \
            bytes([magic]) \
            + packet.payload_enc

    elif magic == PACKET_C2C_DATA:
        return \
            bytes([magic, int(packet.is_encrypted)]) \
            + packet.payload
    else:
        raise MalformedPacket('unknown tx magic: 0x%02x' % magic)

def receive(sock):
    try:
        data, peer = sock.recvfrom(MAX_PACKET_SIZE)
        magic, data = data[0], data[1:]

        payload : Optional[Packet]
        if magic == PACKET_C2H:
            protocol_version = data[0]
            session_id, = struct.unpack('>L', data[1:5])
            payload = Packet_c2h(protocol_version, session_id)

        elif magic == PACKET_H2C:
            src_addr = socket.inet_ntoa(data[:4])
            src_port, = struct.unpack('>H', data[4:6])
            protocol_version = data[6]
            session_id, = struct.unpack('>L', data[7:11])
            payload = Packet_h2c(src_addr, src_port, protocol_version, session_id)

        elif magic == PACKET_C2C_PING:
            payload = Packet_ping(payload=data)

        elif magic == PACKET_C2C_PONG:
            payload = None

        elif magic == PACKET_C2C_AUTH:
            payload = Packet_auth_enc(payload_enc=data)

        elif magic == PACKET_C2C_DATA:
            payload = Packet_data(is_encrypted=bool(data[0]), payload=data[1:])

        else:
            raise MalformedPacket('unknown magic: 0x%02x' % magic)

        return Packet_rx(
            peer=peer,
            magic=magic,
            payload=payload,
        )
    except IndexError as e:
        raise MalformedPacket(str(e))

def sendto(sock, peer, magic, packet=None):
    sock.sendto(
        to_bytes(magic, packet),
        peer,
    )
