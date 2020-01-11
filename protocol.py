import struct
import socket
import collections
from enum import Enum
from typing import NamedTuple, Tuple, Union, Optional

VERSION : int = 4
MAX_PACKET_SIZE : int = 8192

class Magic(Enum):
    C2H      = 0x01
    H2C      = 0x02
    C2C_PING = 0x04
    C2C_PONG = 0x05
    C2C_AUTH = 0x06
    C2C_DATA = 0x08

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
    magic : Magic
    payload : Optional[Packet]

class MalformedPacket(Exception):
    pass

def _read_c_string(bs : bytes) -> Tuple[str, bytes]:
    nul = bs.find(0)
    if nul < 0:
        raise MalformedPacket('NUL byte not found')

    return bs[:nul].decode('ascii'), bs[nul+1:]

def to_bytes(magic : Magic, packet : Packet) -> bytes:
    if magic is Magic.C2H:
        assert isinstance(packet, Packet_c2h)
        return \
            bytes([magic.value, packet.protocol_version]) \
            + struct.pack('>L', packet.session_id)

    elif magic is Magic.H2C:
        assert isinstance(packet, Packet_h2c)
        return \
            bytes([magic.value]) \
            + socket.inet_aton(packet.src_addr) \
            + struct.pack('>H', packet.src_port) \
            + bytes([int(packet.protocol_version)]) \
            + struct.pack('>L', packet.session_id)

    elif magic is Magic.C2C_PING:
        assert isinstance(packet, Packet_ping)
        return \
            bytes([magic.value]) \
            + packet.payload

    elif magic is Magic.C2C_PONG:
        return bytes([magic.value])

    elif magic is Magic.C2C_AUTH:
        assert isinstance(packet, Packet_auth_enc)
        return \
            bytes([magic.value]) \
            + packet.payload_enc

    elif magic is Magic.C2C_DATA:
        assert isinstance(packet, Packet_data)
        return \
            bytes([magic.value, int(packet.is_encrypted)]) \
            + packet.payload
    else:
        raise MalformedPacket('unknown tx magic: 0x%02x' % magic.value)

def receive(sock : socket.socket) -> Packet_rx:
    try:
        data, peer = sock.recvfrom(MAX_PACKET_SIZE)
        magic, data = Magic(data[0]), data[1:]

        payload : Optional[Packet]
        if magic is Magic.C2H:
            protocol_version = data[0]
            session_id, = struct.unpack('>L', data[1:5])
            payload = Packet_c2h(protocol_version, session_id)

        elif magic is Magic.H2C:
            src_addr = socket.inet_ntoa(data[:4])
            src_port, = struct.unpack('>H', data[4:6])
            protocol_version = data[6]
            session_id, = struct.unpack('>L', data[7:11])
            payload = Packet_h2c(src_addr, src_port, protocol_version, session_id)

        elif magic is Magic.C2C_PING:
            payload = Packet_ping(payload=data)

        elif magic is Magic.C2C_PONG:
            payload = None

        elif magic is Magic.C2C_AUTH:
            payload = Packet_auth_enc(payload_enc=data)

        elif magic is Magic.C2C_DATA:
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

def sendto(
    sock : socket.socket,
    peer : Peer,
    magic : Magic,
    packet : Packet,
) -> None:
    sock.sendto(
        to_bytes(magic, packet),
        peer,
    )
