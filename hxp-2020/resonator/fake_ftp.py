import socketserver


LOCAL_PORT = 9000


class FakeFTP(socketserver.StreamRequestHandler):
    def _send(self, cmd):
        print(f'Sent "{cmd.decode()}"')
        self.wfile.write(cmd + b'\r\n')

    def handle(self):
        print('A new connection appears!')
        self._send(b'200 oh hai')
        while True:
            cmd = self.rfile.readline().rstrip()
            print(f'Got "{cmd.decode()}"')

            if cmd:
                cmd = cmd.split()[0]

            if cmd in (b'USER', b'TYPE'):
                self._send(b'200 ok')
            elif cmd in (b'SIZE', b'EPSV'):
                self._send(b'500 nope')
            elif cmd == b'PASV':
                self._send(f'227 go to (127,0,0,1,{LOCAL_PORT // 256},{LOCAL_PORT % 256})'.encode())
            elif cmd == b'STOR':
                self._send(b'150 do it!')
                self._send(b'226 nice knowing you')
            elif cmd in (b'', b'QUIT'):
                print('All done!')
                break
            else:
                raise Exception('Unknown command')


with socketserver.TCPServer(('', 31337), FakeFTP) as server:
    print('Welcome to FakeFTP')
    server.serve_forever()