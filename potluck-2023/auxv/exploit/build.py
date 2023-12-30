import struct
import subprocess
import os
from pathlib import Path


def p16(x):
    return struct.pack('<H', x)


def p32(x):
    return struct.pack('<I', x)


def p64(x):
    return struct.pack('<Q', x)


if __name__ == '__main__':
    payload_raw_path = Path('payload_raw')
    subprocess.check_call(['nasm', 'payload.asm', '-o', payload_raw_path])
    payload_raw_sz = payload_raw_path.stat().st_size
    payload_raw = payload_raw_path.read_bytes()

    start = 0xb0
    vaddr = 0x200_000
    dynamic_size = 0x20
    dynamic_off = start + payload_raw_sz
    mapped_sz = dynamic_off + dynamic_size

    dynamic_name = b'.dynamic\x00'
    shstrtab_name = b'.shstrtab\x00'
    shstrtab_size = len(dynamic_name + shstrtab_name)

    with open('payload', 'wb') as f:
        # ELF identifier
        f.write(b''.join([
            b'\x7fELF',
            b'\x02',             # 64-bit binary
            b'\x01',             # little-endian binary
            b'\x01',             # current ELF version
            b'\x00\x00',         # no specific ABI
            b'\x00' * 7,         # padding
        ]))
        # the rest of the ELF header
        f.write(b''.join([
            p16(0x3),                             # ET_EXEC
            p16(0x3e),                            # EM_X86_64
            p32(0x1),                             # current ELF version (once again)
            p64(vaddr + start),                   # entry point (virtual address)
            p64(0x40),                            # program headers start
            p64(mapped_sz + shstrtab_size),       # program sections start
            p32(0x0),                             # no flags
            p16(0x40),                            # ELF header size
            p16(0x38),                            # program header size
            p16(0x2),                             # program header count
            p16(0x40),                            # section header size
            p16(0x2),                             # section header count
            p16(0x1),                             # string table section
        ]))
        # the payload proper (also the .init section)
        page = 0x1000
        f.write(b''.join([
            p32(0x1),            # PT_LOAD
            p32(0x5),            # RX
            p64(0),              # the payload start in the file
            p64(vaddr),          # virtual address
            p64(vaddr),          # physical address (identical to the virtual one)
            p64(mapped_sz),      # the payload size in the file
            p64(mapped_sz),      # the payload size in memory
            p64(0x1000),         # align to page size
        ]))
        # the dynamic table
        f.write(b''.join([
            p32(0x2),                  # PT_DYNAMIC
            p32(0x4),                  # R
            p64(dynamic_off),          # the payload start in the file
            p64(vaddr + dynamic_off),  # virtual address
            p64(vaddr + dynamic_off),  # physical address
            p64(dynamic_size),         # the dynamic size in the file
            p64(dynamic_size),         # the dynamic size in memory
            p64(0x1),                  # no alignment
        ]))

        f.write(payload_raw)
        # the dynamic table
        f.write(b''.join([
            p64(0x6),           # DT_SYMTAB
            p64(0x0),           # fake value
            p64(0xc),           # DT_INIT
            p64(vaddr + start), # payload address
        ]))
        # the string table for section names
        f.write(b''.join([
            dynamic_name,
            shstrtab_name,
        ]))
        # the dynamic section header
        f.write(b''.join([
           p32(0x0),                 # the section name
           p32(0x6),                 # SHT_DYNAMIC
           p64(0x2),                 # SHF_ALLOC
           p64(vaddr + dynamic_off), # virtual address
           p64(dynamic_off),         # the file offset
           p64(dynamic_size),        # the section size
           p32(1),                   # link to .shstrtab
           p32(0),                   # extra info
           p64(0),                   # alignment
           p64(0),                   # entry size
        ]))
        # the strings section header
        f.write(b''.join([
           p32(len(dynamic_name)),   # the section name
           p32(0x3),                 # SHT_STRTAB
           p64(0x0),                 # no flags
           p64(0),                   # virtual address
           p64(mapped_sz),           # the file offset
           p64(shstrtab_size),       # the section size
           p32(0),                   # section header table index link
           p32(0),                   # extra info
           p64(0),                   # alignment
           p64(0),                   # entry size
        ]))

    os.chmod('payload', 0o777)
