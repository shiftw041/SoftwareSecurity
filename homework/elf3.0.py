from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")

# excute
challenge_path = "/challenge/elf-crackme-level3.0"
elf = ELF(challenge_path)
p = process(elf.path)

''' 
objdump -R elf-crackme-level3.0查看动态链接表
elf-crackme-level3.0:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
08049ffc R_386_GLOB_DAT    __gmon_start__
0804a00c R_386_JUMP_SLOT   perror@GLIBC_2.0
0804a010 R_386_JUMP_SLOT   puts@GLIBC_2.0
0804a014 R_386_JUMP_SLOT   exit@GLIBC_2.0
0804a018 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
0804a01c R_386_JUMP_SLOT   execve@GLIBC_2.0

objdump -d --section=.plt elf-crackme-level3.0查看plt具体代码
第一个函数其实不用改
.got.plt的第0项反而是.dynamic,但是第一第二项都是0（也许got1got2就是0？）
接下来几个函数都是正确的，就是最后一个函数的跳转地址错了
改0x39c 的aa为a0
然后报错函数没找到，看到了pzj的提示，是cat的路径有问题，换到/usr/bin下执行就没事了
'''

# 接收题目的输出
result = p.recvall()
# 打印题目的输出
print(result)