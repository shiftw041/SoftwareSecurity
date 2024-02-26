import hashlib
# 目标结果
p = "\x7c\xcc\x02\xc4\x02\x19\xc5\xc6\x52\x2a\x37\x74\x99\xa9\x60\xec"
result = "7ccc02c40219c5c6522a377499a960ec"

# 枚举密码
class enddd(Exception):
      pass
try:
      for char in range(256):
            password = chr(char)+'3173711194034543fb6d58060b698fd99b2587a0fefd0ff420abaaaff70b594'+'\0'*64*3
            print("try:", char)
            # 统一转换为小写，md5码其实是128位二进制以十六进制字符串形式给出
            md5 = hashlib.md5(password.encode('utf-8')).hexdigest().lower()
            if md5 == result:
                print("flag is zhengde:", chr(char))
                raise enddd()
      print("Password not found.")       

except enddd:
      pass
'''
off-by-one vulnerability单字节缓冲区溢出漏洞
观察发现buf多复制了data一个字节，那么这个字节将会溢出到text的第一位
而md5的输入是0x100位text，所以只需要爆破第一位就好
结果是4
那么输入的第0x21位为4即可
'''