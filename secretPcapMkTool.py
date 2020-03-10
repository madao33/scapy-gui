from scapy.all import *
import structTest1 as ST
secret_key = "madao233" # 必须是刚好8位字节的密码
secret_data = "Live is like a box of chocolate, you never know what you gona get.-<FORREST GUMP>"
secret_str = ST.des_encrypt(secret_key, secret_data)
ptks = IP(dst = "www.baidu.com")/ICMP()/secret_str
print(ptks.load)
wrpcap("secret.pcap",ptks)