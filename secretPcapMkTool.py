from scapy.all import *
import secretEncode as SE
import struct
import binascii
import ctypes


if __name__ == '__main__':
    key = "12345678" # 必须是刚好8位字节的密码
    src = "192.168.0.1"
    data = "Live is like a box of chocolate, you never know what you gona get."
    sdata = SE.des_encrypt(key, data)
    print("加密后的数据：", sdata)
    # IP/ICMP协议报文
    raw_data = key + str(sdata, encoding='utf-8')
    print("raw_data:", raw_data)
    ptk1 = IP(dst="192.168.0.102",version=0xf)/ICMP()/Raw(raw_data)
    print("IP version:", ptk1.version)
    ptk2 = IP(dst="www.baidu.com")/data
    ptk3 = IP()/ICMP()/"madao33"   

    wrpcap('secretTest.pcap',ptk1)
    wrpcap('unsecretTest.pcap', ptk2)
    wrpcap('ipTest.pcap', ptk3)
    ptks = rdpcap('secretTest.pcap')
    print(ptks)
    print(type(ptks[0]))
    data = dict()
    for ptk in ptks:
        print("ip version:", ptk.version)
        if (ptk.version == 15) & ptk.haslayer("IP"): # 未加密
            print(ptk)
            payload = str(ptk.load, encoding = 'utf-8')
            print(payload)
            key = payload[:8]
            sdata = payload[8:]
            print("key: ", key)
            print("sdata: ", sdata)
            udata = str(SE.des_decrypt(key,sdata), encoding='utf-8')
            print("udata: ", udata)
            data['raw'] = udata
        
    