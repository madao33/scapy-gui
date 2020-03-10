from scapy.all import *

def sendAndCap(ip):
    ans, unans = sr(IP(dst = ip) / TCP(sport=30, dport=80))
    dics=[]
    if len(ans) != 0:
        for a in ans:
            for p in a:
                print(p)
                try:
                    dic={}
                    dic["Protocol"] = p[0].proto
                    dic["Destination"] = p[0].dst
                    dic["Source"] = p[0].src
                    dic["Sport"] = p[0].sport
                    dic["Dport"] = p[0].dport
                    print(dic)
                    dics.append(dic)
                    # print >> f,p[1].proto, p[1].dst, p[1].src, p[2].sport, p[2].dport
                except AttributeError:
                    continue
    else:
        print("未接收到数据")
    # f.close()
    return dics,ans

