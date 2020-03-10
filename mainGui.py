from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter import scrolledtext
import dataAna
import protoAna
from scapy.all import *
import struct
import secretEncode as SE
root= Tk()

# 设定窗体分辨率，即大小
root.geometry('1366x720') # 这里的乘号不是 * ，而是小写英文字母 x
print("开始创建窗体")

# 链接文本控件
linkText = Label(root, 
            text='IP/mask',
            font=18,
            bd='2')
linkText.grid(row=0,column=0)
# 链接输入文本控件
link = Entry(root,   
            text='input your ip/mask',
            width=40,
            font=18)
link.grid(row=0,column=1)

# 自定义配置协议
userText = Label(root, 
            text='user key(exactly 8 bytes!)',
            font=18,
            bd='2')
userText.grid(row=0,column=2)

fileString = StringVar()
decodeKey = Entry(root,
            text=fileString,
            font=18,
            width=40,
            fg='black')
decodeKey.grid(row=0,column=3)


# 设置按钮控件

# 捕获按钮回调函数
def startCap(event):
    ip = link.get()
    if len(ip) == 0:
        dataCap.insert(END, "请输入IP\n")
        return
    print("开始抓取数据, ip为：",ip)
    # ip = "192.168.0.102"
    
    dics, packets = dataAna.sendAndCap(ip)
    # 接收到数据不为空
    if len(dics) != 0:
        for dic in dics:
            for k,v in dic.items():
                print(str(k) + ":" + str(v))
                dataAnalyse.insert(END,str(k)+":"+str(v)+'\n')
    else:
        dataAnalyse.insert(END,"received nothing!!!\n")
    
    dataCap.insert(END,packets)
    
    dataAnalyse.insert(END, "\n")
    dataCap.insert(END, "\n")
    dataCap.see(END)
    dataAnalyse.see(END)

Label(root).grid(row=1,column=0)
btn_start = Button(root,
                text='send&capture',
                width=10,
                height=2)
btn_start.bind('<Button-1>',startCap)
btn_start.grid(row=1, column=0,rowspan=2,columnspan=2)

# 监听回调函数
def sniffData(event):
    pkts = sniff(iface=IFACES.dev_from_index(12),count=20) # 简单的抓取数据包
    wrpcap("capted.pcap", pkts)  # 保存为demo.pcap
        
    PD = protoAna.PcapDecode()  # 实例化该类为PD
    pcap_test = rdpcap("capted.pcap")  # 这个demo.pcap包含3次连接
    data_result = dict()  # 将解析结果存入dict
    for p in pcap_test:
        data_result = protoAna.PcapDecode.ether_decode(PD, p)
        print(data_result)
        for k,v in data_result.items():
            dataAnalyse.insert(END,str(k)+":"+str(v)+"\n")
    dataCap.insert(END, pkts)

    dataCap.insert(END,"\n")
    dataAnalyse.insert(END,"\n")
    dataCap.see(END)
    dataAnalyse.see(END)

btn_sniff = Button(root,
                    text = 'sniff',
                    height=2,
                    state='active',
                    width=10)
btn_sniff.bind('<Button-1>', sniffData)
btn_sniff.grid(row=1,column=2,rowspan=2,columnspan=2)

# 数据解析回调函数
def analyzeData(event):
    # pcap_test = rdpcap("capted.pcap")
    dataAnalyse.insert(END, "analysing data....\n")
    
    PD = protoAna.PcapDecode()  # 实例化该类为PD
    pcap_test = rdpcap("secret.pcap")  # 这个demo.pcap包含3次连接
    data_result = dict()  # 将解析结果存入dict
    for p in pcap_test:
        data_result = protoAna.PcapDecode.ether_decode(PD, p)
        for k,v in data_result.items():
            dataAnalyse.insert(END,str(k)+": "+str(v)+"\n")
        print(data_result)
        if p.haslayer("Raw") == True:
            secret_key = decodeKey.get()
            if len(secret_key) != 8:
                dataCap.insert(END, "please input exactly 8 bytes key to decode the data!!!\n"+
                "originly maybe: madao233\n")
            else:   
                # 利用密钥解码load原始数据 
                secret_data=SE.des_decrypt(secret_key, p.load)
                dataAnalyse.insert(END, "Raw load: "+str(secret_data)+"\n")
    dataCap.insert(END, pcap_test)
    dataCap.insert(END,"\n")
    dataAnalyse.insert(END,"\n")
    dataCap.see(END)
    dataAnalyse.see(END)

btn_analyze = Button(root,
                        text='analyze data',
                        height=2,
                        width=10)
btn_analyze.bind('<Button-1>', analyzeData)
btn_analyze.grid(row=1,column=4,rowspan=2,columnspan=2)

# 消息文本控件
dataCap = scrolledtext.ScrolledText(root,
                wrap=WORD,
                font=20,
                bd='2',
                bg='black',
                fg='green',
                width=75,
                height=30)
# dataCap.insert(END, "hello, world!")
dataCap.place(relx=0.25, rely=0.2, anchor=N)


dataAnalyse = scrolledtext.ScrolledText(root,
                    wrap=WORD,
                    font=20,
                    bd='2',
                    bg='black',
                    fg='green',
                    width=75,
                    height=30)
dataAnalyse.place(relx=0.73, rely=0.2,anchor=N)

root.title('NET CAP TOOL')
root.mainloop()