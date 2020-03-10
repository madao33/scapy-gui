from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter import scrolledtext
import dataAna
import scapyTest2
from scapy.all import *

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

# 协议选择控件
protoText = Label(root,
                text="protocol",
                font=18,
                bd='2')
protoText.grid(row=0,column=2)
def show_msg(event):
    protocol = protoChosen.get()
    protoText.setvar(protocol,"1")
protocols = StringVar()
protoChosen = ttk.Combobox(root, width = 20, textvariable = protocols)
protoChosen['values'] = ('TCP', 'IP', 'UDP', 'ARP', 'Ether', 'HTTP')
protoChosen['state'] = 'readonly' # 设置为只读模式
protoChosen.current(0)
protoChosen.bind("<<ComboxSelected>>", show_msg)
protoChosen.grid(row=0,column=3)

# 自定义配置协议
userText = Label(root, 
            text='user protocol',
            font=18,
            bd='2')
userText.grid(row=0,column=4)

fileString = StringVar()
filepath = Entry(root,
            text=fileString,
            font=18,
            width=40,
            fg='black')
filepath.grid(row=0,column=5)

# 打开自定义协议文件
def fileButton():
    usrfile = filedialog.askopenfilename() # 打开文件夹得到文件路径
    print("选择文件：" + usrfile)
    fileString.set(usrfile)
btn_file = Button(root,
                text = 'open',
                command = fileButton)
btn_file.grid(row=0,column=6)

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

Label(root).grid(row=1,column=0)
btn_start = Button(root,
                text='send&capture',
                width=10,
                height=2)
btn_start.bind('<Button-1>',startCap)
btn_start.grid(row=1, column=0,rowspan=2,columnspan=2)

# 停止捕获回调函数
def sniffData(event):
    pkts = sniff(iface=IFACES.dev_from_index(12),count=3) # 简单的抓取数据包
    wrpcap("demo.pcap", pkts)  # 保存为demo.pcap
        
    PD = scapyTest2.PcapDecode()  # 实例化该类为PD
    pcap_test = rdpcap("demo.pcap")  # 这个demo.pcap包含3次连接
    data_result = dict()  # 将解析结果存入dict
    for p in pcap_test:
        data_result = scapyTest2.PcapDecode.ether_decode(PD, p)
        for k,v in data_result.items():
            dataAnalyse.insert(END,str(k)+":"+str(v)+"\n")
    dataCap.insert(END, pkts)

    dataCap.insert(END,"\n")
    dataAnalyse(END,"\n")

btn_sniff = Button(root,
                    text = 'sniff',
                    height=2,
                    state='active',
                    width=10)
btn_sniff.bind('<Button-1>', sniffData)
btn_sniff.grid(row=1,column=2,rowspan=2,columnspan=2)

# 数据解析回调函数
def analyzeData(event):
    print("分析数据")

btn_analyze = Button(root,
                        text='analyze data',
                        height=2,
                        width=10)
btn_analyze.bind('<Button-1>', analyzeData)
btn_analyze.grid(row=1,column=4,rowspan=2,columnspan=2)

# 消息文本控件
dataCap = scrolledtext.ScrolledText(root,
                font=20,
                bd='2',
                bg='black',
                fg='green',
                width=75,
                height=30)
# dataCap.insert(END, "hello, world!")
dataCap.place(relx=0.25, rely=0.2, anchor=N)


dataAnalyse = scrolledtext.ScrolledText(root,
                    font=20,
                    bd='2',
                    bg='black',
                    fg='green',
                    width=75,
                    height=30)
dataAnalyse.place(relx=0.73, rely=0.2,anchor=N)

root.title('NET CAP TOOL')
root.mainloop()