from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter import scrolledtext
from tkinter import messagebox
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

# 本地保存的pcap文件
userText = Label(root, 
            text='filename',
            font=18,
            bd='2')
userText.grid(row=0,column=2)

fileString = StringVar()
filePath = Entry(root,
            text=fileString,
            font=18,
            width=70,
            fg='black')
filePath.grid(row=0,column=3)

def openFile(event):
    filename = filedialog.askopenfilename()
    print("选择文件：", filename)

    filePath.delete(0, END)
    filePath.insert(0,filename)

btn_open = Button(root,
                    text='open',
                    width=10,
                    height=2
                    )
btn_open.bind('<Button-1>',openFile)
btn_open.grid(row=0,column=4)

# 空一行
Label(root).grid(row=1,column=0)

def pcapAna(ptks):
    
    PD = protoAna.PcapDecode()
    for p in ptks:
        data = dict()
        data = protoAna.PcapDecode.ether_decode(PD,p)
        # 自定义协议内容解析
        if p.haslayer("IP") & (p.version == 15):
            payload = str(p.load, encoding = 'utf-8')
            key = payload[:8]
            sdata = payload[8:]
            data["key"] = key
            data["load"] = str(SE.des_decrypt(key,sdata), encoding='utf-8')
        print(data)
        for k,v in data.items():
            dataCap.insert(END, str(k) + ": " + str(v) +"\n")
        dataCap.insert(END,"\n")
        dataCap.see(END)

def NetCap(ip):
    ptks = sniff(iface = IFACES.dev_from_index(12),count=5)
    pcapAna(ptks)

def dataRead(file):
    ptks = rdpcap(file)
    pcapAna(ptks)

# 设置按钮控件
# 数据解析回调函数
def startCap_Analyse(event):
    
    ip = link.get()
    file = filePath.get()
    chose = False
    data = dict()
    # 根据用户的选择，调用抓包函数或者本地文件
    if len(ip) == 0 | len(file) == 0:
        messagebox.showwarning("warnig!","There should be a ip or filepath at least!")#提出警告对话窗
    elif len(ip) !=0 & len(file) != 0:
        chose = messagebox.askquestion("conflict", "choose Ip?")
        if(chose == True):
            data = NetCap(ip)
            return
        else:
            data = dataRead(file)
            return
    elif len(ip) !=0:
        data = NetCap(ip)
        return
    else:
        data = dataRead(file)
        return    

# 开始按钮外观属性设置
btn_start = Button(root,
                        text='start',
                        height=2,
                        width=10)
btn_start.bind('<Button-1>', startCap_Analyse)
btn_start.grid(row=2,column=0,rowspan=2,columnspan=2)

# 消息文本控件
dataCap = scrolledtext.ScrolledText(root,
                wrap=WORD,
                font=20,
                bd='2',
                bg='black',
                fg='green',
                width=150,
                height=30)
dataCap.place(relx=0.5, rely=0.2, anchor=N)
root.title('NET CAP TOOL')
root.mainloop()