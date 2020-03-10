scapy simple python data capture GUI based on scapy & tkinter 
befor using this tool:
1. install scapy: pip install scapy
for this highly recommend use this command: pip install --pre scapy[basic]
2. install NpCap: Google or baidu -.-
3. install tkinter:
usage:
1. python mainGui to run this tool;
2. input ip you want test, then press the button 'send&capture',then will show the result in two windows.The left one is the 
summary about the data you captured, while right one shows the data analysed in detail;
3. press button 'sniff' to capture the data from wireless interface, this property should costumerise based on your own PC. 
Data shows see No.2.
4. Input you key first to decode the data you sniffed, the key must be exactly EIGHT bytes!. You can try secretPcapMkTool.py
to make your own pcap data.Data shows see No.2. 

一个简易的基于SCAPY和tkinter的python数据包抓取GUI
用法：
1. 运行mainGui.py；
2. 输入要测试的IP，按下‘send&capture’,在无误的情况下就可以接收到数据，然后结果会在两个窗口显示，左边的窗口是抓取数据的简述，右边的是数据处理的结果；
3. 按下‘sniff'按钮从无线网卡中抓取数据，无线网卡的属性需要根据自己的电脑自定义，数据显示的结果参照第二条；
4. 输入密码以便解码嗅探得到的数据，密码必须是八位字节！可以使用secretPcapMkTool.py脚本生成自己的pcap数据包。数据的显示结果参照第二条。
