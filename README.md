# SCAPY-GUI

## 使用前

### 安装相关依赖

1. scapy
`pip install --pre scapy[basic]`
2. tkinter
`pip install tkinter`
3. pydes
`pip install pydes`

其余的模块若在运行过程中报错，请自行安装以下格式安装
`pip install module-name`

若是pip安装速度较慢，考虑将`pip`的安装镜像源替换为国内镜像源，具体的操作步骤可以查考这篇博客[将pip源更换到国内镜像](https://blog.csdn.net/sinat_21591675/article/details/82770360)


## 使用方法

### 运行程序

1. Linux下

首先需要切换到程序目录下，然后用管理员权限运行

```
cd SCAPY-GUI-MASTER
sudo python3 mainGUI.py
```

2. windows下

用管理员权限打开cmd，然后在cmd中切换到程序路径下

```
cd SCAPY-GUI-MASTER
python3 mainGUI.py
```
程序路径根据自己的情况为准

### 嗅探

首先在`sniff counts`中输入要嗅探接受包的数量，这里填入的必须是数字。然后点击按钮`sniff`,在接受数据包数量达到需求后，会在下方的窗口显示解析后的数据结果

### 本地数据包

点击`open`，选择本地pcap包，然后点击按钮`fileExtract`，在下方窗口会显示解析后的数据结果。

### 关于自定义数据包

本程序设置了一个自定义实现自定义协议生成的脚本[secretPcapMkTool.py](secretPcapMkTool.py),在该脚本中的第11行的data为要加密的文本，可以自行替换，运行该脚本可以在当前目录下生成pcap包`secretTest.pcap`。运用该包可以测试自定义协议的解析效果。
