# pppoe-ser

> 基于PySide6、scapy开发的模拟PPPoE服务端的GUI界面测试工具，用于响应PPPoE客户端的ppp协议报文。

## 介绍

### Developer

[FanHao](http://alanfanh.github)

### 项目结构

````text
pppoe-ser
|
|--common
|  |
|  |---Globals.py       # 获取路径,配置读取
|  |---gui.py           # 界面源码
|  |---untitled.ui      # 界面UI
|--packet               # 抓取报文pcap文件保存目录
|  
|--WinMain.py           # 界面主线程,工作子线程,核心处理逻辑
|--config.ini           # 参数配置存储文件
|--ReadMe.md            # 本文件
|
````
### 遗留问题

1.MPPE加密未解决
2.PPPoEv6接入另一种通过ND协议交互没有以实现

## 环境

> 运行环境：Windows系统

### 开发语言

> python3.9.10 64bit

### 依赖

> 可使用"pip install -r requirements.txt"一键安装所有依赖项

````text
wmi==1.5.1
scapy==2.4.5
configparser==5.2.0
IPy==0.83
PySide6==6.2.3
````

## 打包

安装pyinstaller
````
pip install pyinstaller
````

管理员权限打开cmd，切换至WinMain.py所在目录，执行如下命令
````python
pyinstaller -F WinMain.py
````

修改WinMain.spec文件中如下内容
````
hiddenimports=['Queue'],
console=True,icon='logo.ico'
name='PPPoE_Server'
````

执行命令打包
````
pyinstaller -F  WinMain.spec
````
	
打包后.exe文件位置：dist文件夹下