#coding=utf8
import os,sys
import time
import configparser

def cur_file_dir():
     #获取脚本路径
     path = os.getcwd()
     # path = "C:\Users\\xiongxiangquan\Desktop\ser"
     #判断为脚本文件还是py2exe编译后的文件，如果是脚本文件，则返回的是脚本的目录，如果是py2exe编译后的文件，则返回的是编译后的文件路径
     if os.path.isdir(path):
         return path
     elif os.path.isfile(path):
         return os.path.dirname(path)

#打印结果
mainpath = cur_file_dir()
print(mainpath)
ConfigFile = os.path.join(mainpath,"config.ini")

def readcfg():
    kargs={}
    cf = configparser.ConfigParser()
    cf.read(ConfigFile)
    for opt in cf.sections():
        if opt:
            kargs[opt]={}
    for opt in kargs.keys():
        for k,v in cf.items(opt):
            kargs[opt][k]=v
    return kargs

def writecfg(**kargs):
    pass
ss = readcfg()