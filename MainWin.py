# -*- coding: utf-8 -*-
from datetime import datetime
import sys,os
import time
import re
import json
import configparser
import random
# import dnet
import binascii
import wmi
import IPy
from PySide6 import QtCore,QtGui
from PySide6.QtCore import SIGNAL
from PySide6.QtWidgets import QWidget,QApplication  
from common.gui import Ui_Form
from common.Global import * 
from scapy.all import *
import hashlib as md5sss

# lcp option-code 
op_dict = {'None':'0','MRU:1':'1','ACCM:2':'2','AP:3':'3','Quality:4':'4','Magic:5':'5','PFC:7':'7','AaCFC:8':'8','FCS:9':'9','SDP:10':'10','Numbered-M:11':'11','MLP:12':'12','Callback:13':'13','CTime:14':'14','Compound-F:15':'15','NDE:16':'16','MRRU:17':'17','MSSNHF:18':'18','MED:19':'19','Proprie:20':'20','DCE:21':'21'}


class RunThread(QtCore.QThread):
    #把打印的字符串发送给UI主线程
    singal_sendnum= QtCore.Signal(str) # 已发送数据包个数
    def __init__(self, parent=None):
        super(RunThread, self).__init__(parent)
        self.parent = parent
        global op_dict

    def init_data(self):
        self.config=readcfg()
        self.client_info = {}
        avg ={             # ser 默认配置 
            'username':self.config['server']['user'],
            'password':self.config['server']['pwd'],
            'server_name':self.config['server']['hw_sername'],
            'ac_name':self.config['server']['ac_name'],
            'auth':self.config['server']['authen'],
            'smac':self.config['server']['hw_smac'],
            'local_ip':self.config['ipv4_config']['hw_server'],
            'iface':self.config['inface']['inface'],
            'is_reply':self.config['ipv4_config']['hw_reply'],
            'ip':self.config['ipv4_config']['hw_serip'],
            'dns1':self.config['ipv4_config']['hw_dns1'],
            'dns2':self.config['ipv4_config']['hw_dns2'],
            'check_pkt':self.config['ipv4_config']['check_pkt'],
            'timeout':'30',      
            'send_pack':'',        
            'wait_echoreq':self.config['ipv4_config']['wait_echoreq'],
            'save_all':'1',         
            'ser_error':self.config['ipv4_config']['ser_error'],
            'lcp_op':self.config['ipv4_config']['lcp_op'],
            'is_run':'1',
            'keep_live':30, 
            'ip_addr':self.config['ipv6_config']['remoteip'],
            'prefix':['%s'%self.config['ipv6_config']['ipv6prefix']],
            'dnsser':['%s'%self.config['ipv6_config']['dnsserver']],
            'dnsdomain':['%s'%self.config['ipv6_config']['domain']],
            'ipv6_support':self.config['support']['v6support'],
            'ipv4_support':self.config['support']['v4support']
            } 
        # self.mppe=self.config['ipv4_config']['hw_mppe']
        self.pkt_list = []
        dir_path=os.getcwd()
        dir1 = dir_path +"\packet"
        if not os.path.exists(dir1):
            os.mkdir(dir1)
        self.dir=dir1+"\pppoe.pcap"
        self.packall_dir=dir1+"\pppoe_all.pcap"
        self.checked=avg['check_pkt']
        self.smac=avg['smac']
        self.local_ip=avg['local_ip']
        self.dns1=avg['dns1']
        self.dns2=avg['dns2']
        self.iface=avg['iface']   
        self.username=avg['username'] 
        self.password=avg['password'] 
        self.server_name = avg['server_name']
        self.ac_name = avg['ac_name']
        self.timeout = int(avg['timeout'],10)
        self.wait_echoreq = int(avg['wait_echoreq'])  # 等待多长时间后回复维链报文
        self.send_packet = avg['send_pack']           # send_pack 协商完成后发送数据包
        self.reply = avg['is_reply']                  # 不回应PADI PADS 'LCP Terminate'     
        self.save_all = int(avg['save_all'])          # 默认保存所有交互的报文
        self.ser_error = avg['ser_error']             # ser异常
        self.ipv6_support = avg['ipv6_support']       # 支持IPv6
        self.ipv4_support = avg['ipv4_support']       # 支持IPv4
        self.lcp_op_type_list = [1, 3, 5]
        self.lcp_op = eval(op_dict[avg['lcp_op']]) 
        if self.lcp_op != 0:
                # 配置ser发出lcp_req报文时，携带某类options的type
                if self.lcp_op not in self.lcp_op_type_list:
                    self.lcp_op_type_list.append(self.lcp_op)             
        self.pppoe_tags={"server_name":self.server_name}  # ,"ac_cookies":"" 
        self.lcp_options={"mru":"1492","auth":avg['auth']}   #default lcp options 
        self.ipcp_options={"ip":avg['ip'],"dns1":self.dns1,"dns2":self.dns2,"nbns1":"223.1.1.1","nbns2":"223.2.2.2"} #default 
        self.lcp_id = random.randint(10,20)
        self.ip_addr = avg['ip_addr']           # 协商的地址
        self.prefix = avg['prefix']
        self.dnsser = avg['dnsser']             # DNS address
        self.dnsdomain = avg['dnsdomain']       # dnsdomain
        self.ipcp_id = 10
        self.save_times = 1
        self.send_times = 1
        self.padt_times = 1
        self.test_nak = 1
        self.ipcp_flag = 0
        self.chap_id = 84
        self.loop_ra = 0
        self.chap_time = 1
        self.ttime = [0]    ;#用来控制发送维链
        self.chap_flag = 0 ;#为1表示认证成功
        #loop pppoe_tags lcp_options ipcp_options
        for i in ['pppoe_tags','lcp_options','ipcp_options']:
            _optdict=getattr(self,i)
            for k,v in _optdict.items():
                setattr(self,k,v)
        self.lcp_up = [0,0];  #lcp链路建立起来的标准时 发送ACK和收到ACK ,第一个为收到ACK 第二个为发送ACK
        # self.filter="(pppoed or pppoes or icmpv6) and (ether dst %s or ether dst %s)" % (self.smac,"ff:ff:ff:ff:ff:ff")
        self.filter = "(ether dst %s or ether dst %s)" % (self.smac,"ff:ff:ff:ff:ff:ff")
        self.client_info[self.smac]=[self.username]
        self.pro_list = ['PPP_LCP_Configure','PPP_LCP_Echo','PPP_LCP_Terminate','PPP_LCP_Code_Reject','PPP_LCP_Protocol_Reject','PPP_LCP_Discard_Request','PPP_LCP']
        self.magicnum = self.random_magicnum()  # len ---> 4
        print("######################")
        self.channage_number = ''

    def start_test(self):
        print("start---> \n")
        self.start()

    def stop_test(self):
        print("stop_test")
        self.terminate()
        self.wait()
        self.quit()
        if self.save_all == 1:
            self.save_packet(self.pkt_list,op=1)

    def add_pppoetags(self):
        """
        对pppoe_tags进行解析,解析后返回load的二进制形式的值
        """
        pppoe_tag_code_dict={"server_name":"0101"}
        load=""
        for k,v in self.pppoe_tags.items():
            if hasattr(self,k):
                #判断是否存在该变量
                value = getattr(self,k)
                load=load+pppoe_tag_code_dict[k]+"%04x" %(len(value))+self.str2hex(value)
        load=load+self.random_hostuiq()
        return self.hex2bin(load)

    def get_time(self):
        """
        获取当前时间，返回当前时间的 秒数
        """
        time.sleep(1)
        dt = datetime.now()
        return int(dt.strftime("%S"))

    def random_accookies(self):
        """
        随机生成cookies值，并返回
        """
        return "".join(random.sample("abcdefghijklmnopqrstuvwxyz0123456789",20))

    def random_magicnum(self):
        """
        随机生成一个魔术字字段的值，并返回
        """
        mgc_n = "0x"+"".join(random.sample("0123456789abcdef",8))
        return eval(mgc_n)

    def run(self):
        """
        开启指定网卡，报文嗅探
        filter过滤 
        prn回调函数 
        store保存或丢弃抓取的报文，0 默认不保存
        iface网卡
        """
        self.init_data()
        sniff(filter=self.filter,prn=self.detect_pppoe_paket,store=0,iface=self.iface)

    def detect_pppoe_paket(self,pkt):
        """
        ① 保存嗅探到的报文
        ② 嗅探到报文的不同会话阶段、不同protocol报文调用对应函数处理
        """
        # if self.ipcp_flag:
            # _get_s = time.localtime( time.time() ).tm_sec / 30
            # if _get_s != self.ttime[0]:
                # self.ttime[0] = _get_s
                # self.send_lcp_echo_request(pkt)
        self.pkt_list.append(pkt)
        _type = {
            0x8863:{
                'code':{
                    0x09:self.send_pado_packet,
                    0x19:self.send_pads_packet,
                    0xa7:self.send_padt_packet
                }
            },
            0x8864:{
                'proto':{
                    0xc021:self.config_lcp_packet,
                    0xc223:self.send_chap_packet,
                    0xc023:self.send_pap_packet,
                    0x0021:self.send_ip_packet,
                    0x8021:self.send_ipcp_packet,
                    0xc029:self.send_CBCP_request,
                    0x8057:self.send_ipv6cp_paket,
                    0x0057:self.select_ipv6_paket
                }
            }
        }
        try:
            if _type.has_key(pkt.type):
                #得到的数据包为PPPOE协议封装的数据包
                _methoddict = _type[pkt.type]   
                for k,v in _methoddict.items():
                    _kVal = getattr(pkt,k)
                    if _methoddict[k].has_key(_kVal):
                        _obj = _methoddict[k][_kVal]
                        _obj(pkt)
        except:
            pass

    def send_pado_packet(self,pkt):
        """
        ① 若：需要检查会话阶段PADI报文，则保存
        ② 若：设置server服务器不响应PADI，则丢弃
        ③ 正常情况：
            解析收到PADI tag字段的值
            生成对应PADO包，并发送
        """
        if self.checked == 'padi' and self.save_times == 1: # ①
            self.save_packet(pkt)
            self.save_times = 0
        reply = self.reply.lower() 
        if reply == "padi":                                 # ②
            print("PADI not reply")
            pass
        else:                                               # ③
            args={'0x0102':self.ac_name,'0x0104':self.random_accookies(),'0x0101':self.server_name}
            loadbin=self.update_option(load=pkt.load,key="pppoe",**args)
            raw=copy.deepcopy(pkt)
            raw.src,raw.dst,raw.code=self.smac,pkt.src,0x07
            raw.len=len(loadbin)
            loadbin=self.appendbin(loadbin,len(loadbin))
            raw.load=loadbin
            self.pkt_list.append(raw)
            sendp(raw,iface=self.iface)

    def send_pads_packet(self,pkt):
        """
        若：需要检查会话阶段PADR报文，则保存
        若：设置server服务器不响应PADR，则丢弃
        根据是/否模拟服务器发异常报文，设置对应 会话sessionid
           生成PADS报文，并发送
        """
        if self.checked == 'padr' and self.save_times == 1: 
            self.save_packet(pkt)
            self.save_times = 0
        reply = self.reply.lower() 
        if self.reply == "padr":                 
            print("PADR not reply")
        else:                                           
            kargs={'0x0101':self.server_name}
            hexstr=self.bin2hex(pkt.load)
            ret=self.parser_data(hexstr,"pppoe")
            ret.pop('0x0104')
            loadbin=''
            for k,v in ret.items():
                kv_str=k[2:]+"%04x" %(len(v))+self.str2hex(v)
                loadbin=loadbin+self.hex2bin(kv_str)
            raw=copy.deepcopy(pkt)
            raw.src,raw.dst,raw.code=self.smac,pkt.src,0x65
            if self.ser_error == "pads_no_id":
                raw.sessionid=None
            else:
                randint_sessionid = "0x00" + "".join(random.sample("0123456789",2))
                raw.sessionid=eval(randint_sessionid)
            raw.len=len(loadbin)
            loadbin=self.appendbin(loadbin,len(loadbin))
            raw.load=loadbin
            self.pkt_list.append(raw)
            sendp(raw,iface=self.iface)

    def send_padt_packet(self,pkt): 
        """
        ① 若：需要检查会话阶段PADT报文，则保存
        ② 若：设置server服务器不响应PADT，则丢弃
        ③ 收到PADT若：
               已建立链路层通路，则回复PADT
               同时，初始化参数
        """
        self.pkt_list.append(pkt)
        if self.checked == 'padt' and self.save_times == 1: 
            self.save_packet(pkt)
            self.save_times = 0
        if self.reply != 'padt':  
            raw=copy.deepcopy(pkt)
            raw.src,raw.dst=self.smac,pkt.src
            if self.ipcp_flag == 1 :
                self.pkt_list.append(raw)
                sendp(raw,iface=self.iface)
                self.ipcp_flag = 0  
                self.padt_times = 1
                self.lcp_up = [0,0]

    def send_padt(self,pkt): 
        """
        构造PADT报文，并发送
        用于 服务器主动断开连接
        """
        load_meg = '\x01\x04\x00\x14g3viox7z5bmer0c1f2kp'
        length = len(load_meg)
        raw = Ether(src=pkt.dst,dst=pkt.src,type=0x8863)/PPPoED(version=1,type=1,code=0xa7,sessionid=pkt.sessionid,len=length)/Raw(load=load_meg)
        self.lcp_id+=1
        self.pkt_list.append(raw)
        sendp(raw,iface=self.iface)

    def config_lcp_packet(self,pkt):
        """
        需要检查会话阶段PADR报文，则保存
        解析收到的LCP报文，根据不同类型做出对应处理，并回复
        以收到的LCP code来区分报文
        """
        raw = copy.deepcopy(pkt)
        raw.src,raw.dst=pkt.dst,pkt.src
        for pro in self.pro_list:
            try:
                lcp_code = pkt[pro].code
                break
            except:
                pass
        if lcp_code == 1:
            if self.checked == 'lcp_req' and self.save_times == 1:  
                self.save_packet(pkt)
                self.save_times = 0
            type_accept = []
            type_reject = []
            if hasattr(pkt,'options'):
                for i in range(len(pkt.options)):
                    if pkt.options[i].type in self.lcp_op_type_list:
                        type_accept.append(pkt.options[i].type)
                    else:
                        type_reject.append(pkt.options[i].type)
            else:
                pass 
            if len(type_reject) == 0:
                reject_flag=0
                if self.lcp_up[0] == 0:
                    self.send_lcp_req(pkt)
                raw[PPP_LCP_Configure].code = 2
                if self.ser_error == 'lcp_id_err':
                    raw[PPP_LCP_Configure].id = random.randint(5,20)
                self.lcp_up[1]=1
                self.pkt_list.append(raw)
                sendp(raw,iface=self.iface)
            else:
                # 存在不能被接受的options时
                reject_flag=1
                # 去除可接受的options字段,留下不能接受的options功能，在reject中回复
                raw[PPP_LCP_Configure].code = 4
                length = 0
                options_list = []
                for i in range(len(pkt.options)):
                    if pkt.options[i].type in type_reject:
                        options_list.append(pkt.options[i])
                        length = length + pkt.options[i].len
                raw[PPP_LCP_Configure].options = options_list
                raw[PPP_LCP_Configure].len = length + 4
                raw[PPPoE].len = length +6
                self.pkt_list.append(raw)
                sendp(raw,iface=self.iface)  
        elif lcp_code == 2:
            if self.checked == 'lcp_ack' and self.save_times == 1:  # 检查lcp_ack
                self.save_packet(pkt)
                self.save_times = 0
            self.pkt_list.append(pkt)
            self.lcp_up[0]=1
        elif lcp_code in [3,4]:
            if lcp_code == 3:
                if self.checked == 'lcp_nak' and self.save_times == 1:  
                    # 检查Configure_nck
                    self.save_times = 0
                    self.save_packet(pkt)
            else:
                if self.checked == 'lcp_reject' and self.save_times == 1:  
                    # 检查lcp_reject
                    self.save_packet(pkt)
                    self.save_times = 0
            #从字典中删除拒绝的字段
            for i in range(len(pkt.options)):
                if pkt.options[i].type in self.lcp_op_type_list:
                    self.lcp_op_type_list.remove(pkt.options[i].type)
            self.send_lcp_req(pkt)
        elif lcp_code == 5:
            if self.checked == "lcp_terminate" and self.save_times == 1: 
                self.save_packet(pkt)
                self.save_times = 0
            if self.reply == "lcp_terminate":
                print("LCP Terminate not reply")
            else:
                raw[PPP_LCP_Terminate].code = 6
                self.pkt_list.append(raw)
                sendp(raw,iface=self.iface)
        elif lcp_code == 6:
            if self.checked == 'terminate_ack' and self.save_times == 1:
                #'check terminate_ack'
                self.save_packet(pkt)
                self.save_times = 0
        elif lcp_code == 9:
            if self.checked == "echo_request" and self.save_times == 1: 
                self.save_packet(pkt)
                self.save_times = 0
            if self.reply == "echo_request":
                print("not reply echo_request")
            else:
                if self.ipcp_flag:
                    _get_s = time.localtime( time.time() ).tm_sec / 30
                    if _get_s != self.ttime[0]:
                        self.ttime[0] = _get_s
                        self.send_lcp_echo_request(pkt)
                    if self.wait_echoreq != 0:
                        time.sleep(self.wait_echoreq)
                    raw[PPP_LCP_Echo].code = 10
                    raw[PPP_LCP_Echo].magic_number = self.magicnum
                    self.pkt_list.append(raw)
                    sendp(raw,iface=self.iface)
        else:
            pass
        if self.lcp_up == [1,1]:
            self.padt_times == 1
            if self.send_packet == 'lcp_terminate' and self.send_times == 1:
                self.send_lcp_terminal(pkt)
                self.send_times = 0
            if self.auth == "chap" and self.chap_flag == 0:
                self.send_chap_packet(pkt)

    def send_lcp_identifier(self,pkt):
        loadbin="\x0c" + self.num2bin(self.lcp_id)+'\x00\x11'+self.magicnum+self.str2bin("test")
        length=6+len(loadbin)   ;# 2byte ppp header, 4byte lcp header
        lcp_req=Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoED(version=1,type=1,code=0x00,sessionid=pkt.sessionid,len=length)/PPP(proto=0xc021)/Raw(load=loadbin)
        self.lcp_id+=1
        self.pkt_list.append(lcp_req)
        sendp(lcp_req,iface=self.iface)

    def send_lcp_echo_request(self,pkt):
        """
        收到echo_request报文，并构造回复
        """
        try:
            lcp_code = pkt[pro].code
        except:
            lcp_code = 0
        if lcp_code == 9:
            lcp_req=Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoED(version=1,type=1,code=0x00,sessionid=pkt.sessionid,len=10)/PPP(proto=0xc021)/PPP_LCP_Echo(code=9,id=self.lcp_id,len=8,magic_number=self.magicnum,data=pkt[PPP_LCP_Echo].data)
        else:
            lcp_req=Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoED(version=1,type=1,code=0x00,sessionid=pkt.sessionid,len=10)/PPP(proto=0xc021)/PPP_LCP_Echo(code=9,id=self.lcp_id,len=8,magic_number=self.magicnum,data="")
        self.lcp_id+=1
        self.pkt_list.append(lcp_req)
        sendp(lcp_req,iface=self.iface)

    def send_lcp_req(self,pkt):
        """
        LCP交互LCP配置的option项
        """
        lcp_op_list = []
        length = 4
        if self.checked == 'lcp_reject':
            self.lcp_op_type_list.append(2)
        for lcpop in self.lcp_op_type_list:
            op_one,op_len = self.set_option(lcpop)
            lcp_op_list.append(op_one)
            length += op_len
        lcp_req = Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoED(version=1,type=1,code=0x00,sessionid=pkt.sessionid,len=length+2)/PPP(proto=0xc021)/PPP_LCP_Configure(code=1,id=self.lcp_id,len=length,options=lcp_op_list)
        self.lcp_id+=1
        if self.checked == 'lcp_option' and self.save_times == 1:
            self.save_packet(pkt)
            self.save_times = 0
        self.pkt_list.append(lcp_req)
        sendp(lcp_req,iface=self.iface)

    def set_option(self,type):
        """
        构造options字段项
        options的type组成的字典 [1, 2, 3, 4, 5, 13]
        """
        op_type = type 
        if op_type in [1, 2, 3, 4, 5, 13]:
            op_dict = {
                1:PPP_LCP_MRU_Option(type=1,len=4,max_recv_unit=1492),
                5:PPP_LCP_Magic_Number_Option(type=5,len=6,magic_number=self.magicnum),
                2:PPP_LCP_ACCM_Option(type=2,len=6,accm=0x0001111),
                4:PPP_LCP_Quality_Protocol_Option(type=4,len=4,quality_protocol=0xc025,data=""),
                13:PPP_LCP_Callback_Option(type=13,len=4,operation=0,message="1234"),
                3:{'pap':PPP_LCP_Auth_Protocol_Option(type=3,len=4,auth_protocol=0xc023,data=""),'chap':PPP_LCP_Auth_Protocol_Option(type=3,len=5,auth_protocol=0xc223,algorithm=5)}
            }
            if op_type != 3:
                op_other = op_dict[op_type]
            else:
                op_other = op_dict[op_type][self.auth]
        elif op_type in [6, 11, 12, 14, 19 ,20]:
            op_other = PPP_LCP_Option(type=op_type,len=6,data='12345678')
        elif op_type in [7, 8, 15, 16, 18]:
            op_other = PPP_LCP_Option(type=op_type,len=2,data='')  
        elif op_type in [9, 10, 21]:
            op_other = PPP_LCP_Option(type=op_type,len=3,data='00')
        elif op_type == 17:
            op_other = PPP_LCP_Option(type=17,len=4,data='1234')
        leng = op_other.len
        if self.checked == 'lcp_nak' and self.test_nak == 1:
            op_other.max_recv_unit = 1550
            self.test_nak = 0
        return op_other,leng

    def send_chap_packet(self,pkt):
        """
        判断协商的加密方式是否为chap
        若是，则发起chap认证
        """
        self.pkt_list.append(pkt)
        try:
            load = self.str2bin(str(pkt[PPP_LCP_Configure]))
        except:
            load = self.str2bin(str(pkt[PPP]))[2:]
        #先判断pkt里面协议,如果不为chap,则发送req,否则发送suc/fail
        # if pkt.proto == 0xc021 and self.chap_time != 0:
        if pkt.proto == 0xc021 :
            random_len=random.randint(10,20)*2
            random_value=random.sample(range(0,255),random_len)
            self.channage_number="".join(map(lambda x:chr(x),list(random_value)))
            chap_header_len=5+random_len+len(self.username)
            loadhex='01%02x%04x%02x%s%s' %(self.chap_id,chap_header_len,random_len,self.bin2hex(self.channage_number),self.str2hex(self.username))
            loadbin=self.hex2bin(loadhex)
            length=chap_header_len+2
            loadbin=self.appendbin(loadbin,length)
            chap_req=Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoED(version=1,type=1,code=0x00,sessionid=pkt.sessionid,len=length)/PPP(proto=0xc223)/Raw(load=loadbin)
            self.chap_id+=1
            self.pkt_list.append(chap_req)
            sendp(chap_req,iface=self.iface)
            # self.chap_time = 0
        elif pkt.proto == 0xc223:
            if  load[0] == '\x02':
                if self.checked == 'chap_res' and self.save_times == 1:
                    self.save_packet(pkt)
                    self.save_times = 0
                if self.reply == 'chap':
                    # 设置服务器不回应chap请求
                    self.pkt_list.append(pkt)
                else:
                    ret={}
                    ret['id']=load[1]
                    length=struct.unpack("!B",load[4])[0]
                    all_len=struct.unpack("!H",load[2:4])[0]
                    ret['chall']=self.bin2hex(load[5:5+length])
                    ret['username']=load[5+length:all_len]
                    self.chap_response_num=0
                    username=self.username
                    if ret['username'] == self.username:
                        password=self.password
                        md_a=md5sss.new()
                        md_a.update(ret['id']+password+self.channage_number)
                        md5_value=md_a.hexdigest()
                        if md5_value.upper() == ret['chall'].upper():
                            #发送认证成功
                            rel = 3
                            msg="Success"
                            self.chap_flag = 1
                        else:
                            rel = 4
                            msg="Failure"
                            #发送密码错误
                    else:
                        # 发送用户名不存在
                        msg='\x00\x04'
                        rel = 4
                    id_c = pkt[PPP_CHAP_ChallengeResponse].id
                    # value_c = len(msg)
                    new_raw=Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoED(version=1,type=1,code=0x00,sessionid=pkt.sessionid)/PPP(proto=0xc223)/PPP_CHAP_ChallengeResponse(code=rel,id=id_c,value=msg)
                    
                    self.pkt_list.append(new_raw)
                    sendp(new_raw,iface=self.iface)
                    self.chap_response_num+=1
                    if self.chap_flag:
                        if 13 in self.lcp_op_type_list:
                            self.send_CBCP_request(pkt)
                        self.send_ipcp_req(pkt)
                    else:
                        self.send_lcp_terminal(pkt)

    def send_lcp_terminal(self,pkt):
        """
        构造并回复lcp_terminal报文
        """
        lcp_ter=Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoED(version=1,type=1,code=0x00,sessionid=pkt.sessionid,len=20)/PPP(proto=0xc021)/PPP_LCP_Terminate(code=5,id=pkt.id,len=18,data='authfalseasdfg')
        self.lcp_id+=1
        self.pkt_list.append(lcp_ter)
        sendp(lcp_ter,iface=self.iface)

    def appendbin(self,loadbin,pppoe_len):
        """
        主要用于补齐不足64字节的文件
        """
        binstr=loadbin
        randstr="".join(map(lambda x:chr(x),range(1,255)))
        if pppoe_len<40:
            if pppoe_len<36:
                binstr=loadbin+"\x00"*(36-pppoe_len)+'\xea\x94\xa5\xb3'
            else:
                binstr=loadbin+"".join(random.sample(randstr,40-pppoe_len))
        return binstr

    def send_pap_packet(self,pkt):
        """
        解析获取得到username和password
        完成认证
        """
        if self.checked == 'pap_req' and self.save_times == 1:  
            self.save_packet(pkt)
            self.save_times = 0
        if self.reply == 'pap':
            # 设置服务器不回应pap请求
            self.pkt_list.append(pkt)
        else:
            try:
                pap_proto = pkt.proto
                pap_code = pkt[PPP_PAP_Request].code
            except:
                pap_proto = pap_code =0
            if pap_proto == 0xc023 and pap_code == 1:
                username=pkt[PPP_PAP_Request].username
                password=pkt[PPP_PAP_Request].password
                flag=0
                if username == self.username:
                    if password == self.password:
                        flag=1
                    else:
                        msghex="0e"+self.str2hex("Password error")
                else:
                    msghex="User invalid"
                raw = Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoE(version=1,type=1,code=0,sessionid=pkt.sessionid,len='')/PPP(proto=0xc023)/PPP_PAP_Response(code=2,id=0x1,len='',msg_len='',message='Login ok')
                mesbin = self.tobin(str(raw[PPP_PAP_Response].message))
                raw[PPP_PAP_Response].msg_len = len(mesbin)
                raw[PPP_PAP_Response].len = len(mesbin) + 5
                raw[PPPoE].len = len(mesbin) + 5 + 2
                if flag:
                    self.pkt_list.append(raw)
                    sendp(raw,iface=self.iface)
                    self.pkt_list.append(pkt)
                    if 13 in self.lcp_op_type_list:
                        self.send_CBCP_request(pkt)
                    if self.ipv4_support == "True":
                        self.send_ipcp_req(pkt)
                    if self.ipv6_support == "True":
                        self.send_ipv6cp_request(pkt)
                else:
                    self.pkt_list.append(pkt)
                    self.send_lcp_terminal(pkt)

    def send_CBCP_request(self,pkt):
        try:
            load_n = pkt.load
        except:
            load_n = '\x01\x00\x00\x06\x01\x02'
        if pkt.proto == 0xc029:
            if load_n == '\x02':
                load_n = '\x03' + load_n[2:]
        else:
            load_n = '\x01\x00\x00\x06\x01\x02'
        cbcp = Ether(dst=pkt.src,src=pkt.dst,type=0x8864)/PPPoE(sessionid=pkt.sessionid)/PPP(proto=0xc029)/Raw(load=load_n)
        self.pkt_list.append(cbcp)
        sendp(cbcp,iface=self.iface)

    def send_ipcp_req(self,pkt):
        """
        构造发送ipcp_request
        """
        if pkt.proto != 0x8021:
            obj=PPP_IPCP_Option_IPAddress()
            obj.len=6
            obj.data=self.local_ip
            ipcp_option_list=[obj]
        else:
            ipcp_option_list=self.parser_ipcp_options()
        opt_len=len(ipcp_option_list)*6
        pppoe_len=opt_len+4+2
        loadbin=''
        loadbin=self.appendbin(loadbin,pppoe_len)
        ipcp_req=Ether(src=pkt.dst,dst=pkt.src,type=0x8864)/PPPoE(version=1,type=1,code=0,sessionid=pkt.sessionid,len=pppoe_len)/PPP(proto=0x8021)/PPP_IPCP(code=1,id=self.ipcp_id,len=opt_len+4,options=ipcp_option_list)/Raw(load=loadbin)
        if self.checked == 'ipcp_rej' and self.save_times == 1:
            obj_r = PPP_IPCP_Option()
            obj_r.type = 2
            obj_r.len=6
            obj_r.data=0x002d 
            ipcp_req.options.append(obj_r)
            ipcp_req[PPP_IPCP].len = ipcp_req[PPP_IPCP].len + 6
            ipcp_req[PPPoE].len = ipcp_req[PPPoE].len + 6
            self.save_times = 0
        self.pkt_list.append(ipcp_req)
        sendp(ipcp_req,iface=self.iface)

    def send_ipcp_packet(self,pkt):
        #如果为认证成功的pap报文或者chap报文
        #进入这里说明收到的IPCP的 requests报文或者
        #如果为NAK(3) 则照着回应一个request(1) 如果为REQ(1) 则回应一个ACK(2)
        #如果为REJECT(4) ,解析拒绝的内容然后继续REQ(1)
        raw = copy.deepcopy(pkt)
        code=pkt[PPP_IPCP].code
        raw[PPP_IPCP].code=2
        #解析出ip dns1 dns2 等地址 ,如果均为0则不进行添加
        if code == int('0x01',16) and self.ipv4_support == "True":
            if self.checked == 'ipcp_req' and self.save_times == 1: 
                self.save_packet(pkt)
                self.save_times = 0
            ret=pkt.options
            ret_len=len(ret)
            map_ipcp_dict={"03":"ip","81":"dns1","82":"nbns1","83":"dns2","84":"nbns2"}
            ipcp_dict={'ip':PPP_IPCP_Option_IPAddress,'dns1':PPP_IPCP_Option_DNS1,'dns2':PPP_IPCP_Option_DNS2}
            ipcp_list=[]
            for i in xrange(0,ret_len):
                if ret[i].data == "0.0.0.0":
                    raw[PPP_IPCP].code=3
                    ret[i].data=getattr(self,map_ipcp_dict["%02x" %(ret[i].type)])
            raw[PPP_IPCP].options=ret
            raw.src,raw.dst=pkt.dst,pkt.src
            self.pkt_list.append(raw)
            sendp(raw,iface=self.iface)
            self.ipcp_flag = 1
            if self.send_packet == 'padt':
                self.send_padt(pkt)
        elif code == int('0x02',16):
            if self.checked == 'ipcp_ack' and self.save_times == 1:
                self.save_packet(pkt)
                self.save_times = 0
        elif code == int('0x03',16):
            if self.checked == 'ipcp_nak' and self.save_times == 1: 
                self.save_packet(pkt)
                self.save_times = 0
                self.send_ipcp_req(pkt)
        elif code == int('0x04',16):
            if self.checked == 'ipcp_rej' and self.save_times == 1:
                self.save_packet(pkt)
                self.save_times = 0
                self.send_ipcp_req(pkt)

    def parser_ipcp_options(self):
        ipcp_dict={'ip':PPP_IPCP_Option_IPAddress,'dns1':PPP_IPCP_Option_DNS1,'dns2':PPP_IPCP_Option_DNS2,'nbns1':PPP_IPCP_Option_NBNS1,'nbns2':PPP_IPCP_Option_NBNS2}
        ret_str=[]
        for key,value in self.ipcp_options.items():
            if key in ipcp_dict.keys():
                obj=ipcp_dict[key]()
                obj.len=6
                obj.data=value
                ret_str.append(obj)
        return ret_str

    def send_ip_packet(self,pkt):
        pass

    def send_ipv6cp_paket(self,pkt):
        """
        判断收到的报文 pkt 中ipv6cp code 
        code 1 ---> IPV6CP configuration Request
             2 ---> IPV6CP configuration ACK
        是否为 1 ，若是 1 则回复 configuration ACK
        """
        if pkt.load[:1] == "\x01" and self.ipv6_support == "True":
            raw = copy.deepcopy(pkt)
            raw.src,raw.dst=pkt.dst,pkt.src
            raw.load = "\x02" + pkt.load[1:]
            self.pkt_list.append(raw)
            sendp(raw,iface=self.iface)

    def send_ipv6cp_request(self,pkt):
        """
        构造一个 IPV6CP configuration Request 报文
        并于指定网卡发送
        ①sessionid 由收到包获取
        ②"\x01\x01\x00\x0e\x01\x0a" 表示：
        IPV6CP 
            code            - 1
            Identifier      - 1
            length          - 14
            //** Options **//
            Interface Identifier:
        ③eui_64_setmac
            link-local MAC地址根据eui_64规则生成
            Interface Identifier地址
        """
        if self.ipv6_support == "True":
            raw = Ether(dst=pkt.src,src=pkt.dst,type=0x8864)/PPPoE(version=1,type=1,code=0x00,sessionid=pkt.sessionid,len=16)/PPP(proto=0x8057)/Raw(load="")
            value = self.eui_64_setmac(self.smac)
            raw.load = "\x01\x01\x00\x0e\x01\x0a" + self.mac2bin(value)
            self.pkt_list.append(raw)
            sendp(raw,iface=self.iface)

    def select_ipv6_paket(self,pkt):
        """
        根据收到的不同类型的包，做出对应回复
        收到 ICMPv6ND_RS      ---> ICMPv6ND_RA
             DHCP6_Solicit    ---> DHCPv6 Advertise
             DHCP6_Request    ---> DHCPv6 Reply
        """
        ipv6_type = 0
        select_ND = [
            "ICMPv6ND_RS",
            "ICMPv6ND_RA"
        ]
        select_type = [
            "DHCP6_Solicit",
            "DHCP6_Request"
          ]
        for i in select_ND:
            try:
                ipv6_type = pkt[i].type
                break
            except:
                continue
        if ipv6_type == 0:
            for i in select_type:
                try:
                    ipv6_type = pkt[i].msgtype
                    break
                except:
                    continue
        if ipv6_type == 133:
            self.send_icmpv6_RA(pkt)
        elif ipv6_type == 1 :
            time.sleep(0.5)
            Ether0 = Ether(dst=pkt.src,src=pkt.dst,type=0x8864)
            PPPoE0 = PPPoE(version=1,type=1,code=0x00,sessionid=pkt.sessionid,len=None)
            PPP0 = PPP(proto=pkt.proto)
            IPv60 = IPv6(version=6,tc=0,fl=0,plen=None,nh=17,hlim=1,src='fe80::1',dst=pkt[IPv6].src)
            UDP0 = UDP(sport=547,dport=546)
            DHCP6_Advertise0 = DHCP6_Advertise(msgtype=2,trid=pkt[DHCP6_Solicit].trid)
            DHCP6OptClientId0 = DHCP6OptClientId(optcode=pkt[DHCP6OptClientId].optcode,optlen=pkt[DHCP6OptClientId].optlen,duid=pkt[DHCP6OptClientId].duid)
            DHCP6OptServerId0 = DHCP6OptServerId(optcode=2,optlen=None,duid=DUID_LLT(type=1,hwtype=1,lladdr=self.smac))
            DHCP6OptIA_NA0 = DHCP6OptIA_NA(optcode=3,optlen=None,iaid=pkt.iaid,T1=600,T2=900,ianaopts=DHCP6OptIAAddress(optcode=5,optlen=None,addr=self.ip_addr,preflft=1300,validlft=2000,iaaddropts='\x00\r\x00\x02\x00\x00'))
            DHCP6OptIA_PD0 = DHCP6OptIA_PD(optcode=25,optlen=None,iaid=pkt.iaid,T1=600,T2=900,iapdopt=DHCP6OptIAPrefix(optcode=26,optlen=None,preflft=1300,validlft=2000,plen=None,prefix=self.prefix,iaprefopts='\x00\r\x00\x02\x00\x00'))
            DHCP6OptDNSServers0 = DHCP6OptDNSServers(optcode=23,optlen=None,dnsservers=self.dnsser)
            DHCP6OptDNSDomains0 = DHCP6OptDNSDomains(optcode=24,optlen=None,dnsdomains=self.dnsdomain)
            raw = Ether0/PPPoE0/PPP0/IPv60/UDP0/DHCP6_Advertise0/DHCP6OptClientId0/DHCP6OptServerId0/DHCP6OptIA_NA0/DHCP6OptIA_PD0/DHCP6OptDNSServers0/DHCP6OptDNSDomains0
            self.pkt_list.append(raw)
            sendp(raw,iface=self.iface)
        elif ipv6_type == 3 :
            Ether0 = Ether(dst=pkt.src,src=pkt.dst,type=0x8864)
            PPPoE0 = PPPoE(version=1,type=1,code=0x00,sessionid=pkt.sessionid,len=None)
            PPP0 = PPP(proto=pkt.proto)
            IPv60 = IPv6(version=6,tc=0,fl=0,plen=None,nh=17,hlim=pkt[IPv6].hlim,src='fe80::1',dst=pkt[IPv6].src)
            UDP0 = UDP(sport=547,dport=546)
            DHCP6_Reply0 = DHCP6_Reply(msgtype=7,trid=pkt[DHCP6_Request].trid)
            DHCP6OptClientId0 = DHCP6OptClientId(optcode=pkt[DHCP6OptClientId].optcode,optlen=pkt[DHCP6OptClientId].optlen,duid=pkt[DHCP6OptClientId].duid)
            DHCP6OptServerId0 = DHCP6OptServerId(optcode=2,optlen=None,duid=DUID_LLT(type=1,hwtype=1,lladdr=self.smac))
            DHCP6OptIA_NA0 = DHCP6OptIA_NA(optcode=3,optlen=None,iaid=pkt.iaid,T1=600,T2=900,ianaopts=DHCP6OptIAAddress(optcode=5,optlen=None,addr=self.ip_addr,preflft=1300,validlft=2000,iaaddropts='\x00\r\x00\x02\x00\x00'))
            DHCP6OptIA_PD0 = DHCP6OptIA_PD(optcode=25,optlen=None,iaid=pkt.iaid,T1=600,T2=900,iapdopt=DHCP6OptIAPrefix(optcode=26,optlen=None,preflft=1300,validlft=2000,plen=None,prefix=self.prefix,iaprefopts='\x00\r\x00\x02\x00\x00'))
            DHCP6OptDNSServers0 = DHCP6OptDNSServers(optcode=23,optlen=None,dnsservers=self.dnsser)
            DHCP6OptDNSDomains0 = DHCP6OptDNSDomains(optcode=24,optlen=None,dnsdomains=self.dnsdomain)
            raw = Ether0/PPPoE0/PPP0/IPv60/UDP0/DHCP6_Reply0/DHCP6OptClientId0/DHCP6OptServerId0/DHCP6OptIA_NA0/DHCP6OptIA_PD0/DHCP6OptDNSServers0/DHCP6OptDNSDomains0
            self.pkt_list.append(raw)
            sendp(raw,iface=self.iface)
        else:
            self.loop_ra = 1

    def eui_64_setmac(self,mac):
        """
        EUI-64规则  根据mac生成 接口-id
        """
        mac_list = mac.split(":")
        list_len = len(mac_list)
        ## 1 mac --> bin mac
        bintomac = ""
        for i in range(list_len):
            bin_m = bin(int(mac_list[i],16))[2:]
            if len(bin_m) == 8:
                bintomac += bin_m
            else:
                bintomac += "0"*(8-len(bin_m)) + bin_m
            if i < len(mac_list) -1:
                bintomac += ":" 
        ## 2 24 add FFFE(1111111111111110)
        bintomac = bintomac[:27] + "11001000:00111010:" + bintomac[27:]
        ## 3 set 7td 1
        bintomac = bintomac[:6] + "1" + bintomac[7:]
        mac_id = ""
        mac_list2 = bintomac.split(":")
        for i in range(len(mac_list2)):
            mac_id += hex(int(mac_list2[i],2))[2:]
            if i < len(mac_list2) -1:
                mac_id += ":"
        return mac_id

    def send_icmpv6_RA(self,pkt):
        """
        回复RS报文
        """
        raw = Ether(dst=pkt.src,src=pkt.dst,type=pkt[Ether].type)/PPPoE(version=1,type=1,code=pkt[PPPoE].code,sessionid=pkt[PPPoE].sessionid,len=58)/PPP(proto=0x0057)/IPv6(version=6,tc=0,fl=0,plen=16,nh=58,hlim=255,src="fe80::1",dst=pkt[IPv6].src)/ICMPv6ND_RA(type=134,code=0,cksum=None,chlim=64,M=1,O=1,H=0,P=0,res=0,routerlifetime=300,reachabletime=0,retranstimer=0) 
        self.pkt_list.append(raw)
        sendp(raw,iface=self.iface)

    def loop_icmpv6_RA(self,pkt):
        """
        未完善
        固定间隔发送 ICMPv6ND_RA报文
        """
        print("\n\nloop_icmpv6_RA")

    def update_option(self,load,key="pppoe",**kargs):
        #主要用于添加,删除,修改,查找load中某个字段的值
        #key 分别为pppoe lcp ipcp三种类型
        #第一步,先把load转换成16进制字符串形式,然后按照key进行拆分
        key_dict={"pppoe":4,"lcp":2,"ipcp":2}
        if load:
            loadhex=self.bin2hex(load)
            ret=self.parser_data(loadhex,key)
        else:
            ret={}
        new_ret=dict(ret,**kargs)
        loadbin=''
        # for k,v in new_ret.items():
        for k,v in new_ret.items():
            if len(v) == 0 and k !="0x0101":
                continue
            if key == "pppoe":
                kv_str=k[2:]+"%04x" %(len(v))+self.str2hex(v)
            else:
                kv_str=k[2:]+"%02x" %(len(v)+2)+self.str2hex(v)
            loadbin=loadbin+self.hex2bin(kv_str)
        return loadbin

    def parser_data(self,allstr,key):
        key_dict={"pppoe":4,"lcp":2,"ipcp":2}
        par_len=key_dict[key]
        two_len=par_len*2
        x="%0"+str(par_len)+"x"
        ret={}
        #如果为lcp或者ipcp则需要减去头部2byte
        decress_len=0
        left_shift=8
        if par_len == 2:
            decress_len=two_len
            left_shift=0
        while True:
            if allstr:
                type=eval('0x'+allstr[0:par_len])
                length=eval('0x'+allstr[par_len:two_len])
                value=allstr[two_len:two_len+length*2-decress_len]
                ret["0x"+x %(type)]=self.hex2bin(value)
                allstr=allstr[left_shift+length*2:]
            else:
                break
        return ret

    def str2hex(self,allstr):
        return "".join(map(lambda x:"%02X" %(ord(x)),list(allstr)))

    def tobin(self,var,flag="str",leng=2):
        function=getattr(self,"%s2bin" %(flag))
        if flag == "num":
            return function(var,leng)
        else:
            return function(var)
        #steps,str=>ascii(dec)==>ascii(hex)==>binstr
        hexstr="".join(map(lambda x:"%02X" %(ord(x)),list(allstr)))
        strbin=self.hex2bin(hexstr)
        return strbin

    def str2bin(self,allstr):
        #steps,str=>ascii(dec)==>ascii(hex)==>binstr
        hexstr="".join(map(lambda x:"%02X" %(ord(x)),list(allstr)))
        strbin=self.hex2bin(hexstr)
        return strbin

    def num2bin(self,num,leng="2"):
        hexstr=str("%0"+str(leng)+"X") %(num)
        binnum=self.hex2bin(hexstr)
        return binnum

    def ip2bin(self,ip,flag=". "):
        hexlist=re.split(r"[%s]" %(flag),ip)
        hexstr="".join(map(lambda x:"%02x" %(int(x)),hexlist))
        binip=self.hex2bin(hexstr)
        return binip

    def mac2bin(self,mac,flag=":-"):
        hexlist=re.split(r"[%s]" %(flag),mac)
        hexstr="".join(hexlist)
        binmac=self.hex2bin(hexstr)
        return binmac

    def hex2bin(self,hexstr):
        len_str=len(hexstr)
        retStr=""
        for i in range(0,len_str,2):
            substr=chr(int(hexstr[i:i+2],16))
            retStr=retStr+substr
        return retStr

    def bin2hex(self,binstr):
        hexstr="".join(map(lambda x:"%02X" %(ord(x)),list(binstr)))
        return hexstr

    def save_packet(self,pkt,op=0):
        """
        将交互过程的报文保存在packet文件夹中
        若无此文件夹，自动生成
        """
        if op:
            if os.path.exists(self.packall_dir):
                os.remove(self.packall_dir)
            wrpcap(self.packall_dir,pkt)
            print("\n"*6)
        else:
            if os.path.exists(self.dir):
                os.remove(self.dir)
            wrpcap(self.dir,pkt)
            

class Form(QWidget):  
    def __init__(self, parent=None):  
        super(Form, self).__init__(parent) 
        self.ui=Ui_Form()
        self.ui.setupUi(self)
        self.setWindowTitle(u"PPPoE-Server")
        global op_dict
        self.index_iface = {}
        self.macdict = {} #用于存放接口mac地址
        self.ipdict = {}  #用于存放MAC地址对应的IP地址
        self.init_iface()
        self.init_Smethod()
        self.init_Authen()
        self.init_hw_reply()
        self.init_check_pkt()
        self.init_lcp_op()
        self.init_send_pack()
        self.init_hw_mppe()
        self.init_ser_error()
        self.init_cfg()
        self.init_uioption()
        self.connect(self.ui.hw_save,SIGNAL("clicked()"),self.savecfg)
        self.connect(self.ui.hw_start,SIGNAL("clicked()"),self.startserver)
        self.runthread = RunThread(self)
        
    def get_inface(self):
        system = sys.platform
        ifacelist = []
        if "linux" in system:
            print('run program in Linux')
            # ifacelist=[]
            ifacedict = {}
            for x in xrange(30):
                try:
                    iface="eth%s" %(x)
                    obj=dnet.eth(iface)
                    mac = binascii.b2a_hex(obj.get()).upper()
                    ifacedict[mac] = iface
                    self.macdict[iface] = {}
                    self.macdict[iface]['mac'] = mac
                    ifacelist.append(iface)
                except Exception as e:
                    pass
            return ifacedict
        else: 
            # ifacedict = {"Realtek PCI GBE Family Controller":{"mac":"00:B0:C2:03:5B:C5"},"Realtek PCI GBE Family Controller #2":{"mac":"C8:3A:35:DB:BD:F9"},"Realtek PCIe GBE Family Controller":{"mac":"74:27:EA:A2:28:B5"}}
            # windows 系统
            # 获取windows电脑的网卡描述，排除VMware、Teredo、环回网卡
            print('run in Windows')
            # ifacelist = []
            data = os.popen('ipconfig /all').readlines()
            meg = '\xc3\xe8\xca\xf6'
            a3 = '\xbf\xed\xb4\xf8\xc1\xac\xbd\xd3' # ---> a3 = '宽带连接'
            for line in data:
                if line == "" or line == "\n":
                    continue
                if meg in line or '描述' in line:
                    if ("Microsoft" not in line) and ("VMware" not in line) and ("Teredo" not in line) and (a3 not in line):
                        index = line.index(':') + 2
                        interface = line[index:-1]
                        ifacelist.append(interface)
            # print ifacelist 一下几行是去除list重复项
            iface_list = []
            for ifa in ifacelist:
                if ifa not in iface_list:
                   iface_list.append(ifa)
            return iface_list
    
    def startserver(self):
        text=self.ui.hw_start.text()
        if text == u"Running...":
            print("stop...")
            self.runthread.stop_test()
            self.ui.hw_start.setText(u"Start")
        else:
            self.select_iface()
            self.savecfg(False)
            print("start...")
            self.ui.hw_start.setText(u"Running...")
            self.runthread.start_test()

    def savecfg(self,flag=True):
        """
        先把以前的信息读取出来
        然后以字典的形式保存在配置文件config.ini中
        再替换GUI上有的参数,没有的参数不操作
        """
        guidict = {}
        guidict['server']={}
        guidict['inface']={}
        guidict['support']={}
        guidict['ipv4_config']={}
        guidict['ipv6_config']={}
        
        # Server
        guidict['inface']['inface'] = self.ui.iface.currentText()
        guidict['server']['authen'] = self.ui.Authen.currentText()
        guidict['server']['hw_smac'] = self.ui.hw_smac.text()
        guidict['server']['pwd'] = self.ui.Pwd.text()
        guidict['server']['user'] = self.ui.User.text()
        guidict['server']['hw_sername'] = self.ui.hw_sername.text()
        guidict['server']['ac_name'] = self.ui.ac_name.text()
        # IPv4_Config
        guidict['ipv4_config']['hw_reply'] = self.ui.hw_reply.currentText()
        guidict['ipv4_config']['pro_rayload'] = self.ui.hw_reply.currentText()
        guidict['ipv4_config']['check_pkt'] = self.ui.check_pkt.currentText()
        guidict['ipv4_config']['lcp_op'] = self.ui.lcp_op.currentText()
        guidict['ipv4_config']['hw_server'] = self.ui.hw_server.text()
        guidict['ipv4_config']['hw_serip']=self.ui.hw_serip.text()
        guidict['ipv4_config']['hw_dns1'] = self.ui.hw_dns1.text()
        guidict['ipv4_config']['hw_dns2'] = self.ui.hw_dns2.text()
        guidict['ipv4_config']['wait_echoreq'] = self.ui.wait_echoreq.text()
        guidict['ipv4_config']['send_pack'] = self.ui.send_pack.currentText()
        guidict['ipv4_config']['hw_mppe'] = self.ui.hw_mppe.currentText()
        guidict['ipv4_config']['ser_error'] = self.ui.ser_error.currentText()
        # ipv6_config
        guidict['ipv6_config']['remoteip'] = self.ui.RemoteIp.text()
        guidict['ipv6_config']['ipv6prefix'] = self.ui.Ipv6Prefix.text()
        guidict['ipv6_config']['dnsserver'] = self.ui.DnsServer.text()
        guidict['ipv6_config']['domain'] = self.ui.Domain.text()
        guidict['ipv6_config']['support_method'] = self.ui.Support_method.currentText()
        # IPv6_fun
        guidict['support']['v6support'] = str(self.ui.V6Support.isChecked())
        # IPv4_fun
        guidict['support']['v4support'] = str(self.ui.V4Support.isChecked())
        init_dict = readcfg()
        cf = configparser.ConfigParser()
        for key,value in init_dict.items():
            cf.add_section(key)
            for k,v in value.items():
                # if guidict.has_key(key):
                if key in guidict:
                    if k in guidict[key]:
                    # if guidict[key].has_key(k):
                        cf.set(key, k, guidict[key][k])
                        continue
                cf.set(key, k, v)
        with open(ConfigFile,"w+") as f:
            cf.write(f)
        self.config=readcfg()
        print("config",self.config)
        if flag:
            QtGui.QMessageBox.information(self,"savecfg","saved ok",QtGui.QMessageBox.Yes)

    def init_cfg(self):
        self.config=readcfg()
        print("read config.ini")
        self.ui.Pwd.setText(self.config['server']['pwd'])
        self.ui.User.setText(self.config['server']['user'])
        self.ui.ac_name.setText(self.config['server']['ac_name'])
        self.ui.hw_sername.setText(self.config['server']['hw_sername'])
        self.ui.hw_smac.setText(self.config['server']['hw_smac'])
        self.ui.hw_server.setText(self.config['ipv4_config']['hw_server'])
        self.ui.hw_serip.setText(self.config['ipv4_config']['hw_serip'])
        self.ui.hw_dns1.setText(self.config['ipv4_config']['hw_dns1'])
        self.ui.hw_dns2.setText(self.config['ipv4_config']['hw_dns2'])
        self.ui.wait_echoreq.setText(self.config['ipv4_config']['wait_echoreq'])
        self.ui.RemoteIp.setText(self.config['ipv6_config']['remoteip'])
        self.ui.Ipv6Prefix.setText(self.config['ipv6_config']['ipv6prefix'])
        self.ui.DnsServer.setText(self.config['ipv6_config']['dnsserver'])
        self.ui.Domain.setText(self.config['ipv6_config']['domain'])

    def init_iface(self):
        ifacelst = self.get_inface()
        for ifa in ifacelst:
            self.ui.iface.addItem(ifa.strip())
        self.connect(self.ui.iface,SIGNAL("currentIndexChanged(int)"),self.select_iface)

    def select_iface(self):
        cur_iface = self.ui.iface.currentText()
        print("iface-->",cur_iface)
        self.iface=cur_iface

    def init_Smethod(self):
        Smethodlst = ['PPPoE+DHCPv6']
        for ifa in Smethodlst:
            self.ui.Support_method.addItem(ifa.strip())
        self.connect(self.ui.Support_method,SIGNAL("currentIndexChanged(int)"),self.select_Support_method)

    def select_Support_method(self):
        cur_iface=self.ui.Support_method.currentText()
        print("Support_method-->",cur_iface)
        self.Support_method=cur_iface

    def init_hw_mppe(self):
        mppe_lst = ["off","on"]
        for hw_mppe in mppe_lst:
            self.ui.hw_mppe.addItem(hw_mppe.strip())
        self.connect(self.ui.hw_mppe,SIGNAL("currentIndexChanged(int)"),self.select_hw_mppe)

    def select_hw_mppe(self):
        cur_hw_mppe=self.ui.hw_mppe.currentText()
        print("hw_mppe-->",cur_hw_mppe)
        self.hw_mppe=cur_hw_mppe
    
    def init_Authen(self):
        Authenlst = ["pap","chap"]
        for Authen in Authenlst:
            self.ui.Authen.addItem(Authen.strip())
        self.connect(self.ui.Authen,SIGNAL("currentIndexChanged(int)"),self.select_Authen)

    def select_Authen(self):
        cur_Authen = self.ui.Authen.currentText()
        print("Authen-->",cur_Authen)
        self.Authen=cur_Authen      

    def init_hw_reply(self):
        reply_lst = ["no","padi","padr","padt","lcp_terminate","echo_request","pap","chap"]
        for hw_reply in reply_lst:
            self.ui.hw_reply.addItem(hw_reply.strip())
        self.connect(self.ui.hw_reply,SIGNAL("currentIndexChanged(int)"),self.select_hw_reply)

    def select_hw_reply(self):
        cur_hw_reply = self.ui.hw_reply.currentText()
        print("hw_reply-->",cur_hw_reply)
        self.hw_reply=cur_hw_reply 

    def init_check_pkt(self):
        pkt_lst = ["---","padi","padr","padt","lcp_req","lcp_ack","lcp_nak","lcp_reject","lcp_option","lcp_terminate","terminate_ack","echo_request","pap_req","chap_res","ipcp_req","ipcp_ack","ipcp_nak","ipcp_rej"]
        for check_pkt in pkt_lst:
            self.ui.check_pkt.addItem(check_pkt.strip())
        self.connect(self.ui.check_pkt,SIGNAL("currentIndexChanged(int)"),self.select_check_pkt)

    def select_check_pkt(self):
        cur_select_check_pkt = self.ui.check_pkt.currentText()
        print("check_pkt-->",cur_select_check_pkt)
        self.check_pkt=cur_select_check_pkt 

    def init_lcp_op(self):
        op_lst = ["None","MRU:1","ACCM:2","AP:3","Quality:4","Magic:5","PFC:7","AaCFC:8","FCS:9","SDP:10","Numbered-M:11","MLP:12","Callback:13","CTime:14","Compound-F:15","NDE:16","MRRU:17","MSSNHF:18","MED:19","Proprie:20","DCE:21"]
        for lcp_op in op_lst:
            self.ui.lcp_op.addItem(lcp_op.strip())
        self.connect(self.ui.lcp_op,SIGNAL("currentIndexChanged(int)"),self.select_lcp_op)

    def select_lcp_op(self):
        cur_select_lcp_op = self.ui.lcp_op.currentText()
        print("lcp_op-->",cur_select_lcp_op)
        self.lcp_op=cur_select_lcp_op 

    def init_send_pack(self):
        send_pack_lst = ["None","padt","lcp_terminate"]
        for send_pack in send_pack_lst:
            self.ui.send_pack.addItem(send_pack.strip())
        self.connect(self.ui.send_pack,SIGNAL("currentIndexChanged(int)"),self.select_send_pack)

    def select_send_pack(self):
        cur_select_send_pack = self.ui.send_pack.currentText()
        print("send_pack-->",cur_select_send_pack)
        self.send_pack = cur_select_send_pack 

    def init_ser_error(self):
        # pads报文无session会话id，回应lcp_req标示符不一致
        ser_error_lst = ["None","pads_no_id","lcp_id_err"]
        for ser_error in ser_error_lst:
            self.ui.ser_error.addItem(ser_error.strip())
        self.connect(self.ui.ser_error,SIGNAL("currentIndexChanged(int)"),self.select_ser_error)

    def select_ser_error(self):
        cur_select_ser_error = self.ui.ser_error.currentText()
        print("ser_error-->",cur_select_ser_error)
        self.ser_error=cur_select_ser_error 
  
    def get_macMapDesc(self):
        c = wmi.WMI()
        mac_desc={}
        self.macipdict = {}
        for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=1):
            mac_desc["".join(interface.MACAddress.split(":"))]=interface.Description
            self.ipdict[interface.MACAddress] = interface.IPADDRESS[0]
        return mac_desc

    def init_uioption(self):
        #先把所有的设置为可写
        self.ui.Pwd.setEnabled(True)
        self.ui.User.setEnabled(True)
        self.ui.hw_ver.setEnabled(False)
        self.ui.hw_code.setEnabled(False)
        self.ui.hw_type.setEnabled(False)
        self.ui.pro_rayload.setEnabled(False)
        self.ui.hw_session_id.setEnabled(False)
        self.ui.hw_tag.setEnabled(False)
        self.ui.hw_server.setEnabled(True)
        self.ui.hw_serip.setEnabled(True)
        self.ui.hw_dns1.setEnabled(True)
        self.ui.hw_dns2.setEnabled(True)
        self.ui.hw_sername.setEnabled(True)
        self.ui.ac_name.setEnabled(True)
        self.ui.ser_error.setEnabled(True)

if __name__=="__main__":
    app = QApplication(sys.argv)
    form = Form()  
    form.show()
    sys.exit(app.exec()) 






