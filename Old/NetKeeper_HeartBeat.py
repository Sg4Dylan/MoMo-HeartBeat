#!/usr/bin/env python2
#encoding=utf-8
#该脚本请配合定时任务使用 建议的定时任务配置见 sx.conf

import time,hashlib,struct,sys,socket,urllib2,json
import os.path
from Crypto.Cipher import AES
from Crypto.Cipher import DES3

#HR01
des=DES3.new('1234ZHEJIANGXINLIWANGLEI',2,'12345678')
#HR02 HR03
aes=AES.new('wanglibinwanglei',1)
#HeartBeat Server
server='117.21.209.186'

g_u='test@nchuout' #帐号
g_p='test' #密码
g_mac='08:00:27:00:24:FD' #MAC地址 半角冒号分割

def HR10(): #心跳包HR10
    sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ramdata='type=6;%did=%s&pwd=%s;ver=%s;time=%d' #原始数据
    l=(8-len(ramdata)%8)%8 #填充
    ramdata=ramdata+l*chr(l)
    data='%s%s%s%s'%('HR10',#header
                     '\x05\x00\x00\x00',#
                     '\x28',#size
                     des.encrypt(ramdata)) #加密
    sock.sendto( data,(server, 444))
    sock.close()

def HR20(): #心跳包HR20
    sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ramdata='7;%s;%s;%s;%s;%d;%s;%d'
    l=(16-len(ramdata)%16)%16
    ramdata=ramdata+l*chr(l)
    data='%s%s%s%s'%('HR20',
                     '\x05\x00\x00\x00',
                     '\x20',
                     aes.encrypt(ramdata))
    sock.sendto(data,(server, 445))
    sock.close()

def HR30send1(): #心跳包HR30
    sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ramdata='8;%08x;%s;%s;%s;%d;%d'
    l=(16-len(ramdata)%16)%16
    ramdata=ramdata+l*chr(l)
    data='%s%s%s%s'%('HR30',
                     '\x02\x05\x00\x00\x00',
                     '\x20',
                     aes.encrypt(ramdata))
    sock.sendto(data,(server, 446))
    sock.close()

def getIP(): #获取外网ip
    res=urllib2.urlopen('http://whois.pconline.com.cn/ipJson.jsp',timeout=2000)
    if res.getcode()!=200:
        return None
    re=res.read().decode('gbk').encode('utf8')
    res.close()
    re=re[re.rfind('{'):re.find('}')+1]
    return json.loads(re)

def HR30send2(): #心跳包HR30
    #导入全局参数
    global g_u,g_p,g_mac
    us=g_u
    pw=g_p
    mac=g_mac
    #获取IP
    ip=getIP()
    if not ip:
        return ''
    else:
        ip=ip['ip']
    #发送
    sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ramdata='TYPE=HEARTBEAT&USER_NAME=%s&PASSWORD=%s&IP=%s&MAC=%s&DRIVER=1&VERSION_NUMBER=2.5.0016v32&HOOK=&IP2=%s'%(
        us,pw,ip,mac,ip)
    #这里使用mac系统的心跳包
    l=(16-len(ramdata)%16)%16
    ramdata=ramdata+l*chr(l)
    data='%s%s%s%s'%('HR30',
                     '\x02\x05\x00\x00\x00',
                     chr(len(ramdata)),
                     aes.encrypt(ramdata))
    sock.settimeout(2.0)
    sock.sendto(data,(server, 443))
    sock.close()
    print('Sending HB to %s, with USERNAME: %s PASSWORD: %s IP: %s MAC: %s' % (server, us, pw ,ip, mac))

def sendHeart():
    #HR10()
    #HR20()
    HR30send1()
    HR30send2()
    time.sleep(1)

def main():
    sendHeart()

if __name__=='__main__':
    main()
