#!/usr/bin/env python2
#encoding=utf-8
import time,hashlib,struct,urllib2,sys,json,socket,re,urllib
import os.path
import pyDes,pyAes,binascii
import ConfigParser
config = ConfigParser.ConfigParser()

global g_u,g_p,g_mac,g_server,g_key,g_timer

class ReadConfig(object):
    def getConfig(self):
        global g_u,g_p,g_mac,g_server,g_key,g_timer
        config.read('setting.ini')
        g_u = config.get('userinfo', 'username')
        g_p = config.get('userinfo', 'password')
        g_mac = config.get('userinfo', 'mac')
        g_server = config.get('serverinfo', 'server')
        g_key = config.get('serverinfo', 'key')
        g_timer = config.get('serverinfo', 'time')
        g_timer = float(g_timer)

class NetUtil(object):
    def getIP(self):
        try:
            res=urllib2.urlopen('http://whois.pconline.com.cn/ipJson.jsp',timeout=2000)
        except:
            return None
        if res.getcode()!=200:
            return None
        re=res.read().decode('gbk').encode('utf8')
        res.close()
        re=re[re.rfind('{'):re.find('}')+1]
        return json.loads(re)

class SxHeartBeat(object):
    def __init__(self,acc,pwd,mac,server,key):
        self._acc=acc
        self._pwd=pwd
        self._mac=mac
        self._server=server
        self._key=key
        self._aes=pyAes.new(key,1)
        self._des=pyDes.triple_des('1234ZHEJIANGXINLIWANGLEI',pyDes.CBC,'12345678')
    def _padData(self,s,length=16):
        l=(length-len(s)%length)%length
        return s+l*chr(l)
    def HR10(self):
        sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ramdata=self._padData('type=6;%did=%s&pwd=%s;ver=%s;time=%d',8)
        data='%s%s%s%s'%('HR10',
                         '\x05\x00\x00\x00',
                         '\x28',
                         self._des.encrypt(ramdata)) 
        sock.sendto( data,(self._server, 444))
        sock.close()
    def HR20(self):
        sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ramdata=self._padData('7;%s;%s;%s;%s;%d;%s;%d')
        data='%s%s%s%s'%('HR20',
                         '\x05\x00\x00\x00',
                         '\x20',
                         self._aes.encrypt(ramdata))
        sock.sendto(data,(self._server, 445))
        sock.close()
    def HR30send1(self):
        sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ramdata=self._padData('8;%08x;%s;%s;%s;%d;%d')
        data='%s%s%s%s'%('HR30',
                         '\x02\x05\x00\x00\x00',
                         '\x20',
                         self._aes.encrypt(ramdata))
        sock.sendto(data,(self._server, 446))
        sock.close()
    def HR30send2(self):
        net=NetUtil()
        ip=net.getIP()
        if not ip:
            return ''
        else:
            ip=ip['ip']
        sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ramdata=self._padData('TYPE=HEARTBEAT&USER_NAME=%s&PASSWORD=%s&IP=%s&MAC=%s&DRIVER=1&VERSION_NUMBER=2.5.0016v32&HOOK=&IP2=%s'%(
            self._acc,self._pwd,ip,self._mac,ip))
        data='%s%s%s%s'%('HR30',
                         '\x02\x05\x00\x00\x00',
                         chr(len(ramdata)),
                         self._aes.encrypt(ramdata.encode('ascii')))
        sock.settimeout(2.0)
        sock.sendto(data,(self._server, 443))
        sock.close()
    def SendAllHB(self):
        #self.HR10()
        #self.HR20()
        self.HR30send1()
        self.HR30send2()
        time.sleep(1)
        self.HR30send2()
        return self._acc,self._pwd,self._mac,self._server,self._key

print('-----------------------------------\nMoMo-HeartBeat Beta v0.1\nby Sg4Dylan\nThis program is licensed under GPL license.\n-----------------------------------')
ReadConfig().getConfig()
while 1:
    print SxHeartBeat(g_u,g_p,g_mac,g_server,g_key).SendAllHB()
    print('Send OK')
    time.sleep(g_timer)