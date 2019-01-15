# _*_ coding:utf-8 _*_
#!/usr/bin/python

from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
reload(sys)
sys.setdefaultencoding('utf8')

ip = '10.132.2.3'
port = 62078

ACK_response = sr1(IP(dst=ip)/TCP(dport=port,flags="A"),timeout=1,verbose=0)
SYN_response = sr1(IP(dst=ip)/TCP(dport=port,flags="S"),timeout=1,verbose=0)

if ((ACK_response == None) or (SYN_response == None)):
   print "Port is either unstatefully filtered or host is down"
elif ((ACK_response == None) or (SYN_response == None)) and not ((ACK_response == None) and (SYN_response == None)):
   print "Stateful filtering in place"    #防火墙在线#此句有逻辑问题，尚未修改</strong>
elif int(SYN_response[TCP].flags) == 18:
   print "Port is unfiltered and open"
elif int(SYN_response[TCP].flags) == 20:
   print "Port is unfiltered and closed"
else:
   print "Unable to determine if the port is filtered"