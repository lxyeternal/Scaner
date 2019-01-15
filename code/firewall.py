# _*_ coding:utf-8 _*_

'''
author:       guowenbo
us:           sichuanuniversity
time:         2018/12/27
explain:      ip for firewall state
'''

import sys
reload(sys)
sys.setdefaultencoding('utf8')
# os.sys.path.append('/Users/apple/anaconda3/envs/python3.6/lib/python2.7/site-packages')
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def find_firewall(ip,port):

    ACK_response = sr1(IP(dst=ip) / TCP(dport=port, flags='A'), timeout=1, verbose=0)
    SYN_response = sr1(IP(dst=ip) / TCP(dport=port, flags='S'), timeout=1, verbose=0)

    if (SYN_response == None  or ACK_response == None):
        ip_for_firewall = '防火墙状态： '+'open'
        print ('firewall is open')
    elif ((ACK_response == None) or (SYN_response == None)) and not ((ACK_response == None) and (SYN_response == None)):
        ip_for_firewall = '防火墙状态： '+'open'
        print ("firewall is open")
    elif (SYN_response[TCP].flags == 18) and (ACK_response[TCP].flags == 4):
        ip_for_firewall = '防火墙状态： ' + 'None'
        print ("Firewalls is close")
    elif (SYN_response[TCP].flags == 18) and (ACK_response == None):
        ip_for_firewall = '防火墙状态： '+'None'
        print ("port is filtered")
    elif (SYN_response == None) and (ACK_response[TCP].flags == 4):
        ip_for_firewall = '防火墙状态： '+'None'
        print ("port is filtered")
    else:
        ip_for_firewall = '防火墙状态： ' + 'None'
        print ("port is closed or host down")

    return ip_for_firewall

