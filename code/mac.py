# -*- coding: UTF-8 -*-

'''
author:      guowenbo
us:          sichuanuniversity
time:        2018/12/27
explain:     ip for mac
'''

import sys
reload(sys)
sys.setdefaultencoding('utf8')
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def scan_ip_mac(ip):


            arpPkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
            res = srp1(arpPkt, timeout=1, verbose=0)
            time.sleep(1)
            if res:
                # print ("IP: " + res.psrc + "     MAC: " + res.hwsrc)
                ip_for_mac = 'Mac地址：' + str(res.hwsrc)
            else:
                ip_for_mac = 'Mac地址：' + '未知'

            return  ip_for_mac

