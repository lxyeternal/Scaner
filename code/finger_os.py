# _*_  coding:utf-8 _*_

'''
author:      guowenbo
us:          sichuanuniversity
time:        2018/12/27
explain:     ip for finger-os information
'''

import sys
reload(sys)
sys.setdefaultencoding('utf8')
# os.sys.path.append('/Users/apple/anaconda3/envs/python3.6/lib/python2.7/site-packages')
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

'''

主机的操作系统扫描，基于tcp协议栈的扫描

'''
# import re
# from scapy.data import KnowledgeBase
# from scapy.config import conf
# from scapy.error import warning
# from scapy.layers.inet import IP, TCP, UDP, ICMP, UDPerror, IPerror
# from scapy.packet import NoPayload
# from scapy.sendrecv import sr
# from scapy.compat import *
# import scapy.modules.six as six
#
#
# finger_ip_os = []
#
# conf.nmap_os_base = "/usr/local/share/nmap/nmap-os-db"
#
# # macos /usr/local/share/nmap/nmap-os-db
#
#
# _NMAP_LINE = re.compile('^([^\\(]*)\\(([^\\)]*)\\)$')
#
#
# class NmapKnowledgeBase(KnowledgeBase):
#     """A KnowledgeBase specialized in Nmap first-generation OS
# fingerprints database. Loads from conf.nmap_os_base when self.filename is
# None.
#
#     """
#     def lazy_init(self):
#         try:
#             fdesc = open(conf.nmap_os_base
#                          if self.filename is None else
#                          self.filename, "rb")
#         except (IOError, TypeError):
#             warning("Cannot open nmap database [%s]", self.filename)
#             self.filename = None
#             return
#
#         self.base = []
#         name = None
#         sig = {}
#         for line in fdesc:
#             line = plain_str(line)
#             line = line.split('#', 1)[0].strip()
#             if not line:
#                 continue
#             if line.startswith("Fingerprint "):
#                 if name is not None:
#                     self.base.append((name, sig))
#                 name = line[12:].strip()
#                 sig = {}
#                 continue
#             if line.startswith("Class "):
#                 continue
#             line = _NMAP_LINE.search(line)
#             if line is None:
#                 continue
#             test, values = line.groups()
#             sig[test] = dict(val.split('=', 1) for val in
#                              (values.split('%') if values else []))
#         if name is not None:
#             self.base.append((name, sig))
#         fdesc.close()
#
#
# nmap_kdb = NmapKnowledgeBase(None)
#
#
# def nmap_tcppacket_sig(pkt):
#     res = {}
#     if pkt is not None:
#         res["DF"] = "Y" if pkt.flags.DF else "N"
#         res["W"] = "%X" % pkt.window
#         res["ACK"] = "S++" if pkt.ack == 2 else "S" if pkt.ack == 1 else "O"
#         res["Flags"] = str(pkt[TCP].flags)[::-1]
#         res["Ops"] = "".join(x[0][0] for x in pkt[TCP].options)
#     else:
#         res["Resp"] = "N"
#     return res
#
#
# def nmap_udppacket_sig(snd, rcv):
#     res = {}
#     if rcv is None:
#         res["Resp"] = "N"
#     else:
#         res["DF"] = "Y" if rcv.flags.DF else "N"
#         res["TOS"] = "%X" % rcv.tos
#         res["IPLEN"] = "%X" % rcv.len
#         res["RIPTL"] = "%X" % rcv.payload.payload.len
#         res["RID"] = "E" if snd.id == rcv[IPerror].id else "F"
#         res["RIPCK"] = "E" if snd.chksum == rcv[IPerror].chksum else (
#             "0" if rcv[IPerror].chksum == 0 else "F"
#         )
#         res["UCK"] = "E" if snd.payload.chksum == rcv[UDPerror].chksum else (
#             "0" if rcv[UDPerror].chksum == 0 else "F"
#         )
#         res["ULEN"] = "%X" % rcv[UDPerror].len
#         res["DAT"] = "E" if (
#             isinstance(rcv[UDPerror].payload, NoPayload) or
#             raw(rcv[UDPerror].payload) == raw(snd[UDP].payload)
#         ) else "F"
#     return res
#
#
# def nmap_match_one_sig(seen, ref):
#     cnt = sum(val in ref.get(key, "").split("|")
#               for key, val in six.iteritems(seen))
#     if cnt == 0 and seen.get("Resp") == "N":
#         return 0.7
#     return float(cnt) / len(seen)
#
#
# def nmap_sig(target, oport=80, cport=81, ucport=1):
#     res = {}
#
#     tcpopt = [("WScale", 10),
#               ("NOP", None),
#               ("MSS", 256),
#               ("Timestamp", (123, 0))]
#     tests = [
#         IP(dst=target, id=1) /
#         TCP(seq=1, sport=5001 + i, dport=oport if i < 4 else cport,
#             options=tcpopt, flags=flags)
#         for i, flags in enumerate(["CS", "", "SFUP", "A", "S", "A", "FPU"])
#     ]
#     tests.append(IP(dst=target)/UDP(sport=5008, dport=ucport)/(300 * "i"))
#
#     ans, unans = sr(tests, timeout=2)
#     ans.extend((x, None) for x in unans)
#
#     for snd, rcv in ans:
#         if snd.sport == 5008:
#             res["PU"] = (snd, rcv)
#         else:
#             test = "T%i" % (snd.sport - 5000)
#             if rcv is not None and ICMP in rcv:
#                 warning("Test %s answered by an ICMP", test)
#                 rcv = None
#             res[test] = rcv
#
#
#     return nmap_probes2sig(res)
#
# def nmap_probes2sig(tests):
#     tests = tests.copy()
#     res = {}
#     if "PU" in tests:
#         res["PU"] = nmap_udppacket_sig(*tests["PU"])
#         del tests["PU"]
#     for k in tests:
#         res[k] = nmap_tcppacket_sig(tests[k])
#
#     return res
#
#
# def nmap_search(sigs):
#     guess = 0, []
#     print ('----------')
#     for osval, fprint in nmap_kdb.get_base():
#         score = 0.0
#         print (osval)
#         for test, values in six.iteritems(fprint):
#             if test in sigs:
#                 score += nmap_match_one_sig(sigs[test], values)
#         score /= len(sigs)
#         if score > guess[0]:
#             guess = score, [osval]
#         elif score == guess[0]:
#             guess[1].append(osval)
#     print ("_____********______")
#     finger_ip_os.append(guess)
#     print (guess)
#     return guess
#
#
# @conf.commands.register
# def nmap_fp(target, oport=80, cport=81):
#     """nmap fingerprinting
# nmap_fp(target, [oport=80,] [cport=81,]) -> list of best guesses with accuracy
# """
#     sigs = nmap_sig(target, oport, cport)
#     return nmap_search(sigs)
#
#
# @conf.commands.register
# def nmap_sig2txt(sig):
#     torder = ["TSeq", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "PU"]
#     korder = ["Class", "gcd", "SI", "IPID", "TS",
#               "Resp", "DF", "W", "ACK", "Flags", "Ops",
#               "TOS", "IPLEN", "RIPTL", "RID", "RIPCK", "UCK", "ULEN", "DAT"]
#     txt = []
#     for i in sig:
#         if i not in torder:
#             torder.append(i)
#     for test in torder:
#         testsig = sig.get(test)
#         if testsig is None:
#             continue
#         txt.append("%s(%s)" % (test, "%".join(
#             "%s=%s" % (key, testsig[key]) for key in korder if key in testsig
#         )))
#     return "\n".join(txt)
#
#
# def scan_ip_os(iplist):
#
#    for i in iplist:
#        print(i)
#        load_module("nmap")
#        conf.nmap_os_base
#        nmap_fp(i)

# ip_list = ['10.132.2.158','10.132.2.3']
# scan_ip_os(ip_list)

'''
操作系统的探测利用ttl进行判断

win2000---->108 
winNT------>107 
win9x------>128 or 127 
WIN7------->64
WINDOWS 95/98 --> 32
solaris---->252 
IRIX------->240 
AIX------->247 
Linux----->64
'''

def find_os(ip):

    r = sr1(IP(dst = ip) / ICMP(), timeout = 1, verbose = 0)

    if r == None:
        ip_for_os = '操作系统类型：' + 'None'
    elif r[IP].ttl <= 64:
        ip_for_os = '操作系统类型：' + 'Linux or Unix'
        print "Linux or Unix!"
    elif r[IP].ttl == 108:
        ip_for_os = '操作系统类型：' + 'Window2000'
        print "Window2000!"
    elif r[IP].ttl == 107:
        ip_for_os = '操作系统类型：' + 'win NT'
        print "win NT!"
    elif r[IP].ttl == 127:
        ip_for_os = '操作系统类型：' + 'win9x'
        print "win9x"
    elif r[IP].ttl == 252:
        ip_for_os = '操作系统类型：' + 'solaris'
        print "solaris"
    elif r[IP].ttl == 128:
        ip_for_os = '操作系统类型：' + 'Windows XP'
        print "Windows XP"
    else:
        ip_for_os = '操作系统类型：' + 'Unix'
        print "Unix!"

    return ip_for_os

'''
iplist = ['192.168.92.129','192.168.92.130']
for i in iplist:
    print (i)
    print (find_os(i))
'''