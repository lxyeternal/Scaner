# -*- coding: utf-8 -*-

'''
author:         guowenbo
us:             sichuanuniversity
time:           2018/12/27
explain:        ip for open-port
'''

from socket import *
import threading
import time

lock = threading.Lock()

class ScanPort():

    def __init__(self,startport,endport,ip):

        self.openNum = 0
        self.portlist = []
        self.port_alive_list = []
        self.ip = ip
        self.startport = int(startport)
        self.endport = int(endport)

    def portScanner(self,host, port):


        # syn = IP(dst=hostname) / TCP(dport=(int(lport), int(hport)), flags=2)
        # result_raw = sr(syn, timeout=1, verbose=False)
        # # 取出收到结果的数据包，做成一个清单
        # result_list = result_raw[0].res
        # for i in range(len(result_list)):
        #     # 判断清单的第i个回复的接受到的数据包，并判断是否有TCP字段
        #     if (result_list[i][1].haslayer(TCP)):
        #         # 得到TCP字段的头部信息
        #         TCP_Fields = result_list[i][1].getlayer(TCP).fields
        #         # 判断头部信息中的flags标志是否为18(syn+ack)
        #         if TCP_Fields['flags'] == 18:
        #             print('端口号: ' + str(TCP_Fields['sport']) + ' is Open!!!')

        try:
            s = socket(AF_INET, SOCK_STREAM)
            s.connect((host, port))
            lock.acquire()
            self.openNum += 1
            lock.release()
            s.close()
            self.portlist.append(port)
            # print(port)
        except:
            pass


    def scan_port(self):
        setdefaulttimeout(1)
        self.endport = int(self.endport) + 1
        ret = int(int(self.endport) - int(self.startport))
        for n in range(1,100):
            threads = []
            # print (n-1)*880,n*880
            for p in range((n - 1) * int(ret/100)+self.startport, n * int(ret/100)+self.startport):
                t = threading.Thread(target=self.portScanner, args=(self.ip, p))
                time.sleep(0.001)
                threads.append(t)
                t.start()
            for t in threads:
                pass
            t.join()  # 在子线程完成运行之前，这个子线程的父线程将一直被阻塞。
        self.portlist.sort()
        # for i in portlist:
        #     print(i)
        self.port_alive_list.append(self.portlist)
        # print (self.port_alive_list)
        # print('[*] The scan is complete!')
        # print('[*] A total of %d open port ' % (self.openNum))
        return self.portlist



# iplist = ['10.132.2.240','10.132.2.158','10.132.2.14']
# for i in iplist:
#     print (i)
#     scaner = ScanPort(1,10000,i)
#     scaner.scan_port()
#     print (scaner.portlist)
