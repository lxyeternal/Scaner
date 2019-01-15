# _*_ coding:utf-8 _*_

'''
author:     guowenbo
us:         sichuanuniversity
time:       2018/12/28
explain:    all_alive_ip for all_infromation(include ip,mac,firewall-state,open-port...)
'''


from Antivirus_software import *
from scanport import *
from mac import *
from firewall import *
from finger_os import *
from ip_bug import *

threads = []
all_ip_all_information = []
class all_infromation():

    def __init__(self,startport,endport,ip_alive_list):
        self.startport = startport
        self.endport = endport
        self.ip_alive_list = ip_alive_list

    def Threads(self):

        for i in self.ip_alive_list:
            thread = threading.Thread(target=self.all, args=(i,))
            threads.append(thread)
            thread.start()
        thread.join()

    def all(self,ip):

        ip_firewall = ''
        all_port_list = ''
        ip_address  = 'IP地址为： ' + ip
        one_ip_all_infromation = []
        scaner = ScanPort(self.startport, self.endport, ip)
        ip_for_portlist = scaner.scan_port()

        for port in ip_for_portlist:
            all_port_list = all_port_list + ',' + str(port)
        ip_port_list = '端口开放情况：' + all_port_list

        if len(ip_for_portlist) == 0:

            ip_firewall == '防火墙状态： open'
        else:

            for test_firewall in ip_for_portlist:

                ip_firewall = find_firewall(ip,test_firewall)                   #防火墙信息

        ip_mac = scan_ip_mac(ip)                                            # mac地址信息

        ip_Antivirus_software = find_Antivirus_software(ip_for_portlist)   #杀毒软件类型

        ip_os = find_os(ip)                                                 #操作系统的类型

        ip_bug_for_mysql = ip_bug_mysql_pwempty(ip)                     #主机漏洞扫描
        ip_bug_for_mongodb = ip_bug_mongodb(ip)
        ip_bug_for_ftp = ip_ftp(ip)
        ip_bug_for_cve = ip_cve(ip)
        one_ip_all_infromation.append(ip_address)
        one_ip_all_infromation.append(ip_mac)
        one_ip_all_infromation.append(ip_port_list)
        one_ip_all_infromation.append(ip_os)
        one_ip_all_infromation.append(ip_firewall)
        one_ip_all_infromation.append(ip_Antivirus_software)
        one_ip_all_infromation.append(ip_bug_for_mysql)
        one_ip_all_infromation.append(ip_bug_for_mongodb)
        one_ip_all_infromation.append(ip_bug_for_ftp)
        one_ip_all_infromation.append(ip_bug_for_cve)


        # for i in one_ip_all_infromation:
        #     print (i)

        all_ip_all_information.append(one_ip_all_infromation)


# ip_list = ['10.132.2.158']
#
# a = all_infromation(1,1000,ip_list)
# a.Threads()

# str(member).decode('string_escape')
# for i in all_ip_all_information[0]:
#
#     print (i)
# for i in all_ip_all_information[1]:
#
#     print (i)

