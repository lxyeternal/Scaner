# -*- coding: UTF-8 -*-

'''
author:       guowenbo
us:           sichuanuniversity
time:         2018/1/3
explain:      ip for Antivirus_software
'''



#  利用端口的开放情况去判断杀毒软件的类型
#  诺顿杀软：2969
#  瑞星杀软：1688，1689

def find_Antivirus_software(port_list):

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

    if 2696 in port_list:

        Ip_for_Antivirus_software = '杀毒软件类型：'+'诺顿杀软'

    elif (1688 or 1689) in port_list:

        Ip_for_Antivirus_software = '杀毒软件类型：' +'瑞星杀软'

    else:

        Ip_for_Antivirus_software = '杀毒软件类型：' + 'None'

    return Ip_for_Antivirus_software
