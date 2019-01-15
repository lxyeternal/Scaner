# _*_ coding:utf-8 _*_

'''
author:     guowenbo
us:         sichuanuniversity
time:       2018/12/27
explain:    ip for bug
'''

from nmap import *

#   对于主机存在的漏洞这里我们使用的是nmap进行扫描
'''
具体参数：

nmap -p 80 –script http-iis-short-name-brute +ip(192.168.1.1)[验证iis短文件名泄露] 
nmap -sV -p 11211 -script memcached-info +ip[验证Memcached未授权访问漏洞] 
nmap -sV -（-）script http-vuln-cve2015-1635 +ip[验证http.sys远程代码执行漏洞] 
nmap -sV –script=ssl-heartbleed +ip[验证心脏出血漏洞] 
nmap -p 27017 –script mongodb-info +ip[验证Mongodb未授权访问漏洞] 
nmap -p 6379 –script redis-info +ip[验证Redis未授权访问漏洞] 
nmap –script=http-vuln-cve2015-1427 –script-args command=’ls’ +ip[验证Elasticsearch未授权访问漏洞] 
nmap -p 873 –script rsync-brute –script-args ‘rsync-brute.module=www’ [验证Rsync未授权访问漏洞]
nmap –max-parallelism 800–script http-slowloris scanme.nmap.org  [http 拒绝服务]
nmap -p3306 --script=mysql-empty-password.nse  [mysql空口令登录漏洞]
nmap -p 21 --script ftp-anon.nse -v + ip[检查目标ftp是否允许匿名登录]
'''

def ip_bug_mysql_pwempty(ip):

    # ip_bug_mysql_pwempty
    nm = PortScannerYield()
    bug = nm.scan(ip,arguments='nmap -p3306 --script=mysql-empty-password.nse')

    for i in bug:
        scan = i[1]['scan']
        try:
            if scan:
                info = i[1]['scan'][ip]['tcp'][3306]['script']['mysql-empty-password']
                if info:
                    ip_bug_mysql = 'mysql空口令漏洞：' + info
                else:
                    ip_bug_mysql = 'mysql空口令漏洞：' + '无'
            else:
                ip_bug_mysql = 'mysql空口令漏洞：' + '无'

        except KeyError:
            ip_bug_mysql = 'mysql空口令漏洞：' + '无'
        print (ip_bug_mysql)
        return  ip_bug_mysql

def ip_bug_mongodb(ip):

    nm = PortScannerYield()
    bug = nm.scan(ip, arguments='nmap -p27017 --script=mongodb-info.nse')

    for i in bug:
        global ip_mongodb
        scan = i[1]['scan']
        try:
            if scan:
                info = i[1]['scan'][ip]['tcp'][27017]['reason']

                if info == 'conn-refused':
                    ip_mongodb = 'Mongodb未授权访问漏洞：' + '无'
                    print (ip_mongodb)
            else:
                ip_mongodb = 'Mongodb未授权访问漏洞：' + '无'

        except KeyError:
            ip_mongodb = 'Mongodb未授权访问漏洞：' + '无'

        return ip_mongodb

def ip_ftp(ip):

    nm = PortScannerYield()
    bug = nm.scan(ip, arguments='nmap -p 21 --script ftp-anon.nse -v')
    for i in bug:
        ip_bug_ftp = ''
        try:
            scan = i[1]['scan'][ip]['tcp']

            if scan:
                info = i[1]['scan'][ip]['tcp'][21]['reason']

                if info == 'conn-refused':
                    ip_bug_ftp = 'ftp匿名登录漏洞：' + '无'
                    # print (ip_bug_ftp)
            else:
                ip_bug_ftp = 'ftp匿名登录漏洞：' + '无'

        except KeyError:

            ip_bug_ftp = 'ftp匿名登录漏洞：' + '无'
        return ip_bug_ftp


def ip_cve(ip):

    nm = PortScannerYield()
    bug = nm.scan(ip, arguments='sudo nmap --script vulscan -sV')

    for i in bug:

        # print (i[1]['scan'][ip]['tcp'].values()[0]['script']['vulscan'])
        try:
            scan = i[1]['scan'][ip]['tcp'].values()[0]['script']['vulscan']
            ip_bug_cve = 'CVE--' + scan

        except KeyError:
            ip_bug_cve = 'CVE--' + 'None'

        return ip_bug_cve

