# Scaner


环境配置：

首先要求：python 3.6</br>
响应的库函数：matplotlib ，python-scapy，logging，threading，python-nmap</br>
本机需要安装的程序：nmap</br>
cript-vulscan配置参考：https://www.jianshu.com/p/3bc47bb361f8</br>


1. Finger_os.py:</br>
>>> 该文件是用来探测操作系统的，其中有一种是基于nmap修改的扫描探测方式。另一种是基于ttl的探测。默认是ttl	的。（配置：需要修改nmap_os_db的位置>>> 为本机的相应的位置）</br>
2. Scanport.py：</br>
>>> 该文件是用来探测开放端口信息的</br>
3. Ip_bug.py：</br>
>>> 该文件是用来探测常见的漏洞的。（需要配置script-vulscan）</br>
4. Mac.py：</br>
>>> 该文件是用来探测mac地址的</br>
5. Firewall.py：</br>
>>> 该文件是用来探测防火墙状态的</br>
6. Antivirus_softwar.py：</br>
>>> 该文件是用来探测杀毒软件的</br>
7. Scanip.py：</br>
>>> 该文件是用来处理接受的输入同时扫描在线的ip主机并进行排序</br>
8. all_information.py：</br>
>>> 该文件是将以上的信息进行整合的代码</br>
9. UI.py：</br>
>>> 该文件是实现UI界面</br>
10. Main.py：</br>
>>> 主函数的执行入口</br>

该项目在实现上还有很多的不足和缺陷，在后面如果有时间的话还是会继续完善的
