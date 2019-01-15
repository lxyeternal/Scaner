# -*- coding: UTF-8 -*-

'''
author:       guowenbo
us:           sichuanuniversity
time:         2018/12/26
explain:      the program for UI
'''

from Tkinter import *
import matplotlib
matplotlib.use("TkAgg")
from PIL import Image, ImageTk
from all_information import *
from scanip import *

class MY_GUI():

    def __init__(self,parent_init_name):
        self.parent_init_name = parent_init_name
        self.ListIP = []
        self.ListInformation = []

    def set_init_windows(self):
        self.parent_init_name.title("局域网扫描器")
        self.parent_init_name.geometry('700x800+10+10')
        self.parent_init_name.resizable(width=True, height=True)
        self.textframe = Frame(self.parent_init_name)
        self. developer = LabelFrame(self.textframe, text="开发信息")
        self.developer.pack(padx=10, pady=10)
        self.textframe.pack()
        Label(self.developer, width=70, height=2, bg="white", text="开发人员：郭文博\n").grid(column=0, row=0)
        Label(self.developer, width=70, height=2, bg="white", text="开发环境：Mac os\n").grid(column=0, row=1)
        Label(self.developer, width=70, height=2, bg="white", text="开发时间：2018-12-20\n").grid(column=0, row=2)
        Label(self.developer, width=70, height=2, bg="white", text="版本号：D-1.00\n").grid(column=0, row=3)

    #  用户指定的输入网段以及端口
        self.user_input = Frame(self.parent_init_name)
        self.user_input_label = LabelFrame(self.user_input, text="扫描网段以及端口")
        self.user_input_label.pack(padx=10,pady=10)
        self.input_ip = StringVar()
        self.input_port = StringVar()
        self.input_help = Label(self.user_input_label, width=70, height=2, bg="white", text="请输入扫描的网段以及端口\n")
        self.entry_ip = Entry(self.user_input_label, width=70,bd = 0,textvariable=self.input_ip,background = 'green')
        self.entry_port = Entry(self.user_input_label, width=70,bd = 0,textvariable=self.input_port,background = 'green')
        self.entry_ip.bind('<Return>', self.get_ip_port)
        self.entry_port.bind('<Return>', self.get_ip_port)
        self.input_help.pack()
        self.entry_ip.pack()
        self.entry_port.pack()
        self.user_input_label.pack()
        self.user_input.pack()
        # get_ip_port(entry_ip.get(),entry_port.get())

    #  扫描的局域网主机ip信息
        self.IpFrame = Frame(self.parent_init_name)
        self.iplistframe = LabelFrame(self.IpFrame,text = "局域网在线主机ip")
        self.iplistframe.pack(padx=10, pady=10)
        self.listip = Listbox(self.iplistframe,width=70,bd = 0)
        self.listip.bind('<Double-Button-1>', self.get_ip_information)
        for item in self.ListIP:
            self.listip.insert(END,item)
        self.listip.pack()
        self.IpFrame.pack()

    #  主机的详细信息
    #  开放端口，os信息，防火墙，杀毒软件
    #  存在的安全漏洞
        self.Information = Frame(self.parent_init_name)
        self.ipinformation = LabelFrame(self.Information, text="局域网主机详细信息")
        self.ipinformation.pack(padx=10, pady=10)
        self.listinformation = Listbox(self.ipinformation, width=70, bd=0)
        for item in self.ListInformation :
            self.listinformation.insert(END, item)
        self.listinformation.pack()
        self.Information.pack()

    #  UI界面按钮
        self.buttonframe = Frame(self.parent_init_name)
        Button(self.buttonframe,text="开始", command=self.printhello).grid(column=0, row=0)
        Button(self.buttonframe, text="退出", command=self.exitui).grid(column=1, row=0)
        Button(self.buttonframe, text="帮助", command=self.help).grid(column=2, row=0)
        self.buttonframe.pack()

    def get_ip_port(self,event):

        ip_input = self.entry_ip.get()
        port_input = self.entry_port.get()
        #   对用户输入的端口信息进行处理
        startport, endport = getport(port_input)
        listip = getip(ip_input)
        #   使用多线程进程扫描在线的ip
        threads_find_ip(listip)
        #  对在线的ip列表进行排序
        sort_alive_ip(ip_alive_list)
        #  多线程对每一个ip的详细进行扫描
        time.sleep(20)
        a = all_infromation(startport, endport, ip_alive_list)
        a.Threads()
        time.sleep(60)
        self.listip.delete(0, END)
        for i in ip_alive_list:
            self.listip.insert(END,i)

    # 192.168.1.119
    def get_ip_information(self,event):

        index_ip = self.listip.curselection()
        # ip_for_list = ip_alive_list[index_ip[0]]
        all_information = all_ip_all_information[index_ip[0]]
        self.listinformation.delete(0, END)
        for item in all_information:
            self.listinformation.insert(END,item)



    def help(self):

        top = Toplevel()
        top.title("帮助")
        top.geometry('600x600')

        ImageFrame = Frame(top)
        ImgFrame = LabelFrame(ImageFrame,text = "help")
        im = Image.open("../image/1.jpg")
        img = ImageTk.PhotoImage(im)
        Label(ImgFrame, width=450,height=160,image=img).grid(row=0, column=0,columnspan=3)
        ImgFrame.pack()
        ImageFrame.pack()

        # pilImage = Image.open("1.png")
        # tkImage = ImageTk.PhotoImage(image=pilImage)
        # label = Label(top,image=tkImage)
        # label.pack()

        textframe = Frame(top)
        developer = LabelFrame(textframe, text="使用教程")
        developer.pack(padx=10, pady=10)
        textframe.pack()
        Label(developer, width=50, height=2, bg="white", text="环境配置：python3.6，python-nmap\n").grid(column=0, row=0)
        Label(developer, width=50, height=2, bg="white", text="开始按钮：点击即可开始扫描主机所在的网段的所有在线的主机\n").grid(column=0, row=1)
        Label(developer, width=50, height=2, bg="white", text="退出按钮：点击即可退出扫描程序                      \n").grid(column=0,row=2)
        Label(developer, width=50, height=2, bg="white", text="帮助按钮：提示程序如何进行使用                      \n").grid(column=0,row=3)
        Label(developer, width=50, height=2, bg="white", text="局域网主机ip：显示该网段的在线主机点击可查看特定主机的详细信息\n").grid(column=0, row=4)

        top.mainloop()

    def printhello(self,event):

        print("2")

    def exitui(self):

        exit(0)

def start():

    init_windows = Tk()
    ZMJ_PORTAL = MY_GUI(init_windows)
    ZMJ_PORTAL.set_init_windows()
    init_windows.mainloop()

