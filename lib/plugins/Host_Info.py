# coding:utf-8
import socket, os, time, platform, sys
from lib.core.common import *


# 作者：咚咚呛
# 版本：v0.1
# 功能：获取本机信息

class Host_Info:
    def __init__(self):
        # 主机名
        self.hostname = ""
        # 主机ip
        self.ip = ""
        # 主机版本
        self.version = ""
        # 主机时间
        self.time = ""

        self.host_info()
        self.get_host_ip()

    # 获取主机基本信息
    def host_info(self):
        self.hostname = platform.node()
        # self.hostname = socket.gethostname()
        self.version = platform.platform()
        self.time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

    def get_host_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            self.ip = s.getsockname()[0]
        finally:
            s.close()

    def run(self):
        print(u'\n主机信息获取')
        print(u'主机名：%s' % self.hostname)
        print(u'主机IP：%s' % self.ip)
        print(u'系统版本：%s' % self.version)
        print(u'主机时间：%s' % self.time)
        sys.stdout.flush()
        file_write(u'主机信息获取\n主机名：%s\n主机IP：%s\n系统版本：%s\n主机时间：%s\n' % (self.hostname, self.ip, self.version, self.time))


if __name__ == '__main__':
    a = Host_Info()
    print(a.hostname)
    print(a.ip)
    print(a.version)
    print(a.time)
