# coding:utf-8
import os, optparse, time, sys
from common import *
from ip import *


# 配置安全类检测
# 1、dns配置检测
# 2、防火墙配置检测

class Config_Analysis:
    def __init__(self):
        self.config_suspicious = []

    # 检测dns设置
    def check_dns(self):
        suspicious, malice = False, False
        shell_process = os.popen(
            'cat /etc/resolv.conf | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"').read().splitlines()
        for ip in shell_process:
            if (find(ip)[0:2] != u'中国') and (find(ip)[0:3] != u'局域网') and (find(ip)[0:4] != u'共享地址'):
                self.config_suspicious.append(
                    {'config': 'dns servername: %s' % ip, 'name': 'abroad dns', 'description': 'abroad dns',
                     'file': '/etc/resolv.conf'})
                suspicious = True
        return suspicious, malice

    # 检测防火墙设置
    def check_iptables(self):
        suspicious, malice = False, False
        shell_process = os.popen("iptables -L -n| grep -v 'Chain'|grep 'ACCEPT'").read().splitlines()
        for iptables in shell_process:
            self.config_suspicious.append(
                {'config': iptables, 'name': 'iptables ACCEPT', 'description': 'iptables ACCEPT', 'file': ''})
            suspicious = True
        if os.path.exists('/etc/sysconfig/iptables'):
            with open('/etc/sysconfig/iptables') as f:
                for line in f:
                    if len(line) > 5:
                        if (line[0] != '#') and ('ACCEPT' in line):
                            self.config_suspicious.append(
                                {'config': line, 'name': 'iptables ACCEPT', 'description': 'iptables ACCEPT',
                                 'file': '/etc/sysconfig/iptables'})
                            suspicious = True
        return suspicious, malice

    def run(self):
        print(u'\n开始配置类安全扫描')
        print align(u' [1]DNS设置扫描', 30) + u'[ ',
        sys.stdout.flush()
        suspicious, malice = self.check_dns()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print align(u' [2]防火墙设置扫描', 30) + u'[ ',
        sys.stdout.flush()
        suspicious, malice = self.check_iptables()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)


if __name__ == '__main__':
    infos = Config_Analysis()
    infos.run()
    print u"可疑配置类如下："
    for info in infos.config_suspicious:
        print info
