# coding:utf-8
from __future__ import print_function
import os, re
from lib.core.common import *
from lib.core.ip.ip import *
from subprocess import Popen, PIPE


# 作者：咚咚呛
# 配置安全类检测
# 1、dns配置检测
# 2、防火墙配置检测
# 3、hosts配置检测

class Config_Analysis:
    def __init__(self):
        self.config_suspicious = []
        self.ip_re = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        self.name = u'配置类安全检测'

    # 检测dns设置
    def check_dns(self):
        suspicious, malice = False, False
        try:
            if os.path.exists('/etc/resolv.conf'):
                shell_process = os.popen(
                    'cat /etc/resolv.conf 2>/dev/null| grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"').read().splitlines()
                for ip in shell_process:
                    if not check_ip(ip): continue
                    if ip == '8.8.8.8': continue
                    malice_result(self.name, u'DNS安全配置', u'/etc/resolv.conf', '', u'DNS设置为境外IP: %s' % ip,
                                  u'[1]cat /etc/resolv.conf', u'可疑', programme=u'vi /etc/resolv.conf #删除或者更改DNS境外配置')
                    suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 检测防火墙设置
    def check_iptables(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/etc/sysconfig/iptables'): return suspicious, malice
            with open('/etc/sysconfig/iptables') as f:
                for line in f:
                    if len(line) < 5: continue
                    if line[0] != '#' and 'ACCEPT' in line:
                        malice_result(self.name, u'防火墙安全配置', u'/etc/sysconfig/iptables', '',
                                      u'存在iptables ACCEPT策略: %s' % line, u'[1]cat /etc/sysconfig/iptables', u'可疑',
                                      programme=u'vi /etc/sysconfig/iptables #删除或者更改ACCEPT配置')
                        suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 检测hosts配置信息
    def check_hosts(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists("/etc/hosts"): return suspicious, malice
            p1 = Popen("cat /etc/hosts 2>/dev/null", stdout=PIPE, shell=True)
            p2 = Popen("awk '{print $1}'", stdin=p1.stdout, stdout=PIPE, shell=True)
            for ip_info in p2.stdout.read().splitlines():
                if not re.search(self.ip_re, ip_info): continue
                if not check_ip(ip_info.strip().replace('\n', '')): continue
                malice_result(self.name, u'HOSTS安全配置', u'/etc/hosts', '', u'存在境外IP设置: %s' % ip_info,
                              u'[1]cat /etc/hosts', u'可疑', programme=u'vi /etc/hosts #删除或者更改境外hosts配置')
                suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    def run(self):
        print(u'\n开始配置类安全扫描')
        file_write(u'\n开始配置类安全扫描\n')

        string_output(u' [1]DNS设置扫描')
        suspicious, malice = self.check_dns()
        result_output_tag(suspicious, malice)

        string_output(u' [2]防火墙设置扫描')
        suspicious, malice = self.check_iptables()
        result_output_tag(suspicious, malice)

        string_output(u' [3]hosts设置扫描')
        suspicious, malice = self.check_hosts()
        result_output_tag(suspicious, malice)

        # 检测结果输出到文件
        result_output_file(self.name)


if __name__ == '__main__':
    infos = Config_Analysis()
    infos.run()
