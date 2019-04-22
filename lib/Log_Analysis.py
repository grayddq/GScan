# coding:utf-8
from __future__ import print_function
import os, optparse, time, json
from lib.SSHAnalysis import *
from lib.common import *
from lib.ip.ip import *
from subprocess import Popen, PIPE


# 作者：咚咚呛
# 版本：v0.1
# 功能：日志类安全分析

class Log_Analysis:
    def __init__(self):
        self.log_malware = []

    # wtmp日志登陆分析，排查境外IP的登陆日志
    def check_wtmp(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/var/log/wtmp'): return suspicious, malice
            p1 = Popen("who /var/log/wtmp", stdout=PIPE, shell=True)
            p2 = Popen("awk '{print $1\" \"$5}'", stdin=p1.stdout, stdout=PIPE, shell=True)
            wtmp_infos = p2.stdout.readlines()
            for wtmp_info in wtmp_infos:
                if wtmp_info:
                    if len(wtmp_info.split(' ')) != 2: continue
                    user = wtmp_info.split(' ')[0]
                    ips = wtmp_info.split(' ')[1]
                    if ips[0] != '(': continue
                    ip = ips.replace('(', '').replace(')', '')
                    if (find(ip)[0:2] != u'中国') and (find(ip)[0:3] != u'局域网') and (find(ip)[0:4] != u'共享地址'):
                        self.log_malware.append(
                            {u'日志类型': u'wtmp登陆历史记录', u'境外IP': ip, u'用户': user, u'可疑特征': u'境外IP登陆主机',
                             u'排查参考命令': u'[1]who /var/log/wtmp'})
                        suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # wtmp日志登陆分析，排查境外IP的登陆日志
    def check_utmp(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/var/log/utmp'): return suspicious, malice
            p1 = Popen("who", stdout=PIPE, shell=True)
            p2 = Popen("awk '{print $1\" \"$5}'", stdin=p1.stdout, stdout=PIPE, shell=True)
            utmp_infos = p2.stdout.readlines()
            for utmp_info in utmp_infos:
                if utmp_info:
                    if len(utmp_info.split(' ')) != 2: continue
                    user = utmp_info.split(' ')[0]
                    ips = utmp_info.split(' ')[1]
                    if ips[0] != '(': continue
                    ip = ips.replace('(', '').replace(')', '')
                    if (find(ip)[0:2] != u'中国') and (find(ip)[0:3] != u'局域网') and (find(ip)[0:4] != u'共享地址'):
                        self.log_malware.append(
                            {u'日志类型': u'wtmp登陆历史记录', u'境外IP': ip, u'用户': user, u'可疑特征': u'境外IP登陆主机',
                             u'排查参考命令': u'[1]who /var/log/wtmp'})
                        suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 排查secure SSH的爆破记录
    def check_sshlog(self):
        suspicious, malice = False, False
        try:
            correct_baopo_infos = SSH_Analysis(log_dir='/var/log/').correct_baopo_infos
            if len(correct_baopo_infos) > 0:
                for info in correct_baopo_infos:
                    self.log_malware.append(
                        {u'日志类型': u'SSH被成功爆破', u'来源IP': info['ip'], u'用户': info['user'], u'爆破时间': info['time']})
                    malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    def run(self):
        print(u'\n开始日志类安全扫描')
        print(align(u' [1]secure日志安全扫描', 30) + u'[ ', end='')
        file_write(u'\n开始日志类安全扫描\n')
        file_write(align(u' [1]secure日志安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_sshlog()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print(align(u' [2]wtmp日志日志安全扫描', 30) + u'[ ', end='')
        file_write(align(u' [4]wtmp日志日志安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_wtmp()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print(align(u' [3]utmp日志日志安全扫描', 30) + u'[ ', end='')
        file_write(align(u' [4]utmp日志日志安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_utmp()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        if len(self.log_malware) > 0:
            file_write('-' * 30 + '\n')
            file_write(u'日志分析结果如下：\n')
            for info in self.log_malware:
                file_write(json.dumps(info, ensure_ascii=False) + '\n')
            file_write('-' * 30 + '\n')


if __name__ == '__main__':
    infos = Log_Analysis()
    infos.run()
    print(u"日志分析如下：")
    for info in infos.log_malware:
        print(info)
