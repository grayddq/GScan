# coding:utf-8
from __future__ import print_function
import os, optparse, time, json
from lib.plugins.SSHAnalysis import *
from lib.core.common import *
from lib.core.ip.ip import *
from subprocess import Popen, PIPE


# 作者：咚咚呛
# 版本：v0.1
# 功能：日志类安全分析

class Log_Analysis:
    def __init__(self):
        self.log_malware = []
        self.name = u'日志类安全检测'

    # wtmp日志登陆分析，排查境外IP的登陆日志
    def check_wtmp(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/var/log/wtmp'): return suspicious, malice
            p1 = Popen("who /var/log/wtmp 2>/dev/null", stdout=PIPE, shell=True)
            p2 = Popen("awk '{print $1\" \"$3\" \"$5}'", stdin=p1.stdout, stdout=PIPE, shell=True)
            wtmp_infos = p2.stdout.read().splitlines()
            for wtmp_info in wtmp_infos:
                if wtmp_info:
                    if len(wtmp_info.split(' ')) != 3: continue
                    user = wtmp_info.split(' ')[0]
                    time = wtmp_info.split(' ')[1]
                    ips = wtmp_info.split(' ')[2]
                    if ips[0] != '(': continue
                    ip = ips.replace('(', '').replace(')', '').replace('\n', '')
                    if check_ip(ip):
                        malice_result(self.name, u'wtmp登陆历史排查', u'/var/log/wtmp', '', u'境外IP使用%s登陆主机：%s' % (user, ip),
                                      u'[1]who /var/log/wtmp', u'可疑', time, user,
                                      programme=u'passwd %s #更改%s用户密码' % (user, user))
                        suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # wtmp日志登陆分析，排查境外IP的登陆日志
    def check_utmp(self):
        suspicious, malice = False, False
        try:
            p1 = Popen("who 2>/dev/null", stdout=PIPE, shell=True)
            p2 = Popen("awk '{print $1\" \"$3\" \"$5}'", stdin=p1.stdout, stdout=PIPE, shell=True)
            utmp_infos = p2.stdout.read().splitlines()
            for utmp_info in utmp_infos:
                if utmp_info:
                    if len(utmp_info.split(' ')) != 3: continue
                    user = utmp_info.split(' ')[0]
                    time = utmp_info.split(' ')[1]
                    ips = utmp_info.split(' ')[2]
                    if ips[0] != '(': continue
                    ip = ips.replace('(', '').replace(')', '').replace('\n', '')
                    if check_ip(ip):
                        malice_result(self.name, u'utmp登陆历史排查', u'/run/utmp', '', u'境外IP使用%s登陆主机：%s' % (user, ip),
                                      u'[1]who', u'可疑', time, user, programme=u'passwd %s #更改%s用户密码' % (user, user))
                        suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # wtmp日志登陆分析，排查境外IP的登陆日志
    def check_lastlog(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/var/log/lastlog'): return suspicious, malice
            p1 = Popen("lastlog 2>/dev/null", stdout=PIPE, shell=True)
            p2 = Popen("awk '{if (NR>1){print $1\" \"$3}}'", stdin=p1.stdout, stdout=PIPE, shell=True)
            lastlogs = p2.stdout.read().splitlines()
            for lastlog in lastlogs:
                if lastlog:
                    if len(lastlog.split(' ', 3)) != 3: continue
                    user = lastlog.split(' ')[0].strip()
                    ip = lastlog.split(' ')[1].replace(' ', '').replace('\n', '')
                    if check_ip(ip):
                        malice_result(self.name, u'lastlog登陆历史排查', u'/var/log/lastlog', '',
                                      u'境外IP使用%s登陆主机：%s' % (user, ip), u'[1]who', u'可疑', "", user,
                                      programme=u'passwd %s #更改%s用户密码' % (user, user))
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
                    user = info['user']
                    time = os.popen("date -d '" + info['time'] + "' '+%Y-%m-%d %H:%M:%S' 2>/dev/null").read().splitlines()[0]
                    ip = info['ip']
                    malice_result(self.name, u'secure日志排查', u'/var/log/secure', '',
                                  u'主机SSH被外部爆破且成功登陆，时间：%s，ip：%s，用户：%s' % (time, ip, user), u'[1]cat /var/secure', u'风险',
                                  time, user, programme=u'passwd %s #更改%s用户密码' % (user, user))
                    malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    def run(self):
        print(u'\n开始日志类安全扫描')
        file_write(u'\n开始日志类安全扫描\n')

        string_output(u' [1]secure日志安全扫描')
        suspicious, malice = self.check_sshlog()
        result_output_tag(suspicious, malice)

        string_output(u' [2]wtmp日志日志安全扫描')
        suspicious, malice = self.check_wtmp()
        result_output_tag(suspicious, malice)

        string_output(u' [3]utmp日志日志安全扫描')
        suspicious, malice = self.check_utmp()
        result_output_tag(suspicious, malice)

        string_output(u' [4]lastlog日志日志安全扫描')
        suspicious, malice = self.check_lastlog()
        result_output_tag(suspicious, malice)

        # 检测结果输出到文件
        result_output_file(self.name)


if __name__ == '__main__':
    infos = Log_Analysis()
    infos.run()
