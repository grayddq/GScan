# coding:utf-8
import os, optparse, time
from SSHAnalysis import *
from common import *


class Log_Analysis:
    def __init__(self):
        self.log_malware = []

    def check_sshlog(self):
        suspicious, malice = False, False
        correct_baopo_infos = SSH_Analysis(log_dir='/var/log/').correct_baopo_infos
        if len(correct_baopo_infos)>0:
            for info in correct_baopo_infos:
                self.log_malware.append({'name':'sshlog','ip':info['ip'],'user':info['user'],'time':info['time']})
                malice = True
        return suspicious, malice


    def run(self):
        print(u'\n开始日志类安全扫描')
        print align(u' [1]SSH日志安全扫描', 30) + u'[ ',
        file_write(u'\n开始日志类安全扫描\n')
        file_write(align(u' [1]SSH日志安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_sshlog()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        if len(self.log_malware) > 0:
            file_write('-' * 30+'\n')
            file_write(u'日志分析如下：\n')
            for info in self.log_malware:
                file_write(str(info) + '\n')
            file_write('-' * 30 + '\n')

if __name__ == '__main__':
    infos = Log_Analysis()
    infos.run()
    print u"日志分析如下："
    for info in infos.log_malware:
        print info