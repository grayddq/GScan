# coding:utf-8
from __future__ import print_function
from subprocess import Popen, PIPE
import os
from lib.core.common import *


# 作者：咚咚呛
# 系统初始化检测
# 1、文件alias配置检测


class SYS_INIT:
    def __init__(self):
        # 异常信息
        self.backdoor_info = []

    def check_alias_conf(self):
        suspicious, malice = False, False
        try:
            files = ['/root/.bashrc', '/root/.bash_profile', '/etc/bashrc']

            for dir in os.listdir('/home/'):
                suspicious2, malice2 = self.alias_file_analysis(os.path.join('%s%s%s' % ('/home/', dir, '/.bashrc')))
                if suspicious2: suspicious = True
                if malice2: malice = True

                suspicious2, malice2 = self.alias_file_analysis(os.path.join('%s%s%s' % ('/home/', dir, '/.bash_profile')))
                if suspicious2: suspicious = True
                if malice2: malice = True

            for file in files:
                suspicious2, malice2 = self.alias_file_analysis(file)
                if suspicious2: suspicious = True
                if malice2: malice = True

            return suspicious, malice
        except:
            return suspicious, malice

    # 分析环境变量alias配置文件的信息
    def alias_file_analysis(self, file):
        suspicious, malice = False, False
        try:
            # 程序需要用到的系统命令
            syscmds = ['ps', 'strings', 'netstat', 'find', 'echo', 'iptables', 'lastlog', 'who', 'ifconfig']
            if not os.path.exists(file): return suspicious, malice
            with open(file) as f:
                for line in f:
                    if line[:5] == 'alias':
                        for syscmd in syscmds:
                            if 'alias ' + syscmd + '=' in line:
                                self.backdoor_info.append(
                                    {u'异常类型': u'系统重要命令被设置alias', u'异常信息': line,
                                     u'排查参考命令': u'[1]alias [2]cat %s' % file})
                                suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    def run(self):
        print(u'\n检测系统初始化扫描')
        file_write(u'\n检测系统初始化扫描\n')

        string_output(u' [1]alias检查')
        suspicious, malice = self.check_alias_conf()
        result_output_tag(suspicious, malice)

        # 检测结果输出到文件
        result_output_file(u'系统初始化检查：', self.backdoor_info)



if __name__ == '__main__':
    init = SYS_INIT()
    init.run()
    print(u"可疑alias配置如下：")
    for info in init.backdoor_info:
        print(info)
