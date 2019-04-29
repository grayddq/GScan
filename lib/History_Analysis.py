# coding:utf-8
from __future__ import print_function
import os, optparse, time, re, sys, json
from lib.ip.ip import *
from lib.common import *


# 作者：咚咚呛
# 分析用户历史操作记录
# 1、获取所有用户目录下.bash_history文件
# 2、匹配境外ip类操作

class History_Analysis:
    def __init__(self):
        # 恶意操作
        self.history = []

    # 获取所有用户下的操作记录，是否存在恶意ip
    def get_all_history(self):
        suspicious, malice = False, False
        try:
            for dir in os.listdir('/home/'):
                suspicious, malice = self.file_analysis(os.path.join('%s%s%s' % ('/home/', dir, '/.bash_history')), dir)
            suspicious2, malice2 = self.file_analysis('/root/.bash_history', 'root')
            if suspicious2: suspicious = True
            if malice2: malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 分析history文件的操作记录
    def file_analysis(self, file, user):
        suspicious, malice = False, False
        try:
            if os.path.exists(file):
                with open(file) as f:
                    for line in f:
                        if analysis_strings(line):
                            self.history.append({u'用户名': user, u'异常执行记录': line})
                            suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    def run(self):
        print(u'\n开始主机历史操作类安全扫描')
        file_write(u'\n开始主机历史操作类安全扫描\n')

        string_output(u' [1]所有历史操作的可疑记录')
        suspicious, malice = self.get_all_history()
        result_output_tag(suspicious, malice)

        # 检测结果输出到文件
        result_output_file(u'可疑的操作记录如下：\n', self.history)


if __name__ == '__main__':
    info = History_Analysis()
    info.run()
    print('可疑的操作记录如下：')
    for info in info.history:
        print(info)
