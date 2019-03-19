# coding:utf-8
import os, optparse, time, re, sys, json
from ip import *
from lib.common import *


# 分析用户历史操作记录
# 1、获取所有用户目录下.bash_history文件
# 2、匹配操作非内网ip下载类信息
# 3、匹配非国内的ip

class History_Analysis:
    def __init__(self):
        # 恶意操作
        self.history = []
        self.ip_http = r'http(|s)://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        self.ip_re = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        self.lan_ip = r'(127\.0\.0\.1)|(localhost)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})'
        # self.get_all_history()

    # 获取所有用户下的操作记录，是否存在恶意ip
    def get_all_history(self):
        suspicious = False
        malice = False
        for dir in os.listdir('/home/'):
            suspicious, malice = self.file_analysis(os.path.join('%s%s%s' % ('/home/', dir, '/.bash_history')), dir)
        suspicious2, malice2 = self.file_analysis('/root/.bash_history', 'root')
        if suspicious2: suspicious = True
        if malice2: malice = True
        return suspicious, malice

    # 分析history文件的操作记录
    def file_analysis(self, file, user):
        suspicious = False
        malice = False
        if os.path.exists(file):
            with open(file) as f:
                for line in f:
                    if not re.search(self.ip_http, line): continue
                    if re.search(self.lan_ip, line): continue
                    for ip in re.findall(self.ip_re, line):
                        if find(ip)[0:2] != u'中国':
                            self.history.append({u'用户名': user, u'异常执行记录': line})
                            suspicious = True
        return suspicious, malice

    def run(self):
        print(u'\n开始主机历史操作类安全扫描')
        file_write(u'\n开始主机历史操作类安全扫描\n')
        print align(u' [1]所有历史操作的可疑记录', 30) + u'[ ',
        file_write(align(u' [1]所有历史操作的可疑记录', 30) + u'[ ')
        sys.stdout.flush()
        # 系统完整性检测
        suspicious, malice = self.get_all_history()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)
        sys.stdout.flush()

        if len(self.history) > 0:
            file_write('-' * 30 + '\n')
            file_write(u'可疑的操作记录如下：\n')
            for info in self.history:
                file_write(json.dumps(info, ensure_ascii=False) + '\n')
            file_write('-' * 30 + '\n')


if __name__ == '__main__':
    info = History_Analysis()
    info.run()
    print '可疑的操作记录如下：'
    for info in info.history:
        print info
