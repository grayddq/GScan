# coding:utf-8
from __future__ import print_function
import os, optparse, time, sys, json
from lib.core.globalvar import *


# 作者：咚咚呛
# 搜索指定时间内主机改动过的所有文件

class Search_File:
    def __init__(self, time):
        # self.time = time.strip()
        self.time = '2019-05-07 12:00:00~2019-05-07 17:00:00'

    def run(self):
        try:
            stime, etime = self.time.split('~')
            log_path = get_value('SYS_PATH') + "/log/search.log"
            DEBUG = get_value('DEBUG')
            files = os.popen("find / -newermt '%s' ! -newermt '%s' 2>/dev/null" % (stime, etime)).read().splitlines()
            print(u'时间周期：%s \n搜索结果：共发现 %d 处文件或者目录的创建和改动' % (self.time, len(files)))

            if os.path.exists(log_path):
                f = open(log_path, "r+")
                f.truncate()
                f.close()
            with open(log_path, 'a+') as f:
                for file in files:
                    f.write(file + '\n')
                    if DEBUG: print(file)
            print(u'结果详情：%s' % log_path)

        except:
            print(u'查询发生错误。')


if __name__ == '__main__':
    Search_File('2019-05-07 00:00:00~2019-05-07 12:00:00').run()
