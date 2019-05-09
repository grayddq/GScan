# coding:utf-8
from __future__ import print_function
import os
from lib.core.ip.ip import *
from lib.core.common import *


# 作者：咚咚呛
# 分析用户历史操作记录
# 1、获取所有用户目录下.bash_history文件
# 2、匹配境外ip类操作

class History_Analysis:
    def __init__(self):
        # 恶意操作
        self.history = []
        self.name = u'主机历史操作类安全检测'

    # 获取所有用户下的操作记录，是否存在恶意ip
    def get_all_history(self):
        suspicious, malice = False, False
        try:
            # 待检测的目录和文件
            file_path = ['/home/', '/root/.bash_history', '/Users/']
            for path in file_path:
                if not os.path.exists(path): continue
                # 目录类，获取目录下的.bash_history文件
                if os.path.isdir(path):
                    for dir in os.listdir(path):
                        file = os.path.join('%s%s%s' % (path, dir, '/.bash_history'))
                        if not os.path.exists(file):continue
                        with open(file) as f:
                            for line in f:
                                contents = analysis_strings(line)
                                if not contents: continue
                                malice_result(self.name, u'history文件安全扫描', file, '', contents, u'[1]cat %s' % file,
                                              u'风险')
                                malice = True
                # 文件类，进行文件的操作分析
                else:
                    with open(path) as f:
                        for line in f:
                            contents = analysis_strings(line)
                            if not contents: continue
                            malice_result(self.name, u'history文件安全扫描', file, '', contents, u'[1]cat %s' % file, u'风险')
                            malice = True
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
        result_output_file(self.name)


if __name__ == '__main__':
    info = History_Analysis()
    info.run()
