# coding:utf-8
from __future__ import print_function
import os, optparse, time, sys, json
from lib.common import *


# 作者：咚咚呛
# 分析主机文件类异常
# 1、系统可执行文件扫描
# 3、临时目录文件扫描
# 4、用户目录文件扫描
# 5、可疑隐藏文件扫描

class File_Analysis:
    def __init__(self):
        # 恶意文件列表
        self.file_malware = []
        # 恶意特征列表
        self.malware_infos = []
        # 获取恶意特征信息
        self.get_malware_info()
        # 系统完整性检测
        # self.check_system_integrity()
        # 临时目录文件扫描
        # self.check_tmp()
        # 可疑隐藏文件扫描
        # self.check_hide()

    # 检查系统文件完整性
    def check_system_integrity(self):
        suspicious, malice = False, False

        binary_list = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/local/sbin/', '/usr/local/bin/']
        try:
            for dir in binary_list:
                if not os.path.exists(dir): continue
                for file in gci(dir):
                    if not os.path.exists(file): continue
                    if os.path.isdir(file): continue
                    if (os.path.getsize(file) == 0) or (
                            round(os.path.getsize(file) / float(1024 * 1024)) > 10): continue
                    malware = self.analysis_file(file)
                    if malware:
                        self.file_malware.append(
                            {u'异常类型': u'文件恶意特征', u'文件路径': file, u'恶意特征': malware,
                             u'手工确认': u'[1]rpm -qa %s [2]strings %s' % (file, file)})
                        malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 检查所有临时目录文件
    def check_tmp(self):
        suspicious, malice = False, False
        tmp_list = ['/tmp/', '/var/tmp/', '/dev/shm/']
        try:
            for dir in tmp_list:
                if not os.path.exists(dir): continue
                for file in gci(dir):
                    if not os.path.exists(file): continue
                    if os.path.isdir(file): continue
                    if (os.path.getsize(file) == 0) or (
                            round(os.path.getsize(file) / float(1024 * 1024)) > 10): continue
                    malware = self.analysis_file(file)
                    if malware:
                        self.file_malware.append(
                            {u'异常类型': u'文件恶意特征', u'文件路径': file, u'恶意特征': malware,
                             u'手工确认': u'[1]rpm -qa %s [2]strings %s' % (file, file)})
                        malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 检查所有用户目录文件
    def check_user_dir(self):
        suspicious, malice = False, False
        dir_list = ['/home/', '/root/']
        try:
            for dir in dir_list:
                if not os.path.exists(dir): continue
                for file in gci(dir):
                    if not os.path.exists(file): continue
                    if os.path.isdir(file): continue
                    if (os.path.getsize(file) == 0) or (
                            round(os.path.getsize(file) / float(1024 * 1024)) > 10): continue
                    malware = self.analysis_file(file)
                    if malware:
                        self.file_malware.append(
                            {u'异常类型': u'文件恶意特征', u'文件路径': file, u'恶意特征': malware,
                             u'手工确认': u'[1]rpm -qa %s [2]strings %s' % (file, file)})
                        malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 可疑文件扫描
    def check_hide(self):
        suspicious, malice = False, False
        try:
            infos = os.popen(
                'find / -type f -name " *" -o -name ". *" -o -name "..." -o -name ".." -o -name "." -o -name " " -print | grep -v "No such" |grep -v "Permission denied"').read().splitlines()
            for file in infos:
                self.file_malware.append(
                    {u'异常类型': u'文件异常隐藏', u'文件路径': file, u'手工确认': u'[1]ls -l %s [2]strings %s' % (file, file)})
                suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 获取配置文件的恶意域名等信息
    def get_malware_info(self):
        try:
            if not os.path.exists('malware'): return
            for file in os.listdir('./malware/'):
                time.sleep(0.001)  # 防止cpu占用过大
                with open(os.path.join('%s%s' % ('./malware/', file))) as f:
                    for line in f:
                        if len(line) > 3:
                            if line[0] != '#': self.malware_infos.append(line.strip().replace("\n", ""))
        except:
            return

    # 分析文件是否包含恶意特征或者反弹shell问题
    def analysis_file(self, file):
        try:
            if not os.path.exists(file): return ""
            if os.path.isdir(file): return ""
            if os.path.islink(file): return ""
            if " " in file: return ""
            if 'GScan' in file: return ""
            if not os.path.exists(file) or (os.path.getsize(file) == 0) or (
                    round(os.path.getsize(file) / float(1024 * 1024)) > 10): return ""
            strings = os.popen("strings %s" % file).readlines()
            for str in strings:
                mal = check_shell(str)
                if mal: return mal
                for malware in self.malware_infos:
                    if malware in str: return malware
            return ""
        except:
            return ""

    def run(self):
        print(u'\n开始文件类安全扫描')
        print(align(u' [1]系统可执行文件安全扫描', 30) + u'[ ', end='')
        file_write(u'\n开始文件类安全扫描\n')
        file_write(align(u' [1]系统可执行文件安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        # 系统完整性检测
        suspicious, malice = self.check_system_integrity()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print(align(u' [2]系统临时目录安全扫描', 30) + u'[ ', end='')
        file_write(align(u' [2]系统临时目录安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        # 临时目录文件扫描
        suspicious, malice = self.check_tmp()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print(align(u' [3]各用户目录安全扫描', 30) + u'[ ', end='')
        file_write(align(u' [3]各用户目录安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        # 临时目录文件扫描
        suspicious, malice = self.check_user_dir()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print(align(u' [4]可疑隐藏文件扫描', 30) + u'[ ', end='')
        file_write(align(u' [4]可疑隐藏文件扫描', 30) + u'[ ')
        sys.stdout.flush()
        # 临时目录文件扫描
        suspicious, malice = self.check_hide()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)
        sys.stdout.flush()

        if len(self.file_malware) > 0:
            file_write('-' * 30 + '\n')
            file_write(u'文件检查异常如下：\n')
            for info in self.file_malware:
                file_write(json.dumps(info, ensure_ascii=False) + '\n')
            file_write('-' * 30)


if __name__ == '__main__':
    # File_Analysis().run()
    info = File_Analysis()
    info.run()
    print(u"文件检查异常如下：")
    for info in info.file_malware:
        print(info)
