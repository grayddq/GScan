# coding:utf-8
from __future__ import print_function
import os, time, sys, json, re
from lib.common import *
from lib.ip.ip import *


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

        self.ip_http = r'(htt|ft)p(|s)://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        self.ip_re = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        self.lan_ip = r'(127\.0\.0\.1)|(localhost)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})'

    # 检查系统文件完整性
    # 由于速度的问题，故只检测指定重要文件
    def check_system_integrity(self):
        suspicious, malice = False, False

        system_file = ["depmod", "fsck", "fuser", "ifconfig", "ifdown", "ifup", "init", "insmod", "ip", "lsmod",
                       "modinfo", "modprobe", "nologin", "rmmod", "route", "rsyslogd", "runlevel", "sulogin", "sysctl",
                       "awk", "basename", "bash", "cat", "chmod", "chown", "cp", "cut", "date", "df", "dmesg", "echo",
                       "egrep", "env", "fgrep", "find", "grep", "kill", "logger", "login", "ls", "mail", "mktemp",
                       "more", "mount", "mv", "netstat", "ping", "ps", "pwd", "readlink", "rpm", "sed", "sh", "sort",
                       "su", "touch", "uname", "gawk", "mailx", "adduser", "chroot", "groupadd", "groupdel", "groupmod",
                       "grpck", "lsof", "pwck", "sestatus", "sshd", "useradd", "userdel", "usermod", "vipw", "chattr",
                       "curl", "diff", "dirname", "du", "file", "groups", "head", "id", "ipcs", "killall", "last",
                       "lastlog", "ldd", "less", "lsattr", "md5sum", "newgrp", "passwd", "perl", "pgrep", "pkill",
                       "pstree", "runcon", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "size", "ssh",
                       "stat", "strace", "strings", "sudo", "tail", "test", "top", "tr", "uniq", "users", "vmstat", "w",
                       "watch", "wc", "wget", "whereis", "which", "who", "whoami"]

        binary_list = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/local/sbin/', '/usr/local/bin/']
        try:
            for dir in binary_list:
                if not os.path.exists(dir): continue
                for file in gci(dir):
                    filename = os.path.basename(file)
                    if not filename in system_file: continue
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
            malware_path = sys.path[0] + '/lib//malware/'
            if not os.path.exists(malware_path): return
            for file in os.listdir(malware_path):
                with open(malware_path + file) as f:
                    for line in f:
                        malware = line.strip().replace('\n', '')
                        if len(malware) > 5:
                            if malware[0] != '#' and malware[0] != '.' and ('.' in malware):
                                self.malware_infos.append(malware)
        except:
            return

    # 分析字符串是否包含境外IP
    def check_contents_ip(self, contents):
        try:
            if not re.search(self.ip_http, contents): return False
            if re.search(self.lan_ip, contents): return False
            for ip in re.findall(self.ip_re, contents):
                if (find(ip)[0:2] != u'中国') and (find(ip)[0:3] != u'局域网') and (find(ip)[0:4] != u'共享地址') and (find(ip)[0:4] != u'本机地址'):
                    return True
            return False
        except:
            return False

    # 分析文件是否包含恶意特征、反弹shell特征、境外ip类信息
    def analysis_file(self, file):
        try:
            time.sleep(0.05)
            if not os.path.exists(file): return ""
            if os.path.isdir(file): return ""
            if " " in file: return ""
            if 'GScan' in file: return ""
            if '.log' in file: return ""
            if (os.path.getsize(file) == 0) or (round(os.path.getsize(file) / float(1024 * 1024)) > 10): return ""
            strings = os.popen("strings %s" % file).readlines()
            if len(strings) > 200: return ""
            for str in strings:
                time.sleep(0.01)
                mal = check_shell(str)
                if mal: return mal
                for malware in self.malware_infos:
                    if malware.replace('\n', '') in str:
                        return malware
                if self.check_contents_ip(str): return str
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
