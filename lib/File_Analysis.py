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
                       "watch", "wc", "wget", "whereis", "which", "who", "whoami", "test"]

        binary_list = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/local/sbin/', '/usr/local/bin/']
        try:
            for dir in binary_list:
                if not os.path.exists(dir): continue
                for file in gci(dir):
                    filename = os.path.basename(file)
                    if not filename in system_file: continue
                    malware = analysis_file(file)
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
                    malware = analysis_file(file)
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
                    malware = analysis_file(file)
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
                'find / -type f -name ". *" -o -name "...*" -o -name "..*" -not -path "/proc/*" -not -path "/run/*" -not -path "/private/*"').read().splitlines()
            for file in infos:
                self.file_malware.append(
                    {u'异常类型': u'文件异常隐藏', u'文件路径': file, u'手工确认': u'[1]ls -l %s [2]strings %s' % (file, file)})
                suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    def run(self):
        print(u'\n开始文件类安全扫描')
        file_write(u'\n开始文件类安全扫描\n')

        string_output(u' [1]系统可执行文件安全扫描')
        suspicious, malice = self.check_system_integrity()
        result_output_tag(suspicious, malice)

        string_output(u' [2]系统临时目录安全扫描')
        suspicious, malice = self.check_tmp()
        result_output_tag(suspicious, malice)

        string_output(u' [3]各用户目录安全扫描')
        suspicious, malice = self.check_user_dir()
        result_output_tag(suspicious, malice)

        string_output(u' [4]可疑隐藏文件扫描')
        suspicious, malice = self.check_hide()
        result_output_tag(suspicious, malice)

        # 检测结果输出到文件
        result_output_file(u'文件检查异常如下：', self.file_malware)


if __name__ == '__main__':
    # File_Analysis().run()
    info = File_Analysis()
    info.run()
    print(u"文件检查异常如下：")
    for info in info.file_malware:
        print(info)
