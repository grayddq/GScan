# coding:utf-8
from __future__ import print_function
import os, optparse, time, sys, json, re
from lib.common import *
from subprocess import Popen, PIPE
from lib.ip.ip import *


# 作者：咚咚呛
# 分析进程信息
# 1、cpu使用超过70% 的进程
# 2、内存使用超过70% 的进程
# 3、隐藏的进程,主要针对mount --bind等挂接方式隐藏进程的检查,解决方案
# 4、是否存在反弹bash的进程
# 5、带有挖矿、黑客工具、可疑进程名的进程
# 6、当前执行的程序，判断可执行exe是否存在恶意域名特征特征

class Proc_Analysis:
    def __init__(self, cpu=70, mem=70):
        # cpu、内存使用率
        self.cpu, self.mem = cpu, mem
        # 可疑的进程列表
        self.process_backdoor = []
        # 恶意的域名等信息
        self.malware_infos = []
        self.get_malware_info()
        self.ip_http = r'(htt|ft)p(|s)://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        self.ip_re = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        self.lan_ip = r'(127\.0\.0\.1)|(localhost)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})'

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
                if (find(ip)[0:2] != u'中国') and (find(ip)[0:3] != u'局域网') and (find(ip)[0:4] != u'共享地址'):
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
            if (os.path.getsize(file) == 0) or (round(os.path.getsize(file) / float(1024 * 1024)) > 10): return ""
            strings = os.popen("strings %s" % file).readlines()
            if len(strings) > 200: return ""
            for str in strings:
                mal = check_shell(str)
                if mal: return mal
                for malware in self.malware_infos:
                    if malware.replace('\n', '') in str:
                        return malware
                if self.check_contents_ip(str): return str
            return ""
        except:
            return ""

    # 判断进程的可执行文件是否具备恶意特征
    def exe_analysis(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/proc/'): return suspicious, malice
            for file in os.listdir('/proc/'):
                if file.isdigit():
                    filepath = os.path.join('%s%s%s' % ('/proc/', file, '/exe'))
                    if (not os.path.islink(filepath)) or (not os.path.exists(filepath)): continue
                    malware = self.analysis_file(filepath)
                    if malware:
                        lnstr = os.readlink(filepath)
                        self.process_backdoor.append(
                            {u'异常类型': u'进程程序恶意特征', u'进程pid': file, u'进程cmd': lnstr, u'恶意特征': malware,
                             u'手工确认': u'[1]ls -a %s [2]strings %s' % (filepath, filepath)})
                        malice = True

            return suspicious, malice
        except:
            return suspicious, malice

    # 过滤反弹shell特征
    def shell_analysis(self):
        suspicious, malice = False, False
        try:
            p1 = Popen("ps -ef", stdout=PIPE, shell=True)
            p2 = Popen("grep -v 'grep'", stdin=p1.stdout, stdout=PIPE, shell=True)
            p3 = Popen("awk '{print $1\" \"$2\" \"$3\" \"$8}'", stdin=p2.stdout, stdout=PIPE, shell=True)
            shell_process = p3.stdout.readlines()
            # shell_process = os.popen(
            #    "ps -ef|grep -v 'grep'|awk '{print $1\" \"$2\" \"$3\" \"$8}'").readlines()
            for pro in shell_process:
                if check_shell(pro):
                    pro_info = pro.strip().split(' ', 3)
                    self.process_backdoor.append(
                        {u'异常类型': u'进程反弹shell特征', u'进程用户': pro_info[0], u'进程pid': pro_info[1], u'父进程ppid': pro_info[2],
                         u'进程cmd': pro_info[3].replace("\n", ""), u'恶意特征': u'反弹shell'})
                    malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 过滤cpu和内存使用的可疑问题
    def work_analysis(self):
        suspicious, malice = False, False
        try:
            p1 = Popen("ps aux", stdout=PIPE, shell=True)
            p2 = Popen('grep -v PID', stdin=p1.stdout, stdout=PIPE, shell=True)
            p3 = Popen('sort -rn -k3', stdin=p2.stdout, stdout=PIPE, shell=True)
            p4 = Popen('head', stdin=p3.stdout, stdout=PIPE, shell=True)
            p5 = Popen("awk '{print $1\" \"$2\" \"$3\" \"$4\" \"$11}'", stdin=p4.stdout, stdout=PIPE, shell=True)
            p6 = Popen(
                "grep -v 'systemd|rsyslogd|mysqld|redis|apache||nginx|mongodb|docker|memcached|tomcat|jboss|java|php|python'",
                stdin=p5.stdout, stdout=PIPE, shell=True)
            cpu_process = p6.stdout.readlines()
            # cpu_process = os.popen(
            #    "ps aux|grep -v PID|sort -rn -k +3|head|awk '{print $1\" \"$2\" \"$3\" \"$4\" \"$11}'|grep -v 'systemd|rsyslogd|mysqld|redis|apache||nginx|mongodb|docker|memcached|tomcat|jboss|java|php|python'").readlines()
            for pro in cpu_process:
                pro_info = pro.strip().split(' ', 4)
                # cpu使用超过标准
                if float(pro_info[2]) > self.cpu:
                    self.process_backdoor.append(
                        {u'异常类型': u'CPU过载', u'进程用户': pro_info[0], u'进程pid': pro_info[1], u'进程ppid': "",
                         u'CPU': pro_info[2],
                         u'内存': pro_info[3],
                         u'进程cmd': pro_info[4].replace("\n", "")})
                    suspicious = True
                # 内存使用超过标准
                if float(pro_info[3]) > self.mem:
                    self.process_backdoor.append(
                        {u'异常类型': u'内存过载', u'进程用户': pro_info[0], u'进程pid': pro_info[1], u'进程ppid': "",
                         u"CPU": pro_info[2],
                         u"内存": pro_info[3],
                         u'进程cmd': pro_info[4].replace("\n", "")})
                    suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 检测隐藏进程
    def check_hide_pro(self):
        suspicious, malice = False, False
        try:
            # ps获取所有pid
            p1 = Popen("ps -ef", stdout=PIPE, shell=True)
            p2 = Popen("awk 'NR>1{print $2}'", stdin=p1.stdout, stdout=PIPE, shell=True)
            pid_process = p2.stdout.splitlines()

            # pid_process = os.popen("ps -ef | awk 'NR>1{print $2}'").read().splitlines()
            # 所有/proc目录的pid
            pid_pro_file = []
            if not os.path.exists('/proc/'): return False, False
            for file in os.listdir('/proc/'):
                if file.isdigit():
                    pid_pro_file.append(file)

            hids_pid = list(set(pid_pro_file).difference(set(pid_process)))
            for pid in hids_pid:
                self.process_backdoor.append(
                    {u'异常类型': u'进程隐藏', u'进程pid': pid,
                     u'手工确认': u"[1] cat /proc/$$/mountinfo|grep %s \n[2] umount /proc/%s" % (pid, pid)})
                malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 查询挖矿进程、黑客工具、可疑进程名称
    def keyi_analysis(self):
        suspicious, malice = False, False
        try:
            p1 = Popen("ps -efwww", stdout=PIPE, shell=True)
            p2 = Popen("grep -E 'minerd|r00t|sqlmap|nmap|hydra|aircrack'", stdin=p1.stdout, stdout=PIPE, shell=True)
            p3 = Popen("grep -v 'grep'", stdin=p2.stdout, stdout=PIPE, shell=True)
            p4 = Popen("awk '{print $1\" \"$2\" \"$3\" \"$8}'", stdin=p3.stdout, stdout=PIPE, shell=True)
            process = p4.stdout.readlines()

            # process = os.popen(
            #    "ps -ef | grep -E 'minerd|r00t|sqlmap|nmap|hydra|aircrack'|grep -v 'grep'|awk '{print $1\" \"$2\" \"$3\" \"$8}'").readlines()
            for pro in process:
                pro_info = pro.strip().split(' ', 3)
                self.process_backdoor.append(
                    {u'异常类型': u'进程恶意程序', u'进程用户': pro_info[0], u'进程pid': pro_info[1], u'进程ppid': pro_info[2],
                     u'进程cmd': pro_info[3].replace("\n", "")})
                suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 数组去重
    def reRepeat(self, old):
        new_li = []
        for i in old:
            if i not in new_li:
                new_li.append(i)
        return new_li

    def run(self):
        print(u'\n开始进程类安全扫描')
        print(align(u' [1]CUP和内存类异常进程排查', 30) + u'[ ', end='')
        file_write(u'\n开始进程类安全扫描\n')
        file_write(align(u' [1]CUP和内存类异常进程排查', 30) + u'[ ')
        sys.stdout.flush()

        # cpu和内存使用的可疑问题
        suspicious, malice = self.work_analysis()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print(align(u' [2]隐藏进程安全扫描', 30) + u'[ ', end='')
        file_write(align(u' [2]隐藏进程安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_hide_pro()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print(align(u' [3]反弹shell类进程扫描', 30) + u'[ ', end='')
        file_write(align(u' [3]反弹shell类进程扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.shell_analysis()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print(align(u' [4]恶意进程信息安全扫描', 30) + u'[ ', end='')
        file_write(align(u' [4]恶意进程信息安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.keyi_analysis()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print(align(u' [5]exe程序安全扫描', 30) + u'[ ', end='')
        file_write(align(u' [5]exe程序安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.exe_analysis()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        self.process_backdoor = self.reRepeat(self.process_backdoor)

        if len(self.process_backdoor) > 0:
            file_write('-' * 30 + '\n')
            file_write(u'恶意进程如下：：\n')
            for info in self.process_backdoor:
                file_write(json.dumps(info, ensure_ascii=False) + '\n')
            file_write('-' * 30 + '\n')


if __name__ == '__main__':
    infos = Proc_Analysis()
    infos.run()
    print(u"恶意进程如下：")
    for info in infos.process_backdoor:
        print(info)
