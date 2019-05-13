# coding:utf-8
from __future__ import print_function
import os, optparse, time, sys, json, re
from lib.core.common import *
from subprocess import Popen, PIPE
from lib.core.ip.ip import *


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
        self.name = u'进程类安全检测'

    # 判断进程的可执行文件是否具备恶意特征
    def exe_analysis(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/proc/'): return suspicious, malice
            for file in os.listdir('/proc/'):
                if file.isdigit():
                    filepath = os.path.join('%s%s%s' % ('/proc/', file, '/exe'))
                    if (not os.path.islink(filepath)) or (not os.path.exists(filepath)): continue
                    malware = analysis_file(filepath)
                    if malware:
                        lnstr = os.readlink(filepath)
                        malice_result(self.name, u'exe程序进程安全扫描', lnstr, file, malware,
                                      u'[1]ls -a %s [2]strings %s' % (filepath, filepath), u'风险',
                                      programme=u'kill %s #关闭恶意进程' % lnstr)
                        malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 过滤反弹shell特征
    def shell_analysis(self):
        suspicious, malice = False, False
        try:
            p1 = Popen("ps -efwww 2>/dev/null", stdout=PIPE, shell=True)
            p2 = Popen("grep -v 'grep'", stdin=p1.stdout, stdout=PIPE, shell=True)
            p3 = Popen("awk '{print $1\" \"$2\" \"$3\" \"$8}'", stdin=p2.stdout, stdout=PIPE, shell=True)
            process = p3.stdout.read().splitlines()
            for pro in process:
                pro_info = pro.strip().split(' ', 3)
                if check_shell(pro_info[3]):
                    malice_result(self.name, u'反弹shell类进程安全扫描', '', pro_info[1],
                                  u'对应进程信息：%s' % pro_info[3].replace("\n", ""),
                                  u'[1]ps -efwww', u'风险', programme=u'kill %s #关闭恶意进程' % pro_info[1])
                    malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 过滤cpu和内存使用的可疑问题
    def work_analysis(self):
        suspicious, malice = False, False
        try:
            p1 = Popen("ps aux 2>/dev/null", stdout=PIPE, shell=True)
            p2 = Popen('grep -v PID', stdin=p1.stdout, stdout=PIPE, shell=True)
            p3 = Popen('sort -rn -k3', stdin=p2.stdout, stdout=PIPE, shell=True)
            p4 = Popen('head', stdin=p3.stdout, stdout=PIPE, shell=True)
            p5 = Popen("awk '{print $1\" \"$2\" \"$3\" \"$4\" \"$11}'", stdin=p4.stdout, stdout=PIPE, shell=True)
            p6 = Popen(
                "grep -v 'systemd|rsyslogd|mysqld|redis|apache||nginx|mongodb|docker|memcached|tomcat|jboss|java|php|python'",
                stdin=p5.stdout, stdout=PIPE, shell=True)
            cpu_process = p6.stdout.read().splitlines()
            # cpu_process = os.popen(
            #    "ps aux|grep -v PID|sort -rn -k +3|head|awk '{print $1\" \"$2\" \"$3\" \"$4\" \"$11}'|grep -v 'systemd|rsyslogd|mysqld|redis|apache||nginx|mongodb|docker|memcached|tomcat|jboss|java|php|python'").readlines()
            for pro in cpu_process:
                pro_info = pro.strip().split(' ', 4)
                # cpu使用超过标准
                if float(pro_info[2]) > self.cpu:
                    malice_result(self.name, u'CPU过载扫描', '', pro_info[1],
                                  u'进程使用CPU过大，对应进程信息：%s' % pro_info[4].replace("\n", ""),
                                  u'[1]ps -efwww', u'风险', programme=u'kill %s #关闭恶意进程' % pro_info[1])
                    suspicious = True
                # 内存使用超过标准
                if float(pro_info[3]) > self.mem:
                    malice_result(self.name, u'内存过载扫描', '', pro_info[1],
                                  u'进程使用内存过大，对应进程信息：%s' % pro_info[4].replace("\n", ""),
                                  u'[1]ps -efwww', u'风险', programme=u'kill %s #关闭恶意进程' % pro_info[1])
                    suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 检测隐藏进程
    def check_hide_pro(self):
        suspicious, malice = False, False
        try:
            # ps获取所有pid
            p1 = Popen("ps -ef 2>/dev/null", stdout=PIPE, shell=True)
            p2 = Popen("awk 'NR>1{print $2}'", stdin=p1.stdout, stdout=PIPE, shell=True)
            pid_process = p2.stdout.read().splitlines()

            # 所有/proc目录的pid
            pid_pro_file = []
            if not os.path.exists('/proc/'): return suspicious, malice
            for file in os.listdir('/proc/'):
                if file.isdigit():
                    pid_pro_file.append(file)
            hids_pid = list(set(pid_pro_file).difference(set(pid_process)))
            if len(hids_pid) > 10: return suspicious, malice
            for pid in hids_pid:
                malice_result(self.name, u'隐藏进程扫描', '', pid, u'进程ID %s 隐藏了进程信息，未出现在进程列表中' % pid,
                              u"[1] cat /proc/$$/mountinfo [2] umount /proc/%s [3]ps -ef |grep %s" % (pid, pid), u'风险',
                              programme=u'umount /proc/%s & kill %s #关闭隐藏进程并结束进程' % (pid, pid))
                malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 查询挖矿进程、黑客工具、可疑进程名称
    def keyi_analysis(self):
        suspicious, malice = False, False
        try:
            p1 = Popen("ps -efwww 2>/dev/null", stdout=PIPE, shell=True)
            p2 = Popen("grep -E 'minerd|r00t|sqlmap|nmap|hydra|aircrack'", stdin=p1.stdout, stdout=PIPE, shell=True)
            p3 = Popen("grep -v 'grep'", stdin=p2.stdout, stdout=PIPE, shell=True)
            p4 = Popen("awk '{print $1\" \"$2\" \"$3\" \"$8}'", stdin=p3.stdout, stdout=PIPE, shell=True)
            process = p4.stdout.read().splitlines()
            for pro in process:
                pro_info = pro.strip().split(' ', 3)
                malice_result(self.name, u'可疑进程信息扫描', '', pro_info[1], pro_info[3].replace("\n", ""), u'[1]ps -efwww',
                              u'风险', programme=u'kill %s #关闭恶意进程' % pro_info[1])
                suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    def run(self):
        print(u'\n开始进程类安全扫描')
        file_write(u'\n开始进程类安全扫描\n')

        string_output(u' [1]CUP和内存类异常进程排查')
        suspicious, malice = self.work_analysis()
        result_output_tag(suspicious, malice)

        string_output(u' [2]隐藏进程安全扫描')
        suspicious, malice = self.check_hide_pro()
        result_output_tag(suspicious, malice)

        string_output(u' [3]反弹shell类进程扫描')
        suspicious, malice = self.shell_analysis()
        result_output_tag(suspicious, malice)

        string_output(u' [4]恶意进程信息安全扫描')
        suspicious, malice = self.keyi_analysis()
        result_output_tag(suspicious, malice)

        string_output(u' [5]exe程序安全扫描')
        suspicious, malice = self.exe_analysis()
        result_output_tag(suspicious, malice)

        # 检测结果输出到文件
        result_output_file(self.name)


if __name__ == '__main__':
    infos = Proc_Analysis()
    infos.run()
