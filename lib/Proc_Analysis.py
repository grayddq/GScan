# coding:utf-8
import os, optparse, time, sys
from common import *


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

        # 查询反弹shell进程
        # self.shell_analysis()
        # 查询cpu和内存使用的可疑进程
        # self.work_analysis()
        # 查询隐藏的进程
        # self.check_hide_pro()
        # 查询挖矿进程、黑客工具、可疑进程名
        # self.keyi_analysis()
        # 判断exe可执行程序是否存在恶意域名特征
        # self.exe_analysis()
        # 数据去重
        # self.process_backdoor = self.reRepeat(self.process_backdoor)

    # 获取配置文件的恶意域名等信息
    def get_malware_info(self):
        if not os.path.exists('malware'): return
        for file in os.listdir('./malware/'):
            time.sleep(0.001)  # 防止cpu占用过大
            with open(os.path.join('%s%s' % ('./malware/', file))) as f:
                for line in f:
                    if len(line) > 3:
                        if line[0] != '#': self.malware_infos.append(line.strip().replace("\n", ""))

    # 判断进程的可执行文件是否具备恶意特征
    def exe_analysis(self):
        suspicious, malice = False, False
        self.get_malware_info()
        if not os.path.exists('/proc/'): return
        for file in os.listdir('/proc/'):
            if file.isdigit():
                filepath = os.path.join('%s%s%s' % ('/proc/', file, '/exe'))
                if (not os.path.islink(filepath)) or (not os.path.exists(filepath)): continue
                strings = os.popen("strings %s" % filepath).readlines()
                for malware in self.malware_infos:
                    time.sleep(0.001)  # 防止cpu占用过大
                    for str in strings:
                        if malware in str:
                            lnstr = os.readlink(filepath)
                            self.process_backdoor.append(
                                {u'异常类型': u'进程程序恶意特征', u'进程pid': file, u'进程cmd': lnstr, u'恶意特征': malware})
                            malice = True
        return suspicious, malice

    # 过滤反弹shell特征
    def shell_analysis(self):
        suspicious, malice = False, False
        shell_process = os.popen(
            "ps -ef | grep -E 'bash -i|telnet|/dev/tcp/'|grep -v 'grep'|awk '{print $1\" \"$2\" \"$3\" \"$8}'").readlines()
        for pro in shell_process:
            pro_info = pro.strip().split(' ', 3)
            self.process_backdoor.append(
                {u'异常类型': u'进程反弹shell特征', u'进程用户': pro_info[0], u'进程pid': pro_info[1], u'父进程ppid': pro_info[2],
                 u'进程cmd': pro_info[3].replace("\n", ""), u'恶意特征': u'反弹shell'})
            malice = True
        return suspicious, malice

    # 过滤cpu和内存使用的可疑问题
    def work_analysis(self):
        suspicious, malice = False, False
        cpu_process = os.popen(
            "ps aux|grep -v PID|sort -rn -k +3|head|awk '{print $1\" \"$2\" \"$3\" \"$4\" \"$11}'|grep -v 'systemd|rsyslogd|mysqld|redis|apache||nginx|mongodb|docker|memcached|tomcat|jboss|java|php|python'").readlines()
        for pro in cpu_process:
            pro_info = pro.strip().split(' ', 4)
            # cpu使用超过标准
            if float(pro_info[2]) > self.cpu:
                self.process_backdoor.append(
                    {u'异常类型': u'CPU过载', u'进程用户': pro_info[0], u'进程pid': pro_info[1], u'进程ppid': "", u'CPU': pro_info[2],
                     u'内存': pro_info[3],
                     u'进程cmd': pro_info[4].replace("\n", "")})
                suspicious = True
            # 内存使用超过标准
            if float(pro_info[3]) > self.mem:
                self.process_backdoor.append(
                    {u'异常类型': u'内存过载', u'进程用户': pro_info[0], u'进程pid': pro_info[1], u'进程ppid': "", u"CPU": pro_info[2],
                     u"内存": pro_info[3],
                     u'进程cmd': pro_info[4].replace("\n", "")})
                suspicious = True
        return suspicious, malice

    # 检测隐藏进程
    def check_hide_pro(self):
        suspicious, malice = False, False
        # ps获取所有pid
        pid_process = os.popen("ps -ef | awk 'NR>1{print $2}'").read().splitlines()
        # 所有/proc目录的pid
        pid_pro_file = []
        if not os.path.exists('/proc/'): return
        for file in os.listdir('/proc/'):
            if file.isdigit():
                pid_pro_file.append(file)

        hids_pid = list(set(pid_pro_file).difference(set(pid_process)))
        for pid in hids_pid:
            self.process_backdoor.append(
                {u'异常类型': u'进程隐藏', u'进程pid': pid,
                 u'排查方式': u"[1] cat /proc/$$/mountinfo|grep %s \n[2] umount /proc/%s" % (pid, pid)})
            malice = True
        return suspicious, malice

    # 查询挖矿进程、黑客工具、可疑进程名称
    def keyi_analysis(self):
        suspicious, malice = False, False
        process = os.popen(
            "ps -ef | grep -E 'minerd|r00t|sqlmap|nmap|hydra|aircrack'|grep -v 'grep'|awk '{print $1\" \"$2\" \"$3\" \"$8}'").readlines()
        for pro in process:
            pro_info = pro.strip().split(' ', 3)
            self.process_backdoor.append(
                {u'异常类型': u'进程恶意程序', u'进程用户': pro_info[0], u'进程pid': pro_info[1], u'进程ppid': pro_info[2],
                 u'进程cmd': pro_info[3].replace("\n", "")})
            suspicious = True
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
        print align(u' [1]CUP和内存类异常进程排查', 30) + u'[ ',
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

        print align(u' [2]隐藏进程安全扫描', 30) + u'[ ',
        file_write(align(u' [2]隐藏进程安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_hide_pro()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print align(u' [3]反弹shell类进程扫描', 30) + u'[ ',
        file_write(align(u' [3]反弹shell类进程扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.shell_analysis()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print align(u' [4]恶意进程信息安全扫描', 30) + u'[ ',
        file_write(align(u' [4]恶意进程信息安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.keyi_analysis()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print align(u' [5]exe程序安全扫描', 30) + u'[ ',
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

        if len(self.malware_infos) > 0:
            file_write('-' * 30 + '\n')
            file_write(u'恶意进程如下：：\n')
            for info in self.malware_infos:
                file_write(json.dumps(info, ensure_ascii=False) + '\n')
            file_write('-' * 30 + '\n')


if __name__ == '__main__':
    infos = Proc_Analysis()
    infos.run()
    print u"恶意进程如下："
    for info in infos.malware_infos:
        print info
