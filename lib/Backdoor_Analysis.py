# coding:utf-8
import os, optparse, time, sys
from common import *


# 常规类后门检测
# 1、LD_PRELOAD后门检测
# 2、ld.so.preload后门检测
# 3、PROMPT_COMMAND后门检测
# 4、crontab后门检测
# 5、alias后门
# 6、ssh后门 ln -sf /usr/sbin/sshd /tmp/su; /tmp/su -oPort=5555;
# 7、SSH Server wrapper 后门，替换/user/sbin/sshd 为脚本文件
# 8、/etc/inetd.conf 后门
# 9、/etc/xinetd.conf/后门
# 10、系统启动项后门检测


class Backdoor_Analysis:
    def __init__(self):
        # 异常后门列表
        self.backdoor = []
        # 恶意特征列表
        self.malware_infos = []
        # 获取恶意特征信息
        self.get_malware_info()
        # LD_PRELOAD后门检测
        # self.check_LD_PRELOAD()
        # ld.so.preload后门检测
        # self.check_ld_so_preload()
        # PROMPT_COMMAND后门检测
        # self.check_PROMPT_COMMAND()
        # 分析cron定时任务后门
        # self.check_cron()
        # 分析SSH后门
        # self.check_SSH()
        # 分析SSHwrapper后门
        # self.check_SSHwrapper()
        # 分析inetd.conf后门
        # self.check_inetd()
        # 分析xinetd.conf后门
        # self.check_xinetd()

    # LD_PRELOAD后门检测
    def check_LD_PRELOAD(self):
        suspicious, malice = False, False
        infos = os.popen("echo $LD_PRELOAD").read().splitlines()
        for info in infos:
            if not len(info) > 3: continue
            self.backdoor.append(
                {'name': 'LD_PRELOAD backdoor', 'info': info, 'file': '', 'malware': '',
                 'solve': '[1]echo $LD_PRELOAD \n[2]unset LD_PRELOAD'})
            malice = True
        return suspicious, malice

    # ld.so.preload后门检测
    def check_ld_so_preload(self):
        suspicious, malice = False, False
        if not os.path.exists('/etc/ld.so.preload'): return suspicious, malice
        with open('/etc/ld.so.preload') as f:
            for line in f:
                if not len(line) > 3: continue
                if line[0] != '#':
                    self.backdoor.append({'name': 'ld.so.preload backdoor', 'info': line.replace("\n", ""),
                                          'file': '/etc/ld.so.preload', 'solve': '[1]cat /etc/ld.so.preload',
                                          'malware': ''})
                    malice = True
                    break
        return suspicious, malice

    # PROMPT_COMMAND后门检测
    def check_PROMPT_COMMAND(self):
        suspicious, malice = False, False
        infos = os.popen("echo $PROMPT_COMMAND").read().splitlines()
        for info in infos:
            suspicious2, malice2 = self.analysis_strings('PROMPT_COMMAND backdoor', 'ROMPT_COMMAND', info,
                                                         '[1]echo $PROMPT_COMMAND')
            if suspicious2: suspicious = True
            if malice2: malice = True
        return suspicious, malice

    # 分析cron定时任务后门
    def check_cron(self):
        suspicious, malice = False, False
        cron_dir_list = ['/var/spool/cron/', '/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.weekly/',
                         '/etc/cron.hourly/', '/etc/cron.monthly/']
        for cron in cron_dir_list:
            files = [os.path.join(cron, i) for i in os.listdir(cron) if (not os.path.isdir(os.path.join(cron, i)))]
            for file in files:
                for i in open(file, 'r'):
                    suspicious2, malice2 = self.analysis_strings('crontab backdoor', file, i, '[1]cat %s' % file)
                    if suspicious2: suspicious = True
                    if malice2: malice = True
        return suspicious, malice

    # 分析alias后门
    def check_alias(self):
        suspicious, malice = False, False
        infos = os.popen("alias").read().splitlines()
        for info in infos:
            suspicious2, malice2 = self.analysis_strings('alias backdoor', "", info, '[1]alias')
            if suspicious2: suspicious = True
            if malice2: malice = True
        return suspicious, malice

    # 分析SSH后门
    def check_SSH(self):
        suspicious, malice = False, False
        infos = os.popen("netstat -ntpl |grep -v ':22 '| awk '{if (NR>2){print $7}}'").read().splitlines()
        for info in infos:
            pid = info.split("/")[0]
            if os.path.exists('/proc/%s/exe' % pid):
                if 'sshd' in os.readlink('/proc/%s/exe' % pid):
                    self.backdoor.append(
                        {'name': 'SSH backdoor', 'info': '/porc/%s/exe' % pid, 'file': '/proc/%s/exe' % pid,
                         'solve': '[1]ls -l /porc/%s [2]ps -ef|grep %s|grep -v grep' % (pid, pid), 'malware': ''})
                    malice = True
        return suspicious, malice

    # 分析SSH Server wrapper 后门
    def check_SSHwrapper(self):
        suspicious, malice = False, False
        infos = os.popen("file /usr/sbin/sshd").read().splitlines()
        if 'ELF' not in infos[0]:
            self.backdoor.append(
                {'name': 'SSHwrapper backdoor', 'info': infos[0], 'file': '/usr/sbin/sshd',
                 'solve': '[1]file /usr/sbin/sshd [2]cat /usr/sbin/sshd', 'malware': ''})
            malice = True
        return suspicious, malice

    # 分析inetd后门
    def check_inetd(self):
        suspicious, malice = False, False
        if not os.path.exists('/etc/inetd.conf'): return suspicious, malice
        with open('/etc/inetd.conf') as f:
            for line in f:
                if '/bin/bash' in line:
                    self.backdoor.append(
                        {'name': 'inetd.conf backdoor', 'info': line, 'file': '/etc/inetd.conf',
                         'solve': '[1]cat /etc/inetd.conf', 'malware': ''})
                    malice = True
        return suspicious, malice

    # 分析xinetd后门
    def check_xinetd(self):
        suspicious, malice = False, False
        if not os.path.exists('/etc/xinetd.conf/'): return suspicious, malice
        for file in os.listdir('/etc/xinetd.conf/'):
            with open(os.path.join('%s%s' % ('/etc/xinetd.conf/', file))) as f:
                for line in f:
                    if '/bin/bash' in line:
                        fpath = os.path.join('%s%s' % ('/etc/xinetd.conf/', file))
                        self.backdoor.append(
                            {'name': 'xinetd.conf backdoor', 'info': line, 'file': '/etc/xinetd.conf/%s' % file,
                             'solve': '[1]cat /etc/xinetd.conf/%s' % file, 'malware': ''})
                        malice = True
        return suspicious, malice

    # 系统启动项检测
    def check_startup(self):
        suspicious, malice = False, False
        init_path = ['/etc/init.d/', '/etc/rc.d/', '/etc/rc.local']
        for path in init_path:
            if os.path.isfile(path):
                malware = self.analysis_file(path)
                if malware:
                    self.backdoor.append(
                        {'name': 'startup backdoor', 'file': path, 'info': '', 'malware': malware,
                         'solve': '[1]cat %s' % path})
                    malice = True
                continue
            for file in gci(path):
                malware = self.analysis_file(file)
                if malware:
                    self.backdoor.append(
                        {'name': 'startup backdoor', 'file': file, 'info': '', 'malware': malware,
                         'solve': '[1]cat %s' % file})
                    malice = True
        return suspicious, malice

    # 获取配置文件的恶意域名等信息
    def get_malware_info(self):
        if not os.path.exists('malware'): return
        for file in os.listdir('./malware/'):
            time.sleep(0.001)  # 防止cpu占用过大
            with open(os.path.join('%s%s' % ('./malware/', file))) as f:
                for line in f:
                    if len(line) > 3:
                        if line[0] != '#': self.malware_infos.append(line.strip().replace("\n", ""))

    # 分析文件是否包含恶意特征或者反弹shell问题
    def analysis_file(self, file):
        strings = os.popen("strings %s" % file).readlines()
        for str in strings:
            if self.check_shell(str): return 'bash shell'
            for malware in self.malware_infos:
                if malware in str: return malware
        return ""

    # 分析字符串是否包含反弹shell特征
    def check_shell(self, content):
        return True if (('bash' in content) and (
                ('/dev/tcp/' in content) or ('telnet ' in content) or ('nc ' in content) or (
                'exec ' in content) or ('curl ' in content) or ('wget ' in content) or ('lynx ' in content))) or (
                               ".decode('base64')" in content) else False

    # 分析一串字符串是否包含反弹shell或者存在的文件路径
    def analysis_strings(self, name, file, contents, solve):
        suspicious, malice = False, False
        content = contents.replace('\n', '')
        if self.check_shell(content):
            self.backdoor.append({'name': name, 'file': file, 'info': content, 'malware': 'bash shell', 'solve': solve})
            malice = True
        else:
            for file in content.split(' '):
                if not os.path.exists(file): continue
                malware = self.analysis_file(file)
                if malware:
                    self.backdoor.append(
                        {'name': name, 'file': file, 'info': content, 'malware': malware, 'solve': solve})
                    malice = True
        return suspicious, malice

    def run(self):
        print(u'\n开始rootkit类安全扫描')
        print align(u' [1]LD_PRELOAD rootkit检测', 30) + u'[ ',
        file_write(u'\n开始rootkit类安全扫描\n')
        file_write(align(u' [1]LD_PRELOAD rootkit检测', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_LD_PRELOAD()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print align(u' [2]ld.so.preload rootkit检测', 30) + u'[ ',
        file_write(align(u' [2]ld.so.preload rootkit检测', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_ld_so_preload()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print align(u' [3]PROMPT_COMMAND rootkit检测', 30) + u'[ ',
        file_write(align(u' [3]PROMPT_COMMAND rootkit检测', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_PROMPT_COMMAND()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print align(u' [4]crontab rootkit检测', 30) + u'[ ',
        file_write(align(u' [4]crontab rootkit检测', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_cron()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print align(u' [5]alias rootkit检测', 30) + u'[ ',
        file_write(align(u' [5]alias rootkit检测', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_SSH()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print align(u' [6]ssh rootkit检测', 30) + u'[ ',
        file_write(align(u' [6]ssh rootkit检测', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_SSH()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print align(u' [7]SSH wrapper rootkit检测', 30) + u'[ ',
        file_write(align(u' [7]SSH wrapper rootkit检测', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_SSHwrapper()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print align(u' [8]inetd.conf rootkit检测', 30) + u'[ ',
        file_write(align(u' [8]inetd.conf rootkit检测', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_inetd()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print align(u' [9]xinetd.conf rootkit检测', 30) + u'[ ',
        file_write(align(u' [9]xinetd.conf rootkit检测', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_xinetd()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print align(u' [10]系统启动项rootkit检测', 30) + u'[ ',
        file_write(align(u' [10]系统启动项rootkit检测', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_startup()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        if len(self.backdoor) > 0:
            file_write('-' * 30 + '\n')
            file_write(u'后门检查异常如下：\n')
            for info in self.backdoor:
                file_write(json.dumps(info, ensure_ascii=False) + '\n')
            file_write('-' * 30 + '\n')

if __name__ == '__main__':
    infos = Backdoor_Analysis()
    infos.run()
    print u"后门检查异常如下："
    for info in infos.backdoor:
        print info
