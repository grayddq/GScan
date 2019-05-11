# coding:utf-8
from __future__ import print_function
import os, time, sys, json, re
from lib.core.common import *
from lib.core.ip.ip import *
from subprocess import Popen, PIPE


# 作者：咚咚呛
# 常规类后门检测
# 1、LD_PRELOAD后门检测
# 2、LD_AOUT_PRELOAD后门检测
# 3、LD_ELF_PRELOAD后门检测
# 4、LD_LIBRARY_PATH后门检测
# 5、ld.so.preload后门检测
# 6、PROMPT_COMMAND后门检测
# 7、cron后门检测
# 8、alias后门
# 9、ssh后门 ln -sf /usr/sbin/sshd /tmp/su; /tmp/su -oPort=5555;
# 10、SSH Server wrapper 后门，替换/user/sbin/sshd 为脚本文件
# 11、/etc/inetd.conf 后门
# 12、/etc/xinetd.conf/后门
# 13、setuid类后门
# 14、/etc/fstab类后门（待写）
# 13、系统启动项后门检测


class Backdoor_Analysis:
    def __init__(self):
        # 异常后门列表
        self.backdoor = []

    # 检测配置文件是否存在恶意配置
    def check_conf(self, tag, file, mode='only'):
        try:
            if not os.path.exists(file): return ""
            if os.path.isdir(file): return ""
            if mode == 'only':
                with open(file) as f:
                    for line in f:
                        if len(line) < 3: continue
                        if line[0] == '#': continue
                        if 'export ' + tag in line:
                            return line
            else:
                return analysis_file(file)
            return ""
        except:
            return ""

    # 检测所有环境变量，是否存在恶意配置
    def check_tag(self, name, tag, mode='only'):
        suspicious, malice = False, False
        try:
            files = ['/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/root/.tcshrc',
                     '/etc/bashrc', '/etc/profile', '/etc/profile.d/', '/etc/csh.login', '/etc/csh.cshrc']
            home_files = ['/.bashrc', '/.bash_profile', '/.tcshrc', '/.cshrc', '/.tcshrc']

            # 循环用户目录查看环境设置
            for dir in os.listdir('/home/'):
                for home_file in home_files:
                    file = os.path.join('%s%s%s' % ('/home/', dir, home_file))
                    info = self.check_conf(tag, file, mode)
                    if info:
                        malice_result(u'常规后门检测', name, file, '', info, u'[1]echo $%s [2]cat %s' % (tag, file), u'可疑',
                                      programme=u'vi %s #删除%s设置' % (file, tag))
                        suspicious = True
            # 检查系统目录的配置
            for file in files:
                # 如果为目录形式，则遍历目录下所有文件
                if os.path.isdir(file):
                    for file in gci(file):
                        info = self.check_conf(tag, file, mode)
                        if info:
                            malice_result(u'常规后门检测', name, file, '', info, u'[1]echo $%s [2]cat %s' % (tag, file),
                                          u'可疑')
                            suspicious = True
                else:
                    info = self.check_conf(tag, file, mode)
                    if info:
                        malice_result(u'常规后门检测', name, file, '', info, u'[1]echo $%s [2]cat %s' % (tag, file), u'可疑',
                                      programme=u'vi %s #删除%s设置' % (file, tag))
                        suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # LD_PRELOAD后门检测
    def check_LD_PRELOAD(self):
        suspicious, malice = False, False
        try:
            suspicious, malice = self.check_tag(u'LD_PRELOAD 后门', 'LD_PRELOAD')
            return suspicious, malice
        except:
            return suspicious, malice

    # LD_AOUT_PRELOAD后门检测
    def check_LD_AOUT_PRELOAD(self):
        suspicious, malice = False, False
        try:
            suspicious, malice = self.check_tag(u'LD_AOUT_PRELOAD 后门', 'LD_AOUT_PRELOAD')
            return suspicious, malice
        except:
            return suspicious, malice

    # LD_ELF_PRELOAD后门检测
    def check_LD_ELF_PRELOAD(self):
        suspicious, malice = False, False
        try:
            suspicious, malice = self.check_tag(u'LD_ELF_PRELOAD 后门', 'LD_ELF_PRELOAD')
            return suspicious, malice
        except:
            return suspicious, malice

    # LD_LIBRARY_PATH后门检测
    def check_LD_LIBRARY_PATH(self):
        suspicious, malice = False, False
        try:
            suspicious, malice = self.check_tag(u'LD_LIBRARY_PATH 后门', 'LD_LIBRARY_PATH')
            return suspicious, malice
        except:
            return suspicious, malice

    # PROMPT_COMMAND后门检测
    def check_PROMPT_COMMAND(self):
        suspicious, malice = False, False
        try:
            suspicious, malice = self.check_tag(u'PROMPT_COMMAND 后门', 'PROMPT_COMMAND')
            return suspicious, malice
        except:
            return suspicious, malice

    # 未知环境变量后门
    def check_export(self):
        suspicious, malice = False, False
        try:
            suspicious, malice = self.check_tag(u'未知环境变量 后门', 'PATH', mode='all')
            return suspicious, malice
        except:
            return suspicious, malice

    # ld.so.preload后门检测
    def check_ld_so_preload(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/etc/ld.so.preload'): return suspicious, malice
            with open('/etc/ld.so.preload') as f:
                for line in f:
                    if not len(line) > 3: continue
                    if line[0] != '#':
                        content = analysis_strings(line)
                        if content:
                            malice_result(u'常规后门检测', u'ld.so.preload 后门', '/etc/ld.so.preload', '', content,
                                          '[1]cat /etc/ld.so.preload', u'风险', programme=u'vi ld.so.preload #删除所有so设置')
                            malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 分析cron定时任务后门
    def check_cron(self):
        suspicious, malice = False, False
        try:
            cron_dir_list = ['/var/spool/cron/', '/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.weekly/',
                             '/etc/cron.hourly/', '/etc/cron.monthly/']
            for cron in cron_dir_list:
                for file in gci(cron):
                    if not os.path.exists(file): continue
                    if os.path.isdir(file): continue
                    for i in open(file, 'r'):
                        content = analysis_strings(i)
                        if content:
                            malice_result(u'常规后门检测', u'cron 后门', file, '', content, '[1]cat %s' % file, u'风险',
                                          programme=u'vi %s #删除定时任务设置' % file)
                            malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 分析SSH后门
    def check_SSH(self):
        suspicious, malice = False, False
        try:
            infos = os.popen(
                "netstat -ntpl 2>/dev/null |grep -v ':22 '| awk '{if (NR>2){print $7}}'").read().splitlines()
            for info in infos:
                pid = info.split("/")[0]
                if os.path.exists('/proc/%s/exe' % pid):
                    if 'sshd' in os.readlink('/proc/%s/exe' % pid):
                        malice_result(u'常规后门检测', u'SSH 后门', u'/porc/%s/exe' % pid, pid, u"非22端口的sshd服务",
                                      u'[1]ls -l /porc/%s [2]ps -ef|grep %s|grep -v grep' % (pid, pid), u'风险',
                                      programme=u'kill %s #关闭异常sshd进程' % pid)
                        malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 分析SSH Server wrapper 后门
    def check_SSHwrapper(self):
        suspicious, malice = False, False
        try:
            infos = os.popen("file /usr/sbin/sshd 2>/dev/null").read().splitlines()
            if not len(infos): return suspicious, malice
            if ('ELF' not in infos[0]) and ('executable' not in infos[0]):
                malice_result(u'常规后门检测', u'SSHwrapper 后门', u'/usr/sbin/sshd', "", u"/usr/sbin/sshd被篡改,文件非可执行文件",
                              u'[1]file /usr/sbin/sshd [2]cat /usr/sbin/sshd', u'风险',
                              programme=u'rm /usr/sbin/sshd & yum -y install openssh-server & service sshd start #删除sshd异常文件，并重新安装ssh服务')
                malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 分析inetd后门
    def check_inetd(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/etc/inetd.conf'): return suspicious, malice
            with open('/etc/inetd.conf') as f:
                for line in f:
                    content = analysis_strings(line)
                    if content:
                        malice_result(u'常规后门检测', u'inetd.conf 后门', u'/etc/inetd.conf', '', content,
                                      u'[1]cat /etc/inetd.conf', u'风险', programme=u'vi /etc/inetd.conf #删除异常点')
                        malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 分析xinetd后门
    def check_xinetd(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/etc/xinetd.conf/'): return suspicious, malice
            for file in os.listdir('/etc/xinetd.conf/'):
                with open(os.path.join('%s%s' % ('/etc/xinetd.conf/', file))) as f:
                    for line in f:
                        content = analysis_strings(line)
                        if content:
                            malice_result(u'常规后门检测', u'xinetd.conf 后门', u'/etc/xinetd.conf', '', content,
                                          u'[1]cat /etc/xinetd.conf', u'风险', programme=u'vi /etc/xinetd.conf #删除异常点')
                            malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 分析setuid后门后
    def check_setuid(self):
        suspicious, malice = False, False
        try:
            file_infos = os.popen(
                "find / ! -path '/proc/*' -type f -perm -4000 2>/dev/null | grep -vE 'pam_timestamp_check|unix_chkpwd|ping|mount|su|pt_chown|ssh-keysign|at|passwd|chsh|crontab|chfn|usernetctl|staprun|newgrp|chage|dhcp|helper|pkexec|top|Xorg|nvidia-modprobe|quota|login|security_authtrampoline|authopen|traceroute6|traceroute|ps'").read().splitlines()
            for info in file_infos:
                malice_result(u'常规后门检测', u'setuid 后门', info, '',
                              u'文件%s 被设置setuid属性，通常此类被设置权限的文件执行后会给予普通用户root权限' % info, u'[1]ls -l %s' % info, u'风险',
                              programme=u'chmod u-s %s #去掉setuid曲线' % info)
                suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 系统启动项检测
    def check_startup(self):
        suspicious, malice = False, False
        try:
            init_path = ['/etc/init.d/', '/etc/rc.d/', '/etc/rc.local', '/usr/local/etc/rc.d',
                         '/usr/local/etc/rc.local', '/etc/conf.d/local.start', '/etc/inittab', '/etc/systemd/system']
            for path in init_path:
                if not os.path.exists(path): continue
                if os.path.isfile(path):
                    content = analysis_file(path)
                    if content:
                        malice_result(u'常规后门检测', u'系统启动项后门', path, '', content, u'[1]cat %s' % path, u'风险',
                                      programme=u'vi %s #删除异常点' % path)
                        malice = True
                    continue
                for file in gci(path):
                    content = analysis_file(file)
                    if content:
                        malice_result(u'常规后门检测', u'系统启动项后门', path, '', content, u'[1]cat %s' % path, u'风险',
                                      programme=u'vi %s #删除异常点' % path)
                        malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    def run(self):
        print(u'\n开始恶意后门类安全扫描')
        file_write(u'\n开始后门类安全扫描\n')

        string_output(u' [1]LD_PRELOAD 后门检测')
        suspicious, malice = self.check_LD_PRELOAD()
        result_output_tag(suspicious, malice)

        string_output(u' [2]LD_AOUT_PRELOAD 后门检测')
        suspicious, malice = self.check_LD_AOUT_PRELOAD()
        result_output_tag(suspicious, malice)

        string_output(u' [3]LD_ELF_PRELOAD 后门检测')
        suspicious, malice = self.check_LD_ELF_PRELOAD()
        result_output_tag(suspicious, malice)

        string_output(u' [4]LD_LIBRARY_PATH 后门检测')
        suspicious, malice = self.check_LD_LIBRARY_PATH()
        result_output_tag(suspicious, malice)

        string_output(u' [5]ld.so.preload 后门检测')
        suspicious, malice = self.check_ld_so_preload()
        result_output_tag(suspicious, malice)

        string_output(u' [6]PROMPT_COMMAND 后门检测')
        suspicious, malice = self.check_PROMPT_COMMAND()
        result_output_tag(suspicious, malice)

        string_output(u' [7]cron定时任务后门检测')
        suspicious, malice = self.check_cron()
        result_output_tag(suspicious, malice)

        string_output(u' [8]未知环境变量 后门检测')
        suspicious, malice = self.check_export()
        result_output_tag(suspicious, malice)

        string_output(u' [9]ssh 后门检测')
        suspicious, malice = self.check_SSH()
        result_output_tag(suspicious, malice)

        string_output(u' [10]SSH wrapper 后门检测')
        suspicious, malice = self.check_SSHwrapper()
        result_output_tag(suspicious, malice)

        string_output(u' [11]inetd.conf 后门检测')
        suspicious, malice = self.check_inetd()
        result_output_tag(suspicious, malice)

        string_output(u' [12]xinetd.conf 后门检测')
        suspicious, malice = self.check_xinetd()
        result_output_tag(suspicious, malice)

        string_output(u' [13]setuid 后门检测')
        suspicious, malice = self.check_setuid()
        result_output_tag(suspicious, malice)

        string_output(u' [14]系统启动项后门检测')
        suspicious, malice = self.check_startup()
        result_output_tag(suspicious, malice)

        # 结果内容输出到文件
        result_output_file(u'常规后门检测')


if __name__ == '__main__':
    infos = Backdoor_Analysis()
    infos.run()
