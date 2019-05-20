# coding:utf-8
from __future__ import print_function
import os
from lib.core.common import *


# 作者：咚咚呛
# 版本：v0.1
# 账户类安全排查
# 1、查看root权限账户，排除root本身
# 2、查看系统中是否存在空口令账户
# 3、查看sudoers文件权限，是否存在可直接sudo获取root的账户
# 4、查看各账户下登录公钥
# 5、密码文件权限检测

class User_Analysis:
    def __init__(self):
        self.user_malware = []
        self.name = u'账户类安全检测'

    # 检测root权限用户
    def check_user(self):
        suspicious, malice = False, False
        try:
            shell_process = os.popen("awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null").read().splitlines()
            for user in shell_process:
                if user.replace("\n", "") != 'root':
                    malice_result(self.name, u'root权限账户安全扫描', '/etc/passwd', '', u'存在特权用户%s' % user.replace("\n", ""),
                                  u'[1]cat /etc/passwd', u'可疑', programme=u'vi /etc/passwd #删除用户root权限')
                    suspicious = False
            return suspicious, malice
        except:
            return suspicious, malice

    # 检测空口令账户
    def check_empty(self):
        suspicious, malice = False, False
        try:
            if os.path.exists('/etc/shadow'):
                shell_process2 = os.popen(
                    "awk -F: 'length($2)==0 {print $1}' /etc/shadow 2>/dev/null").read().splitlines()
                for user in shell_process2:
                    malice_result(self.name, u'空口令账户安全扫描', '/etc/shadow', '', u'存在空口令用户 %s' % user.replace("\n", ""),
                                  u'[1]cat /etc/shadow', u'风险',
                                  programme=u'userdel %s #删除空口令用户' % user.replace("\n", ""))
                    malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 检测sudo权限异常账户
    def check_sudo(self):
        suspicious, malice = False, False
        try:
            if os.path.exists('/etc/sudoers'):
                shell_process3 = os.popen(
                    "cat /etc/sudoers 2>/dev/null |grep -v '#'|grep 'ALL=(ALL)'|awk '{print $1}'").read().splitlines()
                for user in shell_process3:
                    if user.replace("\n", "") != 'root' and user[0] != '%':
                        malice_result(self.name, u'sudoers权限安全扫描', '/etc/sudoers', '',
                                      u'用户 %s 可通过sudo命令获取特权' % user.replace("\n", ""), u'[1]cat /etc/sudoers', u'风险',
                                      programme=u'vi /etc/sudoers #更改sudo设置')
                        suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 获取用户免密登录的公钥
    def check_authorized_keys(self):
        suspicious, malice = False, False
        try:
            for dir in os.listdir('/home/'):
                suspicious2, malice2 = self.file_analysis(
                    os.path.join('%s%s%s' % ('/home/', dir, '/.ssh/authorized_keys')),
                    dir)
                if suspicious2: suspicious = True
                if malice2: malice = True
            suspicious2, malice2 = self.file_analysis('/root/.ssh/authorized_keys', 'root')
            if suspicious2: suspicious = True
            if malice2: malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 分析authorized_keys文件
    def file_analysis(self, file, user):
        suspicious, malice = False, False
        try:
            if os.path.exists(file):
                shell_process = os.popen("cat " + file + " 2>/dev/null |awk '{print $3}'").read().splitlines()
                if len(shell_process):
                    authorized_key = ' & '.join(shell_process).replace("\n", "")
                    malice_result(self.name, u'账户免密码证书安全扫描', file, '',
                                  u'用户%s存在免密登录的证书，证书客户端名称：%s' % (user, authorized_key), u'[1]cat %s' % file, u'可疑',
                                  programme=u'vi %s #删除证书设置' % file)
                suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 密码文件检测
    def passwd_file_analysis(self):
        suspicious, malice = False, False
        try:
            files = ['/etc/passwd', '/etc/shadow']
            for file in files:
                if not os.path.exists(file): continue
                shell_process = os.popen("ls -l " + file + " 2>/dev/null |awk '{print $1}'").read().splitlines()
                if len(shell_process) != 1: continue
                if file == '/etc/passwd' and shell_process[0] != '-rw-r--r--':
                    malice_result(self.name, u'账户密码文件扫描', file, '',
                                  u'passwd文件权限变更，不为-rw-r--r--', u'ls -l /etc/passwd', u'可疑')
                    suspicious = True
                elif file == '/etc/shadow' and shell_process[0] != '----------':
                    malice_result(self.name, u'账户密码文件扫描', file, '',
                                  u'shadow文件权限变更，不为----------', u'ls -l /etc/shadow', u'可疑')
                    suspicious = True
            return suspicious, malice
        except:
            return suspicious, malice

    def run(self):
        print(u'\n开始账户类安全扫描')
        file_write(u'\n开始账户类安全扫描\n')

        string_output(u' [1]root权限账户安全扫描')
        suspicious, malice = self.check_user()
        result_output_tag(suspicious, malice)

        string_output(u' [2]空口令账户安全扫描')
        suspicious, malice = self.check_empty()
        result_output_tag(suspicious, malice)

        string_output(u' [3]sudoers权限安全扫描')
        suspicious, malice = self.check_sudo()
        result_output_tag(suspicious, malice)

        string_output(u' [4]账户免密码证书安全扫描')
        suspicious, malice = self.check_authorized_keys()
        result_output_tag(suspicious, malice)

        string_output(u' [5]账户密码文件扫描')
        suspicious, malice = self.passwd_file_analysis()
        result_output_tag(suspicious, malice)

        # 检测结果输出到文件
        result_output_file(self.name)


if __name__ == '__main__':
    infos = User_Analysis()
    infos.run()
    print(u"可疑账户如下：")
    for info in infos.user_malware:
        print(info)
