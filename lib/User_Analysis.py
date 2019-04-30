# coding:utf-8
from __future__ import print_function
import os
from lib.common import *


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

    # 检测root权限用户
    def check_user(self):
        suspicious, malice = False, False
        try:
            shell_process = os.popen("awk -F: '$3==0 {print $1}' /etc/passwd").readlines()
            for user in shell_process:
                if user.replace("\n", "") != 'root':
                    self.user_malware.append(
                        {u'用户': user.replace("\n", ""), u'异常描述': u'属于特权用户'})
                    suspicious = False
            return suspicious, malice
        except:
            return suspicious, malice

    # 检测空口令账户
    def check_empty(self):
        suspicious, malice = False, False
        try:
            if os.path.exists('/etc/shadow'):
                shell_process2 = os.popen("awk -F: 'length($2)==0 {print $1}' /etc/shadow").readlines()
                for user in shell_process2:
                    self.user_malware.append(
                        {u'用户': user.replace("\n", ""), u'异常描述': u'当前用户存在空口令'})
                    malice = True
            return suspicious, malice
        except:
            return suspicious, malice

    # 检测sudo权限异常账户
    def check_sudo(self):
        suspicious, malice = False, False
        try:
            if os.path.exists('/etc/sudoers'):
                shell_process3 = os.popen("cat /etc/sudoers|grep -v '#'|grep 'ALL=(ALL)'|awk '{print $1}'").readlines()
                for user in shell_process3:
                    if user.replace("\n", "") != 'root' and user[0] != '%':
                        self.user_malware.append(
                            {u'用户': user.replace("\n", ""), u'异常描述': u'可通过sudo命令获取特权'})
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
                shell_process = os.popen("cat " + file + "|awk '{print $3}'").readlines()
                if len(shell_process):
                    authorized_key = ' & '.join(shell_process).replace("\n", "")
                    self.user_malware.append({u'用户': user.replace("\n", ""), u'异常描述': u'存在免密登录的证书',
                                              u'证书客户端名称': authorized_key})
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
                shell_process = os.popen("ls -l " + file + "|awk '{print $1}'").read().splitlines()
                if len(shell_process) != 1: continue
                if file == '/etc/passwd' and shell_process[0] != '-rw-r--r--':
                    self.user_malware.append(
                        {u'文件': file, u'异常描述': u'passwd文件权限变更，不为-rw-r--r--', u'排查参考命令': u'ls -l /etc/passwd'})
                    suspicious = True
                elif file == '/etc/shadow' and shell_process[0] != '----------':
                    self.user_malware.append(
                        {u'文件': file, u'异常描述': u'shadow文件权限变更，不为----------', u'排查参考命令': u'ls -l /etc/shadow'})
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

        string_output(u' [3]sudoers文件权限账户安全扫描')
        suspicious, malice = self.check_sudo()
        result_output_tag(suspicious, malice)

        string_output(u' [4]账户免密码证书安全扫描')
        suspicious, malice = self.check_authorized_keys()
        result_output_tag(suspicious, malice)

        string_output(u' [5]账户密码文件扫描')
        suspicious, malice = self.passwd_file_analysis()
        result_output_tag(suspicious, malice)

        # 检测结果输出到文件
        result_output_file(u'可疑账户类信息如下：', self.user_malware)


if __name__ == '__main__':
    infos = User_Analysis()
    infos.run()
    print(u"可疑账户如下：")
    for info in infos.user_malware:
        print(info)
