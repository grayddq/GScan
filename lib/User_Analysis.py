# coding:utf-8
from __future__ import print_function
import os, optparse, time, sys, json
from lib.common import *


# 作者：咚咚呛
# 版本：v0.1
# 账户类安全排查
# 1、查看root权限账户，排除root本身
# 2、查看系统中是否存在空口令账户
# 3、查看sudoers文件权限，是否存在可直接sudo获取root的账户
# 4、查看各账户下登录公钥

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

    def run(self):
        print(u'\n开始账户类安全扫描')
        print(align(u' [1]root权限账户安全扫描', 30) + u'[ ', end='')
        file_write(u'\n开始账户类安全扫描\n')
        file_write(align(u' [1]root权限账户安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_user()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print(align(u' [2]空口令账户安全扫描', 30) + u'[ ', end='')
        file_write(align(u' [2]空口令账户安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_empty()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print(align(u' [3]sudoers文件权限账户安全扫描', 30) + u'[ ', end='')
        file_write(align(u' [3]sudoers文件权限账户安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_sudo()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        print(align(u' [4]账户免密码证书安全扫描', 30) + u'[ ', end='')
        file_write(align(u' [4]账户免密码证书安全扫描', 30) + u'[ ')
        sys.stdout.flush()
        suspicious, malice = self.check_authorized_keys()
        if malice:
            pringf(u'存在风险', malice=True)
        elif suspicious and (not malice):
            pringf(u'警告', suspicious=True)
        else:
            pringf(u'OK', security=True)

        if len(self.user_malware) > 0:
            file_write('-' * 30 + '\n')
            file_write(u'可疑账户如下：\n')
            for info in self.user_malware:
                file_write(json.dumps(info, ensure_ascii=False) + '\n')
            file_write('-' * 30 + '\n')


if __name__ == '__main__':
    infos = User_Analysis()
    infos.run()
    print(u"可疑账户如下：")
    for info in infos.user_malware:
        print(info)
