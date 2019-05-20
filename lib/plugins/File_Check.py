# -*- coding: utf8 -*-
# author：  咚咚呛
# 对系统重要文件夹进行监控，并把修改、创建的文件进行日志打印，
# 排除prelink服务对二进制文件修改对结果进行干扰，每次排查都会排除prelink的操作
from __future__ import print_function
import os, sys, hashlib
from lib.core.globalvar import *
from lib.core.common import *


class File_Check:
    def __init__(self):
        # 异常文件列表
        self.file_malware = []
        self.CHECK_DIR = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/local/sbin/', '/usr/local/bin/']
        # 是否只针对特定文件进行监控
        self.HIGH_FILTER = True
        # 监控文件内容列表
        self.HEIGH_FILE_ALARM = ["depmod", "fsck", "fuser", "ifconfig", "ifdown", "ifup", "init", "insmod", "ip",
                                 "lsmod", "modinfo", "modprobe", "nologin", "rmmod", "route", "rsyslogd", "runlevel",
                                 "sulogin", "sysctl", "awk", "basename", "bash", "cat", "chmod", "chown", "cp", "cut",
                                 "date", "df", "dmesg", "echo", "egrep", "env", "fgrep", "find", "grep", "kill",
                                 "logger", "login", "ls", "mail", "mktemp", "more", "mount", "mv", "netstat", "ping",
                                 "ps", "pwd", "readlink", "rpm", "sed", "sh", "sort", "su", "touch", "uname", "gawk",
                                 "mailx", "adduser", "chroot", "groupadd", "groupdel", "groupmod", "grpck", "lsof",
                                 "pwck", "sestatus", "sshd", "useradd", "userdel", "usermod", "vipw", "chattr", "curl",
                                 "diff", "dirname", "du", "file", "groups", "head", "id", "ipcs", "killall", "last",
                                 "lastlog", "ldd", "less", "lsattr", "md5sum", "newgrp", "passwd", "perl", "pgrep",
                                 "pkill", "pstree", "runcon", "sha1sum", "sha224sum", "sha256sum", "sha384sum",
                                 "sha512sum", "size", "ssh", "stat", "strace", "strings", "sudo", "tail", "test", "top",
                                 "tr", "uniq", "users", "vmstat", "w", "watch", "wc", "wget", "whereis", "which", "who",
                                 "whoami", "test"]
        # 系统执行路径
        self.SYS_PATH = get_value('SYS_PATH')
        self.HASH_DB = get_value('SYS_PATH') + '/db/hash_db.txt'
        # prelink服务会修改二进制文件，此处保存prelink服务的相关日志路径
        self.PRELINK_LOG_PATH = ['/var/log/prelink/prelink.log', '/var/log/prelink.log']

        # 开始进行扫描
        self.check_dir_hash()

    # 计算一个文件的hash值
    # 返回hash值字符串
    def file_hash(self, file_path):
        try:
            md5obj = hashlib.md5()
            size = 102400
            fp = open(file_path, 'rb')
            while True:
                content = fp.read(size)
                if not content:
                    break
                md5obj.update(content)
            fp.close()
            return md5obj.hexdigest()
        except:
            return "error"

    # 获取一个目录下的所有文件HASH值
    # 返回内容hash_list_content，包含[[文件路径，hash值],[文件路径，hash值]]
    def dir_hash(self, path):
        hash_list_content = []
        for root, dirs, files in os.walk(path, topdown=True):
            for filename in files:
                # 如果只监控重要名称文件，则其他文件抛弃不创建hash
                if self.HIGH_FILTER:
                    if filename in self.HEIGH_FILE_ALARM:
                        # 存在软链指向真实文件不存在现象
                        if os.path.exists(os.path.join(root, filename)):
                            hash_list = []
                            hash_list.append(os.path.join(root, filename))  # 保存文件绝对路径
                            if 'error' == self.file_hash(os.path.join(root, filename)): continue
                            hash_list.append(self.file_hash(os.path.join(root, filename)))  # 保存文件hash
                            hash_list_content.append(hash_list)
                else:
                    # 存在软链指向真实文件不存在现象
                    if os.path.exists(os.path.join(root, filename)):
                        hash_list = []
                        hash_list.append(os.path.join(root, filename))  # 保存文件绝对路径
                        hash_list.append(self.file_hash(os.path.join(root, filename)))  # 保存文件hash
                        hash_list_content.append(hash_list)
        return hash_list_content

    # 获取存储的hash值文件
    # 返回内容history_hash_list_content，包含[[],[]]
    def get_history_hash_list(self):
        if not os.path.exists(self.HASH_DB):
            self.write_hash_db("Initialization")
            return "", ""
        if os.path.getsize(self.HASH_DB) == 0:
            self.write_hash_db("Initialization")
            return "", ""
        # 获取hash文件内容到数据组中
        history_hash_list_content = []
        # 获取文件路绝对路径到数组中
        history_file_path_list = []
        for line in open(self.HASH_DB):
            if line != "" or line != None:
                tmp_hash = []
                tmp_hash.append(line.split('||')[0].split('\n')[0])  # 文件绝对路径
                tmp_hash.append(line.split('||')[1].split('\n')[0])  # 文件hash
                history_hash_list_content.append(tmp_hash)
                history_file_path_list.append(line.split('||')[0].split('\n')[0])
        return history_hash_list_content, history_file_path_list

    # 写hash数据文件
    # 传入参数为操作类型，
    # Initialization为初始化hash文件，
    # Coverage为文件变动时，覆盖原hash文件
    def write_hash_db(self, type):
        time_string = time.time()
        if type == "Initialization":
            if not os.path.exists(self.HASH_DB):
                f = open(self.HASH_DB, "w")
                f.truncate()
                f.close()
            if os.path.getsize(self.HASH_DB) == 0:
                f = open(self.HASH_DB, 'w')
                for check_dir in self.CHECK_DIR:
                    for hash_list in self.dir_hash(check_dir):
                        f.write(hash_list[0] + "||" + hash_list[1] + "||" + str(time_string) + "\n")
                f.close()
        if type == "Coverage":
            if os.path.exists(self.HASH_DB):
                os.remove(self.HASH_DB)
            f = open(self.HASH_DB, 'w')
            for check_dir in self.CHECK_DIR:
                for hash_list in self.dir_hash(check_dir):
                    f.write(hash_list[0] + "||" + hash_list[1] + "||" + str(time_string) + "\n")
            f.close()

    # 检测操作类型，判断出现文件变动时，是修改还是创建
    # True为修改
    # Flase为创建
    def check_operation_type(self, file_path, history_file_path_list):
        return True if file_path in history_file_path_list else False

    # 检测是否存在prelink服务
    # 返回服务真假，和日志内容
    def check_prelink_server(self):
        for path in self.PRELINK_LOG_PATH:
            if os.path.exists(path):
                file_object = open(path)
                try:
                    all_the_text = file_object.read()
                finally:
                    file_object.close()
                return True, all_the_text
        return False, ""

    # 检测相对应目录的hash是否进行了变化
    def check_dir_hash(self):
        # 判断是否出现文件变动
        HASH_FILE_TYPE = False
        # 最新hash文件列表
        current_hash_list_content = []
        # 获取HASH库文件列表
        history_hash_list_content, history_file_path_list = self.get_history_hash_list()
        if len(history_hash_list_content) == 0 or len(history_file_path_list) == 0:
            return

        # 判断是否存在prelink服务，并返回内容
        PRELINK_SERVER, prelingk_log = self.check_prelink_server()

        # 开始针对监控目录进行检测
        for check_dir in self.CHECK_DIR:
            try:
                current_hash_list_content = self.dir_hash(check_dir)
                for hash_list in current_hash_list_content:
                    # 判断是否存在hash记录
                    if not hash_list in history_hash_list_content:
                        HASH_FILE_TYPE = True
                        # 判断是否是prelink服务更新
                        if PRELINK_SERVER:
                            if len(prelingk_log) > 0:
                                # 判断是否存在prelink此条日志
                                if prelingk_log.find(hash_list[0]) > 0: continue
                        # 记录变动文件结果
                        self.file_malware.append({'file': hash_list[0],
                                                  'action': 'Edit' if self.check_operation_type(hash_list[0],
                                                                                                history_file_path_list) else 'Create',
                                                  'newMD5': hash_list[1]})

            except:
                continue
        # 存在文件修改，hash进行覆盖
        if HASH_FILE_TYPE: self.write_hash_db("Coverage")


if __name__ == '__main__':
    info = File_Check().file_malware
    for i in info:
        print(i)
