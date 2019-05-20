# coding:utf-8
from __future__ import print_function
import os, time, sys, json, re, operator, datetime, hashlib,json
from lib.core.common import *


# 作者：咚咚呛
# 功能：根据已知的异常风险，进行信息聚合，根据时间线排序，获取黑客的行动轨迹

class Data_Aggregation:
    def __init__(self):
        # 可能存在的黑客入口点信息
        self.begins = []
        # 检测结果信息
        self.result_infos = []
        # 本次新增异常风险,与历史进行数据对比
        self.dif_result_infos = []
        # 是否差异扫描
        self.diffect = False

    # 读取db文件，提取hash内容，进行结果判断存在哪些新增风险。
    def result_db_filter(self):
        old_db = []
        DB_PATH = get_value('DB_PATH')
        with open(DB_PATH) as f:
            for line in f:
                old_db.append(line.strip())
        for info in self.result_infos:
            hash_txt = info[u'检测项'] + info[u'风险名称'] + info[u'异常文件'] + info[u'进程PID'] + info[u'异常时间'] + info[u'异常信息']
            md5obj = hashlib.md5()
            md5obj.update(hash_txt.encode("utf8"))
            hashinfo = md5obj.hexdigest()
            if not hashinfo in old_db:
                self.dif_result_infos.append(info)
        # 写检测结果到db文件
        self.write_result_to_db()

    # 写检测结果到db文件
    def write_result_to_db(self):
        DB_PATH = get_value('DB_PATH')
        # 写结果文件到db
        with open(DB_PATH, 'w') as f:
            for info in self.result_infos:
                hash_txt = info[u'检测项'] + info[u'风险名称'] + info[u'异常文件'] + info[u'进程PID'] + info[u'异常时间'] + info[u'异常信息']
                md5obj = hashlib.md5()
                md5obj.update(hash_txt.encode("utf8"))
                hashinfo = md5obj.hexdigest()
                f.write(hashinfo + '\n')

    # 黑客攻击可能存在的入口点
    def attack_begins(self):
        try:
            attack_begins = os.popen(
                "netstat -ntpl 2>/dev/null | grep -v '127.0.0.1' |awk '{if (NR>1){print $4\" \"$7}}'").read().splitlines()
            for infors in attack_begins:
                if not '/' in infors: continue
                if not ':' in infors: continue
                ip_port = infors.split(' ')[0]  # 开放端口
                pid_name = infors.split(' ')[1]  # 钓鱼进程
                self.begins.append({'ip_port': ip_port, 'pid_name': pid_name})
        except:
            return

    # 追溯溯源信息
    def agregation(self):
        suggestion = get_value('suggestion')
        programme = get_value('programme')

        if len(self.result_infos) > 0:
            say_info, i = u'-' * 30 + u'\n', 1
            say_info += u'根据系统分析的情况，溯源后的攻击行动轨迹为：\n' if not self.diffect else u'根据系统差异分析的情况，溯源后的攻击行动轨迹为：\n'
            # 入口点信息
            for begin_info in self.begins:
                say_info += u'[起点信息] 进程服务%s 端口%s 对外部公开，可能会被作为入侵起点，属于排查参考方向\n' % (
                    begin_info['pid_name'], begin_info['ip_port'])

            programme_info = u'\n初步处理方案如下(请核实后操作)：\n'
            # 根据时间排序
            self.result_infos.sort(key=operator.itemgetter(u'异常时间'))
            for result_info in self.result_infos:
                if result_info[u'检测项'] == u'常规后门检测':
                    say_info += u"[%d][%s] 黑客在%s时间，进行了%s植入,%s\n" % (
                        i, result_info[u'风险级别'], result_info[u'异常时间'] if result_info[u'异常时间'] else u'未知',
                        result_info[u'风险名称'], result_info[u'异常信息'])
                    if suggestion: say_info = say_info + u"           排查参考：%s\n" % result_info[u'手工排查确认']
                    if programme and result_info[u'处理方案']: programme_info += u"[%d] %s\n" % (i, result_info[u'处理方案'])
                if result_info[u'检测项'] == u'配置类安全检测':
                    say_info += u"[%d][%s] 黑客在%s时间，进行了%s变更，%s\n" % (
                        i, result_info[u'风险级别'], result_info[u'异常时间'] if result_info[u'异常时间'] else u'未知',
                        result_info[u'风险名称'], result_info[u'异常信息'])
                    if suggestion: say_info = say_info + u"           排查参考：%s\n" % result_info[u'手工排查确认']
                    if programme and result_info[u'处理方案']: programme_info += u"[%d] %s\n" % (i, result_info[u'处理方案'])
                if result_info[u'检测项'] == u'文件类安全检测':
                    say_info += u"[%d][%s] 黑客在%s时间，植入了恶意文件%s，%s\n" % (
                        i, result_info[u'风险级别'], result_info[u'异常时间'] if result_info[u'异常时间'] else u'未知',
                        result_info[u'异常文件'], result_info[u'异常信息'])
                    if suggestion: say_info = say_info + u"           排查参考：%s\n" % result_info[u'手工排查确认']
                    if programme and result_info[u'处理方案']: programme_info += u"[%d] %s\n" % (i, result_info[u'处理方案'])
                if result_info[u'检测项'] == u'主机历史操作类安全检测':
                    say_info += u"[%d][%s] 黑客在%s时间，进行了恶意操作，%s\n" % (
                        i, result_info[u'风险级别'], result_info[u'异常时间'] if result_info[u'异常时间'] else u'未知',
                        result_info[u'异常信息'])
                    if suggestion: say_info = say_info + u"           排查参考：%s\n" % result_info[u'手工排查确认']
                    if programme and result_info[u'处理方案']: programme_info += u"[%d] %s\n" % (i, result_info[u'处理方案'])
                if result_info[u'检测项'] == u'日志类安全检测':
                    say_info += u"[%d][%s] 黑客在%s时间，通过用户%s进行了主机登陆，%s\n" % (
                        i, result_info[u'风险级别'], result_info[u'异常时间'] if result_info[u'异常时间'] else u'未知',
                        result_info[u'所属用户'], result_info[u'异常信息'])
                    if suggestion: say_info = say_info + u"           排查参考：%s\n" % result_info[u'手工排查确认']
                    if programme and result_info[u'处理方案']: programme_info += u"[%d] %s\n" % (i, result_info[u'处理方案'])
                if result_info[u'检测项'] == u'网络链接类安全检测':
                    say_info += u"[%d][%s] 黑客在%s时间，%s\n" % (
                        i, result_info[u'风险级别'], result_info[u'异常时间'] if result_info[u'异常时间'] else u'未知',
                        result_info[u'异常信息'])
                    if suggestion: say_info = say_info + u"           排查参考：%s\n" % result_info[u'手工排查确认']
                    if programme and result_info[u'处理方案']: programme_info += u"[%d] %s\n" % (i, result_info[u'处理方案'])
                if result_info[u'检测项'] == u'进程类安全检测':
                    say_info += u"[%d][%s] 黑客在%s时间，启动进程%s，%s\n" % (
                        i, result_info[u'风险级别'], result_info[u'异常时间'] if result_info[u'异常时间'] else u'未知',
                        result_info[u'进程PID'], result_info[u'异常信息'])
                    if suggestion: say_info = say_info + u"           排查参考：%s\n" % result_info[u'手工排查确认']
                    if programme and result_info[u'处理方案']: programme_info += u"[%d] %s\n" % (i, result_info[u'处理方案'])
                if result_info[u'检测项'] == u'Rootkit类安全检测':
                    say_info += u"[%d][%s] 黑客在%s时间，植入Rootkit后门，%s\n" % (
                        i, result_info[u'风险级别'], result_info[u'异常时间'] if result_info[u'异常时间'] else u'未知',
                        result_info[u'异常信息'])
                    if suggestion: say_info = say_info + u"           排查参考：%s\n" % result_info[u'手工排查确认']
                    if programme and result_info[u'处理方案']: programme_info += u"[%d] %s\n" % (i, result_info[u'处理方案'])
                if result_info[u'检测项'] == u'系统初始化检测':
                    say_info += u"[%d][%s] 黑客在%s时间，设置了系统命令别名，%s\n" % (
                        i, result_info[u'风险级别'], result_info[u'异常时间'] if result_info[u'异常时间'] else u'未知',
                        result_info[u'异常信息'])
                    if suggestion: say_info = say_info + u"           排查参考：%s\n" % result_info[u'手工排查确认']
                    if programme and result_info[u'处理方案']: programme_info += u"[%d] %s\n" % (i, result_info[u'处理方案'])
                if result_info[u'检测项'] == u'账户类安全检测':
                    say_info += u"[%d][%s] 黑客在%s时间，进行了账户修改设置，%s\n" % (
                        i, result_info[u'风险级别'], result_info[u'异常时间'] if result_info[u'异常时间'] else u'未知',
                        result_info[u'异常信息'])
                    if suggestion: say_info = say_info + u"           排查参考：%s\n" % result_info[u'手工排查确认']
                    if programme and result_info[u'处理方案']: programme_info += u"[%d] %s\n" % (i, result_info[u'处理方案'])
                if result_info[u'检测项'] == u'Webshell安全检测':
                    say_info += u"[%d][%s] 黑客在%s时间，植入了webshell文件%s\n" % (
                        i, result_info[u'风险级别'], result_info[u'异常时间'] if result_info[u'异常时间'] else u'未知',
                        result_info[u'异常文件'])
                    if suggestion: say_info = say_info + u"           排查参考：%s\n" % result_info[u'手工排查确认']
                    if programme and result_info[u'处理方案']: programme_info += u"[%d] %s\n" % (i, result_info[u'处理方案'])
                i += 1
            if programme:
                say_info += programme_info

            file_write(say_info)
            print(
                say_info.replace(u'[风险]', u'[\033[1;31m风险\033[0m]').replace(u'[可疑]', u'[\033[1;33m可疑\033[0m]').replace(
                    u'[起点信息]', u'[\033[1;32m起点信息\033[0m]'))
        else:
            say_info = u'-' * 30 + u'\n'
            say_info += u'本次扫描，未发现入侵异常的信息 \n' if not self.diffect else u'本次差异扫描，未发现入侵异常的信息 \n'
            print(say_info)
            file_write(say_info)

    def run(self):
        self.diffect = get_value('diffect')
        self.result_infos = get_value('RESULT_INFO')
        self.result_infos = reRepeat(self.result_infos)
        self.result_db_filter()
        self.attack_begins()
        if self.diffect: self.result_infos = self.dif_result_infos
        self.agregation()

        # 初始化日志接口
        logger = loging()
        for info in self.result_infos:
            logger.info(json.dumps(info, ensure_ascii=False))
