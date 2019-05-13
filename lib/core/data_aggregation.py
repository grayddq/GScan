# coding:utf-8
from __future__ import print_function
import os, time, sys, json, re, operator, datetime
from lib.core.common import *


# 作者：咚咚呛
# 功能：根据已知的异常风险，进行信息聚合，根据时间线排序，获取黑客的行动轨迹

class Data_Aggregation:
    def __init__(self):
        # 可能存在的黑客入口点信息
        self.begins = []
        self.result_infos = []

    # 黑客攻击可能存在的入口点
    def attack_begins(self):
        try:
            attack_begins = os.popen(
                "netstat -ntpl | grep -v '127.0.0.1' |awk '{if (NR>1){print $4\" \"$7}}'").read().splitlines()
            for infors in attack_begins:
                if not '/' in infors: continue
                if not ':' in infors: continue
                ip_port = infors.split(' ')[0]  # 开放端口
                pid_name = infors.split(' ')[1]  # 钓鱼进程
                self.begins.append({'ip_port': ip_port, 'pid_name': pid_name})
        except:
            return

    def agregation(self):
        suggestion = get_value('suggestion')
        programme = get_value('programme')

        say_info, i = u'-' * 30 + u'\n', 1
        say_info += u'根据系统分析的情况，溯源后的攻击行动轨迹为：\n'
        # 入口点信息
        for begin_info in self.begins:
            say_info += u'[起点信息] 进程服务%s 端口%s 对外部公开，可能会被作为入侵起点，属于排查参考方向\n' % (begin_info['pid_name'], begin_info['ip_port'])

        programme_info = u'\n初步处理方案如下(请核实后操作)：\n'
        # 根据时间排序
        self.result_infos.sort(key=operator.itemgetter(u'异常时间'))
        for result_info in self.result_infos:
            if result_info[u'检测项'] == u'常规后门检测':
                say_info += u"[%d][%s] 黑客在%s时间，进行了%s植入,%s\n" % (
                    i, result_info[u'风险级别'], result_info[u'异常时间'] if result_info[u'异常时间'] else u'未知',
                    result_info[u'风险名称'],
                    result_info[u'异常信息'])
                if suggestion: say_info = say_info + u"           排查参考：%s\n" % result_info[u'手工排查确认']
                if programme and result_info[u'处理方案']: programme_info += u"[%d] %s\n" % (i, result_info[u'处理方案'])
            if result_info[u'检测项'] == u'配置类安全检测':
                say_info += u"[%d][%s] 黑客在%s时间，进行了%s变更，%s\n" % (
                    i, result_info[u'风险级别'], result_info[u'异常时间'] if result_info[u'异常时间'] else u'未知',
                    result_info[u'风险名称'],
                    result_info[u'异常信息'])
                if suggestion: say_info = say_info + u"           排查参考：%s\n" % result_info[u'手工排查确认']
                if programme and result_info[u'处理方案']: programme_info += u"[%d] %s\n" % (i, result_info[u'处理方案'])
            if result_info[u'检测项'] == u'文件类安全检测':
                say_info += u"[%d][%s] 黑客在%s时间，植入了恶意文件%s，%s\n" % (
                    i, result_info[u'风险级别'], result_info[u'异常时间'] if result_info[u'异常时间'] else u'未知',
                    result_info[u'异常文件'],
                    result_info[u'异常信息'])
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
                    result_info[u'所属用户'],
                    result_info[u'异常信息'])
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
                    result_info[u'进程PID'],
                    result_info[u'异常信息'])
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
        print(say_info.replace(u'[风险]', u'[\033[1;31m风险\033[0m]').replace(u'[可疑]', u'[\033[1;33m可疑\033[0m]').replace(
            u'[起点信息]', u'[\033[1;32m起点信息\033[0m]'))

    def run(self):
        self.result_infos = get_value('RESULT_INFO')
        self.result_infos = reRepeat(self.result_infos)
        self.attack_begins()
        self.agregation()
