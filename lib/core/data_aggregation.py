# coding:utf-8
from __future__ import print_function
import os, time, sys, json, re, operator, datetime
from lib.core.common import *


# 作者：咚咚呛
# 功能：根据已知的异常风险，进行信息聚合，根据时间线排序，获取黑客的行动轨迹

class Data_Aggregation:
    def __init__(self):
        self.result_infos = []

    def cmp_datetime(self, a, b):
        try:
            a_datetime = datetime.datetime.strptime(a, '%Y-%m-%d %H:%M:%S')
            b_datetime = datetime.datetime.strptime(b, '%Y-%m-%d %H:%M:%S')

            if a_datetime > b_datetime:
                return 1
            elif a_datetime < b_datetime:
                return -1
            else:
                return 0
        except:
            return 1

    def run(self):
        self.result_infos = get_value('RESULT_INFO')
        self.result_infos = reRepeat(self.result_infos)
        print(u'-' * 30)
        say_info = u'根据系统分析的情况，溯源后的行动轨迹为：'
        print(u'\033[1;31m根据系统分析的情况，溯源后的行动轨迹为：\033[0m')
        self.result_infos.sort(cmp=self.cmp_datetime, key=operator.itemgetter(u'异常时间'))
        i = 1
        for result_info in self.result_infos:
            if result_info[u'检测项'] == u'常规后门检测':
                print(
                    u"[%d] 黑客在%s时间，进行了%s植入,%s" % (i, result_info[u'异常时间'], result_info[u'风险名称'], result_info[u'异常信息']))
            if result_info[u'检测项'] == u'配置类安全检测':
                print(u"[%d] 黑客在%s时间，进行了%s变更，%s" % (
                    i, result_info[u'异常时间'], result_info[u'风险名称'], result_info[u'异常信息']))
            if result_info[u'检测项'] == u'文件类安全检测':
                print(u"[%d] 黑客在%s时间，植入了恶意文件%s，%s" % (
                    i, result_info[u'异常时间'], result_info[u'异常文件'], result_info[u'异常信息']))
            if result_info[u'检测项'] == u'主机历史操作类安全检测':
                print(u"[%d] 黑客在%s时间，进行了恶意操作，%s" % (i, result_info[u'异常时间'], result_info[u'异常信息']))
            if result_info[u'检测项'] == u'日志类安全检测':
                print(u"[%d] 黑客在%s时间，进行了主机登陆，%s" % (i, result_info[u'异常时间'], result_info[u'异常信息']))
            if result_info[u'检测项'] == u'网络链接类安全检测':
                print(u"[%d] 黑客在%s时间，%s" % (i, result_info[u'异常时间'], result_info[u'异常信息']))
            if result_info[u'检测项'] == u'进程类安全检测':
                print(
                    u"[%d] 黑客在%s时间，启动进程%s，%s" % (i, result_info[u'异常时间'], result_info[u'进程PID'], result_info[u'异常信息']))
            if result_info[u'检测项'] == u'Rootkit类安全检测':
                print(u"[%d] 黑客在%s时间，植入Rootkit后门，%s" % (i, result_info[u'异常时间'], result_info[u'异常信息']))
            if result_info[u'检测项'] == u'系统初始化检测':
                print(u"[%d] 黑客在%s时间，设置了系统命令别名，%s" % (i, result_info[u'异常时间'], result_info[u'异常信息']))
            if result_info[u'检测项'] == u'账户类安全检测':
                print(u"[%d] 黑客在%s时间，进行了账户修改设置，%s" % (i, result_info[u'异常时间'], result_info[u'异常信息']))
            if result_info[u'检测项'] == u'Webshell安全检测':
                print(u"[%d] 黑客在%s时间，植入了webshell文件%s" % (i, result_info[u'异常时间'], result_info[u'异常文件']))
            i += 1
