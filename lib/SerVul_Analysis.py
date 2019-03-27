# coding:utf-8
from __future__ import print_function
import os, optparse, time, sys, json
from lib.common import *


# 应用服务风险检测
# 1、redis服务风险检测

class SerVul_Analysis:
    def __init__(self):
        return

    def check_redis(self):
        conf_file = '/etc/redis.conf'
        redis_pass = False
        if not os.path.exists(conf_file):
            return False
        # 打开日志文件
        f = open(conf_file, 'r')
        for i in f:
            if 'requirepass' == i.strip()[0:11]:
                redis_pass = True
        if not redis_pass:
            print(u"存在redis未授权访问风险")





