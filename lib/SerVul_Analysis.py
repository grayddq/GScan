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
        suspicious, malice = False, False
        conf_file = '/etc/redis.conf'
        if not os.path.exists(conf_file):
            return suspicious, malice
        # 打开日志文件
        f = open(conf_file, 'r')
        for i in f:
            if 'requirepass' == i.strip()[0:11]:
                return suspicious, malice
        return True, malice


