# coding:utf-8
from __future__ import print_function
# from lib.common import *
from common import *
import os, platform, sys

# nginx
# 1、进程名称中出现-c 跟配置文件
# 2、不存在-c 获取的默认配置文件/etc/nginx/nginx.conf
# tomcat
# 1、提取-Dcatalina.home
# jetty
# 1、


class Webshell_Analysis:
    def __init__(self):
        self.webroot = []
        self.webconf = []

    def getWebserverConf(self):
        webserver = ['nginx','tomcat','jetty','apache','resin','jboss','weblogic']
        for name in webserver:
            cmd = 'ps -ef |grep ' + name + '|grep -v grep|awk '


    def run(self):
