# coding:utf-8
from __future__ import print_function
# from lib.common import *
# from common import *
import os, platform, sys


# nginx
# 1、进程名称中出现-c 跟配置文件
# 2、不存在-c 获取的默认配置文件/etc/nginx/nginx.conf
# 3、去读nginx.conf
# tomcat
# 1、提取-Dcatalina.home=、-Djava.io.tmpdir=
# 2、home/webapp、home/work、tmp均纳入为web扫描目录
# jetty
# 1、提取


class Webshell_Analysis:
    def __init__(self):
        self.webroot = ['/var/www/', '/tmp/']
        self.webconf = []

    def getStrPath(self, match, str):
        if match in str:
            path = str.split(match)[1].split(' ')[0]
            return path
        return ''

    def getWebserverConf(self):
        webserver = ['nginx', 'tomcat', 'jetty', 'httpd', 'resin', 'jboss', 'weblogic','jenkins']
        for name in webserver:
            cmd = "ps -efwww |grep " + name + "|grep -v grep|awk '{for(i=8;i<=NF;i++)printf\"%s \",$i;printf\"\\n\"}'"
            # cmd = "ps -efwww|cut -c49-|grep tomcat|grep -v grep"
            shell_process = os.popen(cmd).read().splitlines()
            for pro in shell_process:
                if name == 'nginx':
                    conf = self.getStrPath(' -c ', pro)
                    if conf:
                        self.webconf.append({'name': 'nginx', 'conf': conf, 'home': '', 'webroot': ''})
                    else:
                        self.webconf.append(
                            {'name': 'nginx', 'conf': '/etc/nginx/nginx.conf', 'home': '', 'webroot': ''})
                elif name == 'tomcat':
                    conf = self.getStrPath(' -Dcatalina.home=', pro)
                    if conf:
                        self.webconf.append({'name': 'tomcat', 'home': conf, 'conf': '', 'webroot': conf + '/webapp'})
                        self.webconf.append({'name': 'tomcat', 'home': conf, 'conf': '', 'webroot': conf + '/work'})
                    conf = self.getStrPath(' -Djava.io.tmpdir=', pro)
                    if conf: self.webconf.append({'name': 'tomcat', 'conf': '', 'webroot': conf})

                elif name == 'jetty':
                    conf = self.getStrPath(' -Djetty.home=', pro)
                    if conf:
                        self.webconf.append({'name': 'jetty', 'home': conf, 'conf': '', 'webroot': conf + '/webapp'})
                        self.webconf.append({'name': 'jetty', 'home': conf, 'conf': '', 'webroot': conf + '/work'})
                    conf = self.getStrPath(' -Djetty.webroot=', pro)
                    if conf: self.webconf.append({'name': 'jetty', 'home': conf, 'conf': '', 'webroot': conf})
                    conf = self.getStrPath(' -Djava.io.tmpdir=', pro)
                    if conf: self.webconf.append({'name': 'jetty', 'conf': '', 'webroot': conf})
                elif name == 'httpd':
                    conf = self.getStrPath(' -f ', pro)
                    if conf:
                        self.webconf.append({'name': 'httpd', 'conf': conf, 'home': '', 'webroot': ''})
                    else:
                        self.webconf.append(
                            {'name': 'httpd', 'conf': '/etc/httpd/conf/httpd.conf', 'home': '', 'webroot': ''})
                elif name == 'resin':
                    root = self.getStrPath(' --root-directory ', pro)
                    if root:
                        self.webconf.append({'name': 'resin', 'conf': '', 'home': '', 'webroot': root + '/webapps'})
                    conf = self.getStrPath(' -conf ', pro)
                    if conf: self.webconf.append({'name': 'resin', 'conf': conf, 'home': '', 'webroot': ''})
                elif name == 'jenkins':
                    root = self.getStrPath(' --webroot=', pro)
                    if root:
                        self.webconf.append({'name': 'jenkins', 'conf': '', 'home': '', 'webroot': root})





    #解析nginx的配置文件，读取web路径
    def parseNginxConf(self):
        return []

    #解析resin的配置文件，读取web路径
    def parseResinConf(self):
        return []

    def getWebRoot(self):
        if len(self.webconf):
            for conf in self.webconf:
                if conf['webroot']:
                    self.webroot.append(conf['webroot'])
                else:
                    if conf['name'] == 'nginx':
                        self.webroot = self.webroot + self.parseNginxConf(conf['conf'])
                    elif conf['name'] == 'resin':
                        self.webroot = self.webroot + self.parseResinConf(conf['conf'])


    def run(self):
