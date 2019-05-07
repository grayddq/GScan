# coding:utf-8
from __future__ import print_function
from lib.core.common import *
import os, platform, sys, glob
from subprocess import Popen, PIPE


# 作者：咚咚呛
# 版本：v0.1
# 功能：根据本机的web服务，提取web的根目录，供后续webshell扫描使用
# nginx
# 1、进程名称中出现-c 跟配置文件
# 2、不存在-c 获取的默认配置文件/etc/nginx/nginx.conf
# 3、去读nginx.conf
# tomcat
# 1、提取-Dcatalina.home=、-Djava.io.tmpdir=
# 2、home/webapp、home/work、tmp均纳入为web扫描目录
# jetty
# 。。。。


class Webserver:
    def __init__(self):
        self.webroot = ['/var/www/', '/tmp/']
        self.webconf = []

    def getStrPath(self, match, str):
        if match in str.decode():
            path = str.decode().split(match)[1].split(' ')[0]
            return path
        return ''

    def getWebserverConf(self):
        webserver = ['nginx', 'tomcat', 'jetty', 'httpd', 'resin', 'jboss', 'weblogic', 'jenkins']
        for name in webserver:
            p1 = Popen("ps -efwww 2>/dev/null", stdout=PIPE, shell=True)
            p2 = Popen("grep " + name, stdin=p1.stdout, stdout=PIPE, shell=True)
            p3 = Popen("grep -v grep", stdin=p2.stdout, stdout=PIPE, shell=True)
            p4 = Popen("awk '{for(i=8;i<=NF;i++)printf\"%s \",$i;printf\"\\n\"}'", stdin=p3.stdout, stdout=PIPE,
                       shell=True)
            shell_process = p4.stdout.read().splitlines()
            # cmd = "ps -efwww |grep " + name + "|grep -v grep|awk '{for(i=8;i<=NF;i++)printf\"%s \",$i;printf\"\\n\"}'"
            # shell_process = os.popen(cmd).read().splitlines()
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

    # 解析nginx的配置文件，读取web路径
    def parseNginxConf(self, conf):
        if not os.path.isfile(conf): return
        if not os.path.isfile(conf): return

        with open(conf) as f:
            for readline in f:
                line = readline.lstrip().rstrip("\n").strip()
                if line == '' or line[0] == '#':
                    continue

                elif line[0:4].lower() == 'root':
                    root = line[4:].strip().rstrip(
                        ';').strip('"').strip("'").strip()
                    self.webroot.append(root)
                elif line.lower().startswith("include"):
                    include_conf = line[len("include"):].strip().rstrip(
                        ';').strip('"').strip("'").strip()

                    if '*' in include_conf:
                        include_list = glob.glob(include_conf)
                        for include in include_list:
                            self.parseNginxConf(include)
                    else:
                        self.parseNginxConf(include_conf)

    # 解析resin的配置文件，读取web路径
    def parseResinConf(self, conf):
        if not os.path.isfile(conf): return
        if not os.path.isfile(conf): return
        with open(conf) as f:
            for readline in f:
                line = readline.lstrip().rstrip("\n").strip()
                if line == '' or line[0] == '#' or line[0:4] == '<!--':
                    continue
                elif line[0:8] == '<web-app' and 'root-directory="' in line:
                    root = line.split('root-directory="')[1].split('"')[0]
                    self.webroot.append(root)

    def getWebRoot(self):
        if len(self.webconf):
            for conf in self.webconf:
                if conf['webroot']:
                    self.webroot.append(conf['webroot'])
                else:
                    if conf['name'] == 'nginx':
                        self.parseNginxConf(conf['conf'])
                    elif conf['name'] == 'resin':
                        self.parseResinConf(conf['conf'])

    def run(self):
        # 获取配置文件
        self.getWebserverConf()
        # 获取web根目录
        self.getWebRoot()


if __name__ == '__main__':
    webroot = Webserver()
    webroot.run()
    for root in webroot.webroot:
        print(root)
