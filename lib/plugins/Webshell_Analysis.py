# coding:utf-8
from __future__ import print_function
from lib.core.common import *
import os, platform, sys
from lib.plugins.Webserver import *
from lib.core.globalvar import *


# 作者：咚咚呛
# 分析主机上webshell类文件
# 1、提取nginx的web目录，进行安全扫描
# 2、提取tomcat的web目录，进行安全扫描
# 3、提取jetty的web目录，进行安全扫描
# 4、提取apache的web目录，进行安全扫描
# 5、提取resin的web目录，进行安全扫描
# 6、提取jboss的web目录，进行安全扫描
# 7、提取weblogic的web目录，进行安全扫描
# 8、提取lighttpd的web目录，进行安全扫描


class Webshell_Analysis:
    def __init__(self):
        self.name = u'Webshell安全检测'
        # WEB目录
        self.webroot_list = []
        # yara的webshell规则
        self.rule = os.path.dirname(os.path.abspath(__file__)) + '/webshell_rule/'
        # 恶意webshell列表
        self.webshell_list = []

    # 获取web根目录
    def getWebRoot(self):
        webroot = Webserver()
        webroot.run()
        self.webroot_list = webroot.webroot

    # 将yara规则编译
    def getRules(self, yara):
        index = 0
        filepath = {}
        for dirpath, dirs, files in os.walk(self.rule):
            for file in files:
                ypath = os.path.join(dirpath, file)
                key = "rule" + str(index)
                filepath[key] = ypath
                index += 1
        yararule = yara.compile(filepaths=filepath)
        return yararule

    def scan_web(self):
        for webroot in self.webroot_list:
            if not os.path.exists(webroot): continue
            for file in gci(webroot):
                try:
                    if not os.path.exists(file): continue
                    if os.path.isdir(file): continue
                    if (os.path.getsize(file) == 0) or (
                            round(os.path.getsize(file) / float(1024 * 1024)) > 10): continue
                    fp = open(file, 'rb')
                    matches = self.yararule.match(data=fp.read())
                    if len(matches):
                        self.webshell_list.append(file)
                        malice_result(self.name, u'webshell安全检测', file, '', u'文件匹配上webshell特征，规则：%s' % matches[0],
                                      u'[1]cat %s' % file, u'风险',programme=u'rm %s #删除webshell文件' % file)
                except:
                    continue

    def init_scan(self):
        suspicious, malice, skip = False, False, False
        try:
            SYS_PATH = get_value('SYS_PATH')
            if sys.version_info < (3, 0):
                DEPENDENT_LIBRARIES_2_6 = "/lib/egg/yara_python-3.5.0-py2.6-linux-2.32-x86_64.egg"
                DEPENDENT_LIBRARIES_3_10 = "/lib/egg/yara_python-3.5.0-py2.7-linux-3.10-x86_64.egg"
                DEPENDENT_LIBRARIES_4_20 = "/lib/egg/yara_python-3.8.1-py2.7-linux-4.20-x86_64.egg"
                DEPENDENT_LIBRARIES_16 = "/lib/egg/yara_python-3.5.0-py2.7-macosx-10.12-x86_64.egg"
                DEPENDENT_LIBRARIES_17 = "/lib/egg/yara_python-3.5.0-py2.7-macosx-10.13-x86_64.egg"
                _kernel = platform.release()
                if _kernel.startswith('2.6'):
                    sys.path.append(SYS_PATH + DEPENDENT_LIBRARIES_2_6)
                elif _kernel.startswith('3.') and ("6." in str(platform.dist())):
                    sys.path.append(SYS_PATH + DEPENDENT_LIBRARIES_2_6)
                elif _kernel.startswith('3.'):
                    sys.path.append(SYS_PATH + DEPENDENT_LIBRARIES_3_10)
                elif _kernel.startswith('4.'):
                    sys.path.append(SYS_PATH + DEPENDENT_LIBRARIES_4_20)
                elif _kernel.startswith('16.'):
                    sys.path.append(SYS_PATH + DEPENDENT_LIBRARIES_16)
                elif _kernel.startswith('17.'):
                    sys.path.append(SYS_PATH + DEPENDENT_LIBRARIES_17)
                else:
                    return suspicious, malice, True
                import yara
            else:
                return suspicious, malice, True

            # 编译规则
            self.yararule = self.getRules(yara)
            self.scan_web()

            if len(self.webshell_list) > 0:
                malice = True
            return suspicious, malice, skip
        except:
            return suspicious, malice, skip

    def run(self):
        print(u'\n开始Webshell安全扫描')
        file_write(u'\n开始Webshell安全扫描\n')

        string_output(u' [1]Webshell安全扫描')
        self.getWebRoot()
        suspicious, malice, skip = self.init_scan()
        result_output_tag(suspicious, malice, skip)

        # 检测结果输出到文件
        result_output_file(self.name)


if __name__ == '__main__':
    info = Webshell_Analysis()
    info.run()
    print(u"Webshell文件检查异常如下：")
    for info in info.webshell_list:
        print(info)
