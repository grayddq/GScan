# coding:utf-8
import os, optparse, time
from lib.Host_Info import *
from lib.File_Analysis import *
from lib.History_Analysis import *
from lib.Proc_Analysis import *
from lib.Network_Analysis import *
from lib.Backdoor_Analysis import *
from lib.User_Analysis import *
from lib.common import *
from lib.Config_Analysis import *
from lib.Log_Analysis import *
from lib.Rootkit_Analysis import *
from lib.Webshell_Analysis import *
from lib.Init import *
from lib.globalvar import *

# 作者：咚咚呛
# 版本：v0.1
# 功能：本程序旨在为安全应急响应人员对Linux主机排查时提供便利，实现主机侧安全Checklist的自动化，用于快速主机安全点排查。


if __name__ == '__main__':
    progam = u'''
  _______      _______.  ______      ___      .__   __. 
 /  _____|    /       | /      |    /   \     |  \ |  |    {version:v0.1}
|  |  __     |   (----`|  ,----'   /  ^  \    |   \|  | 
|  | |_ |     \   \    |  |       /  /_\  \   |  . `  |    {author:咚咚呛}
|  |__| | .----)   |   |  `----. /  _____  \  |  |\   | 
 \______| |_______/     \______|/__/     \__\ |__| \__|    http://grayddq.top
                                                        
    
    '''
    print(progam)

    parser = optparse.OptionParser()
    parser.add_option("--overseas", dest="overseas", default=False, action='store_true',
                      help=u"默认国内模式，设置此参数将不进行境外ip的匹配")
    parser.add_option("--full", dest="full_scan", default=False, action='store_true', help=u"完全扫描，默认为快速扫描")
    parser.add_option("--debug", dest="debug", default=False, action='store_true', help=u"调试模式，进行程序的调试数据输出")
    parser.add_option("-l", "--log", dest="logdir", help=u"打包当前系统的所有安全日志，demo: -l /var/log/")
    options, _ = parser.parse_args()

    if not options.logdir:
        # 设置调试模式
        init()
        set_value('DEBUG', True if options.debug else False)
        # 设置国内ip模式
        set_value('Overseas', False if options.overseas else True)
        # 设置扫描模式为完全扫描
        set_value('SCAN_TYPE', 2 if options.full_scan else 1)
        # 创建日志文件
        mkfile()
        file_write(progam + '\n')
        file_write(u'\n开始扫描当前系统安全状态...\n')
        print(u'\033[1;32m开始扫描当前系统安全状态...\033[0m')
        # 主机信息获取
        Host_Info().run()
        # 系统初始化检查
        SYS_INIT().run()
        # 文件类安全检测
        File_Analysis().run()
        # 主机历史操作类扫描
        History_Analysis().run()
        # 主机进程类安全扫描
        Proc_Analysis().run()
        # 网络链接类安全扫描
        Network_Analysis().run()
        # 后门类扫描
        Backdoor_Analysis().run()
        # 账户类扫描
        User_Analysis().run()
        # 安全日志类
        Log_Analysis().run()
        # 安全配置类
        Config_Analysis().run()
        # rootkit检测
        Rootkit_Analysis().run()
        # WEBShell类扫描
        Webshell_Analysis().run()

        # 输出报告
        print(u'-' * 30)
        print(u'\033[1;32m扫描完毕，扫描结果已记入到/var/log/gscan/gscan.log文件中，请及时查看\033[0m')


    elif options.logdir:
        print(u'\033[1;32m开始备份整个系统安全日志...\033[0m\n')
    else:
        parser.print_help()
