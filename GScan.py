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

if __name__ == '__main__':
    progam = '''
  _______      _______.  ______      ___      .__   __. 
 /  _____|    /       | /      |    /   \     |  \ |  |    {version:v0.1}
|  |  __     |   (----`|  ,----'   /  ^  \    |   \|  | 
|  | |_ |     \   \    |  |       /  /_\  \   |  . `  | 
|  |__| | .----)   |   |  `----. /  _____  \  |  |\   | 
 \______| |_______/     \______|/__/     \__\ |__| \__|    http://grayddq.com
                                                        
    
    '''
    print(progam)

    parser = optparse.OptionParser()
    parser.add_option("-s", "--scan", dest="scan", help=u"扫描当前系统安全问题，demo: -s all")
    parser.add_option("-l", "--log", dest="logdir", help=u"打包当前系统的所有安全日志，demo: -l /var/log/")
    options, _ = parser.parse_args()
    if options.scan:
        # 创建日志文件
        mkfile()
        file_write(progam + '\n')
        file_write(u'\n开始扫描当前系统安全状态...\n')
        print(u'\033[1;32m开始扫描当前系统安全状态...\033[0m')
        # 主机信息获取
        Host_Info().run()
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
        # 各类恶意挖矿扫描

        # WEBShell类扫描



    elif options.logdir:
        print(u'\033[1;32m开始备份整个系统安全日志...\033[0m\n')
    else:
        parser.print_help()
