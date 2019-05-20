# coding:utf-8

import os, optparse, time
from lib.core.option import *
from lib.core.globalvar import *
from lib.core.common import *
from lib.plugins.Host_Info import *
from lib.plugins.File_Analysis import *
from lib.plugins.History_Analysis import *
from lib.plugins.Proc_Analysis import *
from lib.plugins.Network_Analysis import *
from lib.plugins.Backdoor_Analysis import *
from lib.plugins.User_Analysis import *
from lib.plugins.Config_Analysis import *
from lib.plugins.Log_Analysis import *
from lib.plugins.Rootkit_Analysis import *
from lib.plugins.Webshell_Analysis import *
from lib.plugins.Sys_Init import *
from lib.plugins.Search_File import *
from lib.core.data_aggregation import *


def main(path):
    parser = optparse.OptionParser()
    parser.add_option("--version", dest="version", default=False, action='store_true', help=u"当前程序版本")

    group = optparse.OptionGroup(parser, "Mode", "GScan running mode options")
    group.add_option("--overseas", dest="overseas", default=False, action='store_true', help=u"境外模式，此参数将不进行境外ip的匹配")
    group.add_option("--full", dest="full_scan", default=False, action='store_true', help=u"完全模式，此参数将启用完全扫描")
    group.add_option("--debug", dest="debug", default=False, action='store_true', help=u"调试模式，进行程序的调试数据输出")
    group.add_option("--dif", dest="diffect", default=False, action='store_true', help=u"差异模式，比对上一次的结果，输出差异结果信息。")
    group.add_option("--sug", dest="suggestion", default=False, action='store_true', help=u"排查建议，用于对异常点的手工排查建议")
    group.add_option("--pro", dest="programme", default=False, action='store_true', help=u"处理方案，根据异常风险生成初步的处理方案")

    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, "Optimization", "Optimization options")
    group.add_option("--time", dest="time", type='string',
                     help=u"搜索指定时间内主机改动过的所有文件，demo: --time='2019-05-07 00:00:00~2019-05-07 23:00:00'")
    group.add_option("--job", dest="job", default=False, action='store_true', help=u"添加定时任务，用于定时执行程序（默认每天零点执行一次）")
    group.add_option("--hour", dest="hour", type='string', help=u"定时任务，每N小时执行一次")
    group.add_option("--log", dest="logdir", default=False, action='store_true', help=u"打包当前系统的所有安全日志（暂不支持）")
    parser.add_option_group(group)

    options, _ = parser.parse_args()

    # 初始化全局模块
    init()
    # 设置调试模式
    set_value('DEBUG', True if options.debug else False)
    # 设置国内ip模式
    set_value('Overseas', True if options.overseas else False)
    # 设置手工排查建议
    set_value('suggestion', True if options.suggestion else False)
    # 设置风险处理方案
    set_value('programme', True if options.programme else False)
    # 设置扫描模式为差异扫描
    set_value('diffect', True if options.diffect else False)
    # 设置扫描模式为完全扫描
    set_value('SCAN_TYPE', 2 if options.full_scan else 1)

    # 系统执行目录
    set_value('SYS_PATH', path)
    # 扫描日志目录
    set_value('LOG_PATH', path + "/log/gscan.log")
    # 结果记录目录
    set_value('DB_PATH', path + "/db/db.txt")
    # 扫描结果
    set_value('RESULT_INFO', [])

    if options.logdir:
        print(u'\033[1;32m开始备份整个系统安全日志...\033[0m\n')
        print(u'\033[1;32m此功能暂不支持\033[0m\n')
    elif options.job:
        print(u'\033[1;32m开始添加定时任务，建议添加任务之前先进行一次入侵检测扫描。\033[0m\n')
        if cron_write('0' if not options.hour else options.hour):
            print(u'任务添加完毕，可使用crontab -l命令查看任务')
        else:
            print(u'\033[1;31m添加失败，建议手工添加任务,参考命令crontab -e\033[0m\n')
    elif options.time:
        print(u'\033[1;32m开始进行文件搜索...\033[0m\n')
        Search_File(options.time).run()
    elif options.version:
        return
    else:
        # 创建日志文件
        mkfile()
        file_write(u'开始扫描当前系统安全状态...\n')
        print(u'\033[1;32m开始扫描当前系统安全状态...\033[0m')
        # 获取恶意特征信息
        get_malware_info(path)
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
        # 漏洞扫描

        # 路径追溯
        Data_Aggregation().run()

        # 输出报告
        print(u'-' * 30)
        print(u'\033[1;32m扫描完毕，扫描结果已记入到 %s 文件中，请及时查看\033[0m' % get_value('LOG_PATH'))
