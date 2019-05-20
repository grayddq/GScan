# GScan v0.1

本程序旨在为安全应急响应人员对Linux主机排查时提供便利，实现主机侧Checklist的自动全面化检测，根据检测结果自动数据聚合，进行黑客攻击路径溯源。

## 作者 ##

咚咚呛 

如有其他建议，可联系微信280495355

## CheckList检测项 ##

自动化程序的CheckList项如下：
    
	1、主机信息获取
	2、系统初始化alias检查
	3、文件类安全扫描
	  3.1、系统重要文件完整行扫描
	  3.2、系统可执行文件安全扫描
	  3.3、临时目录文件安全扫描
	  3.4、用户目录文件扫描
	  3.5、可疑隐藏文件扫描
	4、各用户历史操作类
	  4.1、境外ip操作类
	  4.2、反弹shell类
	5、进程类安全检测
	  5.1、CUP和内存使用异常进程排查
	  5.2、隐藏进程安全扫描
	  5.3、反弹shell类进程扫描
	  5.4、恶意进程信息安全扫描
	  5.5、进程对应可执行文件安全扫描
	6、网络类安全检测
	  6.1、境外IP链接扫描
	  6.3、恶意特征链接扫描
	  6.4、网卡混杂模式检测
	7、后门类检测
	  7.1、LD_PRELOAD后门检测
	  7.2、LD_AOUT_PRELOAD后门检测
	  7.3、LD_ELF_PRELOAD后门检测
	  7.4、LD_LIBRARY_PATH后门检测
	  7.5、ld.so.preload后门检测
	  7.6、PROMPT_COMMAND后门检测
	  7.7、Cron后门检测
	  7.8、Alias后门
	  7.9、SSH 后门检测
	  7.10、SSH wrapper 后门检测
	  7.11、inetd.conf 后门检测
	  7.12、xinetd.conf 后门检测
	  7.13、setUID 后门检测
	  7.14、8种系统启动项后门检测
	8、账户类安全排查
	  8.1、root权限账户检测
	  8.2、空口令账户检测
	  8.3、sudoers文件用户权限检测
	  8.4、查看各账户下登录公钥
	  8.5、账户密码文件权限检测
	9、日志类安全分析
	  9.1、secure登陆日志
	  9.2、wtmp登陆日志
	  9.3、utmp登陆日志
	  9.4、lastlog登陆日志
	10、安全配置类分析
	  10.1、DNS配置检测
	  10.2、Iptables防火墙配置检测
	  10.3、hosts配置检测
	11、Rootkit分析
	  11.1、检查已知rootkit文件类特征
	  11.2、检查已知rootkit LKM类特征
	  11.3、检查已知恶意软件类特征检测
	12.WebShell类文件扫描
	  12.1、WebShell类文件扫描
	  
	  

## 测试环境 ##

>系统：CentOS (6、7) + python (2.x、3.x)
>
>权限：root权限启动
>
>执行时间：默认安全扫描大概执行时间为4～6分钟，完全扫描在1～2小时之间，程序执行时间的长度由检测文件的多少决定，有可能会存在较长的时间，请耐心等待
>
>兼容性：目前程序只针对Centos进行开发测试，其他系统并未做兼容性，检测结果未知

## 部署和执行 ##

程序下载

> root# <kbd>git clone https://github.com/grayddq/GScan.git</kbd>
>
> root# <kbd>cd GScan</kbd>

参数参考

>     sh-3.2# python GScan.py -h
>     
>       _______      _______.  ______      ___      .__   __.
>      /  _____|    /       | /      |    /   \     |  \ |  |    {version:v0.1}
>     |  |  __     |   (----`|  ,----'   /  ^  \    |   \|  |
>     |  | |_ |     \   \    |  |       /  /_\  \   |  . `  |    {author:咚咚呛}
>     |  |__| | .----)   |   |  `----. /  _____  \  |  |\   |
>      \______| |_______/     \______|/__/     \__\ |__| \__|    http://grayddq.top
>       
>       
>     Usage: GScan.py [options]
>      
>     Options:
>      
>       -h, --help     show this help message and exit
>       --version      当前程序版本
>      
>      Mode:
>         GScan running mode options
>        
>         --overseas   境外模式，此参数将不进行境外ip的匹配
>         --full       完全模式，此参数将启用完全扫描
>         --debug      调试模式，进行程序的调试数据输出
>         --dif        差异模式，比对上一次的结果，输出差异结果信息。
>         --sug        排查建议，用于对异常点的手工排查建议
>         --pro        处理方案，根据异常风险生成初步的处理方案
>        
>      Optimization:
>         Optimization options
>        
>         --time=TIME  搜索指定时间内主机改动过的所有文件，demo: --time='2019-05-07
>                      00:00:00~2019-05-07 23:00:00'
>         --job        添加定时任务，用于定时执行程序
>         --log        打包当前系统的所有安全日志（暂不支持）


执行命令参考：

>root# <kbd>python GScan.py</kbd>
>
>root# <kbd>python GScan.py --sug --pro</kbd>
>
>进行定时任务设置，异常日志将按行输出到./GScan/log/log.log，可通过syslog等服务同步日志信息。
>
>root# <kbd>python GScan.py --job</kbd> #每天零点执行一次
>
>root# <kbd>python GScan.py --job --hour=2</kbd> #每2小时执行一次

## 程序脚本说明 ##

	GScan
	----GScan.py                   #主程序
	----log                        #日志和结果记录
	----lib                        #模块库文件
	-------core                    #调用库文件
	----------common.py            #公共库模块
	----------globalvar.py         #全局参数管理模块
	----------option.py            #参数管理模块
	----------ip                   ##ip地址定位库
	-------egg                     #yara打包动态库
	-------malware                 #恶意特征库
	-------plugins                 #检测插件模块库
	----------Host_Info.py         #主机信息获取
	----------File_Analysis.py     #文件类安全检测
	----------History_Analysis.py  #用户历史操作类
	----------Proc_Analysis.py     #进程类安全检测
	----------Network_Analysis.py  #网络类安全检测
	----------Backdoor_Analysis.py #后门类检测
	----------User_Analysis.py     #账户类安全排查
	----------Log_Analysis.py      #日志类安全分析
	----------Config_Analysis.py   #安全配置类分析
	----------Rootkit_Analysis.py  #Rootkit分析
	----------SSHAnalysis.py       #secure日志分析
	----------Webserver.py         #获取当前web服务的web根目录
	----------Webshell_Analysis.py #webshell检测
	----------webshell_rule        #webshell检测的规则


## 程序特点 ##

>1、程序检测的逻辑和方法，均是由一线安全应急人员根据多年实战经验总结出来的。
>
>2、程序包括10W+的恶意特征信息，用于恶意文件的比对和查杀。
>
>3、结果自动化分析，进行黑客攻击溯源



## 程序对标 ##

>入侵痕迹的检测按照经验归纳为如下子项，省去了一些安全配置和基线类等无关项。
>
>注：对比内容为程序的实际检测输出结果，其仅代表个人的观点，不代表产品说明。

    GScan      程序定位为安全人员提供的一项入侵检测工具，旨在尽可能的发现入侵痕迹，溯源出黑客攻击的整个路径。
	chkrootkit 程序定位为安全人员提供的一项入侵检测工具，旨在发现被植入的后门或者rootkit。
	rkhunter   程序定位为安全人员提供的一项入侵检测工具，旨在发现被植入的后门或者rootkit。
	lynis      程序定位为安全人员日常使用的一款用于主机基线和审计的工具，可辅助漏洞扫描和配置管理，也可部分用于入侵检测。


| 检测项 |  GScan  | chkrootkit | rkhunter |  lynis  |
|:-------------|:---------: |:------: |:------: |:---------: |
| 对比版本 | v0.1 | v0.53 | v1.4.6 | v2.7.1 |
| 【检测前检查项】文件alias检查 | √ | √ |  |  |
| 【检测前检查项】系统重要文件完整性检测 | √ | √ |  |  |
| 【主机文件检测】系统重要文件权限检测 |  | √ | √ |  |
| 【主机文件检测】文件恶意特征扫描 | √ |  |  |  |
| 【主机文件检测】文件境外IP特征扫描 | √ |  |  |  |
| 【主机文件检测】敏感目录mount隐藏检测 |  |  | √ | √ |
| 【主机操作检测】境外IP操作记录检测 | √ |  |  |  |
| 【主机操作检测】可疑操作或异常检测 | √ | √ |  |  |
| 【主机进程检测】CPU&内存使用异常检测 | √ |  |  | √ |
| 【主机进程检测】I/O异常检测 |  |  |  | √ |
| 【主机进程检测】隐藏进程检测 | √ |  | √ |  |
| 【主机进程检测】反弹shell进程检测 | √ |  |  |  |
| 【主机进程检测】可疑进程名称检测 | √ |  |  |  |
| 【主机进程检测】进程exe恶意特征检测 | √ |  |  |  |
| 【主机进程检测】僵尸进程检测 |  |  |  | √ |
| 【主机进程检测】可疑的较大共享内存检测 |  |  | √ |  |
| 【主机进程检测】内存恶意特征检测 |  |  |  |  |
| 【网络链接检测】境外IP链接检测 | √ |  |  |  |
| 【网络链接检测】恶意特征链接检测 | √ | √ | √ |  |
| 【网络链接检测】网卡混杂模式检测 | √ | √ | √ | √ |
| 【常规后门检测】LD_PRELOAD后门检测 | √ |  | √ |  |
| 【常规后门检测】LD_AOUT_PRELOAD后门检测 | √ |  | √ |  |
| 【常规后门检测】LD_ELF_PRELOAD后门检测 | √ |  | √ |  |
| 【常规后门检测】LD_LIBRARY_PATH后门检测 | √ |  | √ |  |
| 【常规后门检测】ld.so.preload后门检测 | √ |  | √ |  |
| 【常规后门检测】PROMPT_COMMAND后门检测 | √ |  |  |  |
| 【常规后门检测】Cron后门检测(/var/spool/cron/) | √ |  |  |  |
| 【常规后门检测】Cron后门检测(/etc/cron.d/) | √ |  |  |  |
| 【常规后门检测】Cron后门检测(/etc/cron.daily/) | √ |  |  |  |
| 【常规后门检测】Cron后门检测(/etc/cron.weekly/) | √ |  |  |  |
| 【常规后门检测】Cron后门检测(/etc/cron.hourly/) | √ |  |  |  |
| 【常规后门检测】Cron后门检测(/etc/cron.monthly/) | √ |  |  |  |
| 【常规后门检测】alias后门检测 | √ |  | √ |  |
| 【常规后门检测】其他环境变量未知后门检测 | √ |  |  |  |
| 【常规后门检测】SSH后门检测 | √ |  |  |  |
| 【常规后门检测】SSH Wrapper后门检测 | √ |  |  |  |
| 【常规后门检测】inetd.conf后门检测 | √ |  | √ |  |
| 【常规后门检测】xinetd.conf后门检测 | √ |  | √ |  |
| 【常规后门检测】setUID后门检测 | √ |  |  |  |
| 【常规后门检测】setGID后门检测 |  |  |  |  |
| 【常规后门检测】fstab后门检测 |  |  |  |  |
| 【常规后门检测】系统启动项(/etc/init.d/)后门检测 | √ |  | √ |  |
| 【常规后门检测】系统启动项(/etc/rc.d/)后门检测 | √ |  | √ |  |
| 【常规后门检测】系统启动项(/etc/rc.local)后门检测 | √ |  | √ |  |
| 【常规后门检测】系统启动项(/usr/local/etc/rc.d)后门检测 | √ |  | √ |  |
| 【常规后门检测】系统启动项(/usr/local/etc/rc.local)后门检测 | √ |  | √ |  |
| 【常规后门检测】系统启动项(/etc/conf.d/local.start)后门检测 | √ |  | √ |  |
| 【常规后门检测】系统启动项(/etc/inittab)后门检测 | √ |  | √ |  |
| 【常规后门检测】系统启动项(/etc/systemd/system)后门检测 | √ |  | √ |  |
| 【账户安全检测】root权限账户检测 | √ |  | √ | √ |
| 【账户安全检测】空口令账户检测 | √ |  | √ | √ |
| 【账户安全检测】sudoers文件检测 | √ |  |  | √ |
| 【账户安全检测】用户组文件检测 |  |  | √ | √ |
| 【账户安全检测】密码文件检测 | √ |  | √ | √ |
| 【账户安全检测】用户免密登录公钥检测 | √ |  | √ |  |
| 【日志安全检测】secure日志安全检测 | √ |  |  |  |
| 【日志安全检测】wtmp日志安全检测 | √ | √ |  |  |
| 【日志安全检测】utmp日志安全检测 | √ | √ |  |  |
| 【日志安全检测】lastlog日志安全检测 | √ | √ |  |  |
| 【日志安全检测】web日志安全检测 |  |  |  |  |
| 【日志安全检测】其他服务日志安全检测 |  |  |  |  |
| 【安全配置检测】DNS设置检测 | √ |  |  | √ |
| 【安全配置检测】防火墙设置检测 | √ |  |  | √ |
| 【安全配置检测】hosts安全检测 | √ |  |  | √ |
| 【Rootkit检测】已知Rootkit文件特征检测 | √ | √ | √ |  |
| 【Rootkit检测】已知Rootkit LKM类特征检测 | √ | √ | √ |  |
| 【Rootkit检测】恶意软件类特征检测 | √ |  | √ |  |
| 【WEBShell检测】Nginx服务WebShell检测 | √ |  |  |  |
| 【WEBShell检测】Apache服务WebShell检测 | √ |  |  |  |
| 【WEBShell检测】Tomcat服务WebShell检测 | √ |  |  |  |
| 【WEBShell检测】Jetty服务WebShell检测 | √ |  |  |  |
| 【WEBShell检测】Resin服务WebShell检测 | √ |  |  |  |
| 【WEBShell检测】Jenkins服务WebShell检测 | √ |  |  |  |
| 【WEBShell检测】其他默认web目录WebShell检测 | √ |  |  |  |
| 【漏洞类检查】服务漏洞或配置错误检查 |  |  |  | √ |
| 【自动攻击路径追溯】攻击路径追溯 | √ |  |  |  |



## 检测结果 ##

日志及结果目录默认：./GScan/log/gscan.log


## 运行截图 ##
![Screenshot](pic/1.png)

![Screenshot](pic/2.png)

![Screenshot](pic/3.png)

![Screenshot](pic/4.png)

![Screenshot](pic/5.png)

## 参考链接 ##
http://www.chkrootkit.org

https://github.com/CISOfy/lynis

http://rkhunter.sourceforge.net/

https://github.com/stamparm/maltrail

