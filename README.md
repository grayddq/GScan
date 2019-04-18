# GScan v0.1

本程序旨在为安全应急响应人员对Linux主机排查时提供便利，实现主机侧安全Checklist的自动化，用于快速主机安全点排查。

## 作者 ##

咚咚呛 

如有其他建议，可联系微信280495355

## CheckList检测项 ##

自动化程序的CheckList项如下：

	1、主机信息获取
	2、文件类安全扫描
	  2.1、系统可执行文件安全扫描
	  2.2、临时目录文件安全扫描
	  2.3、用户目录文件扫描
	  2.4、可疑隐藏文件扫描
	3、各用户历史操作类
	  3.1、可疑ip下载类
	  3.2、反弹shell执行类
	  3.3、下载执行类
	4、进程类安全检测
	  4.1、CUP和内存使用异常进程排查
	  4.2、隐藏进程安全扫描
	  4.3、反弹shell类进程扫描
	  4.4、恶意名进程安全扫描
	  4.5、进程对应可执行文件安全扫描
	5、网络类安全检测
	  5.1、对外链接类，境外IP类
	  5.2、恶意IP链接扫描
	  5.3、可疑端口类链接扫描
	  5.4、网卡混杂模式检测
	6、后门类检测
	  6.1、LD_PRELOAD后门检测
	  6.2、ld.so.preload后门检测
	  6.3、PROMPT_COMMAND后门检测
	  6.4、Crontab后门检测
	  6.5、Alias后门
	  6.6、SSH 后门检测
	  6.7、SSH wrapper 后门检测
	  6.8、inetd.conf 后门检测
	  6.9、xinetd.conf 后门检测
	  6.10、系统启动项后门检测
	7、账户类安全排查
	  7.1、检查root权限账户
	  7.2、查看系统中是否存在空口令账户
	  7.3、检查sudoers文件用户权限
	  7.4、查看各账户下登录公钥
	8、日志类安全分析
	  8.1、SSH登陆日志
	9、安全配置类分析
	  9.1、DNS配置检测
	  9.2、Iptables防火墙配置检测
	10、Rootkit分析
	  10.1、各类已知rootkit文件类特征
	  10.2、检查已知rootkit内核符号表
	  10.3、检查已知rootkit内核文件
	11.WebShell类文件扫描
	  11.1、WebShell类文件扫描
	  
	  

## 测试环境 ##

>系统：CentOS (6、7) + python (2.x 3.x)
>
>注：其他系统并未做兼容性测试，检测结果未知

## 部署和执行 ##
> root# <kbd>git clone https://github.com/grayddq/GScan.git</kbd>
>
> root# <kbd>cd GScan</kbd>
> 
> root# <kbd>sudo python GScan.py</kbd>


## 程序脚本说明 ##

	GScan
	----GScan.py                #主程序
	----lib                     #模块库文件
	-------common.py            #调用的公共库
	-------Host_Info.py         #主机信息获取
	-------File_Analysis.py     #文件类安全检测
	-------History_Analysis.py  #用户历史操作类
	-------Proc_Analysis.py     #进程类安全检测
	-------Network_Analysis.py  #网络类安全检测
	-------Backdoor_Analysis.py #后门类检测
	-------User_Analysis.py     #账户类安全排查
	-------Log_Analysis.py      #日志类安全分析
	-------Config_Analysis.py   #安全配置类分析
	-------Rootkit_Analysis.py  #Rootkit分析
	-------SSHAnalysis.py       #secure日志分析
	-------Webserver.py         #获取当前web服务的web根目录
	-------Webshell_Analysis.py #webshell检测
	-----ip                     #ip地址定位库
	-----malware                #各类恶意特征库
	-----egg                    #yara打包动态库
	-----webshell_rule        #webshell检测的规则



## 程序特点 ##

| 检测项 | GScan | chkrootkit | rkhunter | lynis|
|:-------------|:------: |:------: |:------: |:------: |
| 【主机文件检测】系统重要文件完整性检测 | √ |  | √ |  |
| 【主机文件检测】文件恶意特征扫描 | √ |  |  |  |
| 【主机操作检测】境外IP操作记录检测 | √ |  |  |  |
| 【主机进程检测】CPU&内存使用异常检测 | √ |  |  |  |
| 【主机进程检测】隐藏进程检测 | √ |  |  |  |
| 【主机进程检测】反弹shell进程检测 | √ |  |  |  |
| 【主机进程检测】可疑进程名检测 | √ |  |  |  |
| 【主机进程检测】进程exe恶意特征检测 | √ |  |  |  |
| 【网络链接检测】境外IP链接检测 | √ |  |  |  |
| 【网络链接检测】恶意特征链接检测 | √ |  |  |  |
| 【网络链接检测】网卡混杂模式检测 | √ |  |  |  |
| 【常规后门检测】LD_PRELOAD后门检测 | √ |  |  |  |
| 【常规后门检测】ld.so.preload后门检测 | √ |  |  |  |
| 【常规后门检测】PROMPT_COMMAND后门检测 | √ |  |  |  |
| 【常规后门检测】Crontab后门检测 | √ |  |  |  |
| 【常规后门检测】alias后门检测 | √ |  |  |  |
| 【常规后门检测】SSH后门检测 | √ |  |  |  |
| 【常规后门检测】SSH Wrapper后门检测 | √ |  |  |  |
| 【常规后门检测】inetd.conf后门检测 | √ |  |  |  |
| 【常规后门检测】xinetd.conf后门检测 | √ |  |  |  |
| 【常规后门检测】系统启动项后门检测 | √ |  |  |  |
| 【账户安全检测】root权限账户检测 | √ |  |  |  |
| 【账户安全检测】空口令账户检测 | √ |  |  |  |
| 【账户安全检测】sudoers文件检测 | √ |  |  |  |
| 【日志安全检测】secure日志安全检测 | √ |  |  |  |
| 【安全配置检测】DNS设置检测 | √ |  |  |  |
| 【安全配置检测】防火墙设置检测 | √ |  |  |  |
| 【Rootkit检测】已知Rootkit类特征检测 | √ |  | √ |  |
| 【WEBShell检测】Nginx服务WebShell检测 | √ | x | x | x |
| 【WEBShell检测】Apache服务WebShell检测 | √ | x | x | x |
| 【WEBShell检测】Tomcat服务WebShell检测 | √ | x | x | x |
| 【WEBShell检测】Jetty服务WebShell检测 | √ | x | x | x |
| 【WEBShell检测】Resin服务WebShell检测 | √ | x | x | x |
| 【WEBShell检测】Jenkins服务WebShell检测 | √ | x | x | x |
| 【WEBShell检测】各默认web目录WebShell检测 | √ | x | x | x |
| 【系统兼容性】 | x | √ | √ | √ |
| 【安全性检查】漏洞检查 | x |  |  | √ |




## 检测结果 ##

日志及结果目录默认：/var/log/gscan/gscan.log


## 运行截图 ##
![Screenshot](pic/1.png)

![Screenshot](pic/2.png)

![Screenshot](pic/3.png)
