# coding:utf-8
from lib.common import *
import os,platform

# 分析主机上webshell类文件
# 1、提取tomcat的web目录，进行脚本分析
# 2、提取jetty的web目录，进行脚本分析
# 3、提取nginx的web目录，进行脚本分析
# 4、提取


class Webshell_Analysis:
    def __init__(self):
        return