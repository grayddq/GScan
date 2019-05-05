# coding:utf-8
from __future__ import print_function
import os, sys, json, re, time
from imp import reload
from lib.ip.ip import *
from lib.globalvar import *

# 作者：咚咚呛
# 功能：调用的公共库
# 版本：v0.1


if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf-8')

# 用于url提取境外IP信息
ip_http = r'(htt|ft)p(|s)://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
ip_re = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
lan_ip = r'(127\.0\.0\.1)|(localhost)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})'


# 颜色打印
def pringf(strings, security=False, suspicious=False, malice=False):
    if security:
        # 安全显示绿色
        print((u'\033[1;32m%s \033[0m' % strings) + ' ]')
    elif suspicious:
        # 可疑显示黄色
        print((u'\033[1;33m%s \033[0m' % strings) + ' ]')
    elif malice:
        # 恶意显示红色
        print((u'\033[1;31m%s \033[0m' % strings) + ' ]')
    else:
        print(u'%s' % strings)
    sys.stdout.flush()
    file_write((u'%s ' % strings) + ' ]\n')


# 获取字符串宽度
def get_str_width(string):
    widths = [
        (126, 1), (159, 0), (687, 1), (710, 0), (711, 1),
        (727, 0), (733, 1), (879, 0), (1154, 1), (1161, 0),
        (4347, 1), (4447, 2), (7467, 1), (7521, 0), (8369, 1),
        (8426, 0), (9000, 1), (9002, 2), (11021, 1), (12350, 2),
        (12351, 1), (12438, 2), (12442, 0), (19893, 2), (19967, 1),
        (55203, 2), (63743, 1), (64106, 2), (65039, 1), (65059, 0),
        (65131, 2), (65279, 1), (65376, 2), (65500, 1), (65510, 2),
        (120831, 1), (262141, 2), (1114109, 1),
    ]
    width = 0
    for each in string:
        if ord(each) == 0xe or ord(each) == 0xf:
            each_width = 0
            continue
        elif ord(each) <= 1114109:
            for num, wid in widths:
                if ord(each) <= num:
                    each_width = wid
                    width += each_width
                    break
            continue

        else:
            each_width = 1
        width += each_width

    return width


# 对齐字符串，返回对齐后字符串
def align(string, width=40):
    width = 40
    string_width = get_str_width(string)
    if width > string_width:
        return string + ' ' * (width - string_width)
    else:
        return string


# 检测打印信息输出
def string_output(string):
    print(align(string, 30) + u'[ ', end='')
    file_write(align(string, 30) + u'[ ')


# 数组去重
def reRepeat(old):
    new_li = []
    for i in old:
        if i not in new_li:
            new_li.append(i)
    return new_li


# 结果内容输出到文件
def result_output_file(tag, result):
    DEBUG = get_value('DEBUG')
    if len(result) > 0:
        new = reRepeat(result)
        file_write('-' * 30 + '\n')
        file_write(tag + '\n')
        if DEBUG: print(tag)
        for info in new:
            file_write(json.dumps(info, ensure_ascii=False) + '\n')
            if DEBUG: print(json.dumps(info, ensure_ascii=False))
    if DEBUG: print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))


def result_output_tag(suspicious=False, malice=False, skip=False):
    if malice:
        pringf(u'存在风险', malice=True)
    elif suspicious and (not malice):
        pringf(u'警告', suspicious=True)
    elif skip and not suspicious and not malice:
        pringf(u'跳过', suspicious=True)
    else:
        pringf(u'OK', security=True)


# 递归目录返回文件名列表
def gci(filepath):
    filename = []
    files = os.listdir(filepath)
    for fi in files:
        fi_d = os.path.join(filepath, fi)
        if os.path.isdir(fi_d):
            filename = filename + gci(fi_d)
        else:
            filename.append(os.path.join(filepath, fi_d))
    return filename


# 创建日志文件
def mkfile():
    if os.path.exists('/var/log/gscan/gscan.log'):
        f = open('/var/log/gscan/gscan.log', "r+")
        f.truncate()
        f.close()
    else:
        if not os.path.exists('/var/log/gscan/'): os.mkdir('/var/log/gscan/')
        f = open('/var/log/gscan/gscan.log', "w")
        f.truncate()
        f.close()


# 追加文件写入
def file_write(content, logfile='/var/log/gscan/gscan.log'):
    with open(logfile, 'a+') as f:
        f.write(content)
    sys.stdout.flush()
    return


# 分析字符串是否包含反弹shell或者恶意下载执行的特征
def check_shell(content):
    try:
        # 反弹shell类
        if (('bash' in content) and (
                ('/dev/tcp/' in content) or ('telnet ' in content) or ('nc ' in content) or (
                ('exec ' in content) and ('socket' in content)) or ('curl ' in content) or (
                        'wget ' in content) or (
                        'lynx ' in content))) or (".decode('base64')" in content):
            return content
        elif ('/dev/tcp/' in content) and (('exec ' in content) or ('ksh -c' in content)):
            return content
        elif ('exec ' in content) and (('socket.' in content) or (".decode('base64')" in content)):
            return content
        # 下载执行类
        elif (('wget ' in content) or ('curl ' in content)) and (
                (' -O ' in content) or (' -s ' in content)) and (
                ' http' in content) and (
                ('php ' in content) or ('perl' in content) or ('python ' in content) or ('sh ' in content) or (
                'bash ' in content)):
            return content
        return False
    except:
        return False


# 获取配置文件的恶意域名等信息
def get_malware_info():
    try:
        malware_path = sys.path[0] + '/lib/malware/'
        if not os.path.exists(malware_path): return
        for file in os.listdir(malware_path):
            with open(malware_path + file) as f:
                for line in f:
                    malware = line.strip().replace('\n', '')
                    if len(malware) > 5:
                        if malware[0] != '#' and malware[0] != '.' and ('.' in malware):
                            malware_infos.append(malware)
    except:
        return


# 分析字符串是否包含境外IP
# 存在境外IP匹配返回真
# 不存在境外ip返回假
def check_contents_ip(contents):
    try:
        if not re.search(ip_http, contents): return False
        if re.search(lan_ip, contents): return False
        for ip in re.findall(ip_re, contents):
            if (find(ip)[0:2] != u'中国') and (find(ip)[0:3] != u'局域网') and (find(ip)[0:4] != u'共享地址') and (
                    find(ip)[0:4] != u'本机地址'):
                return True
        return False
    except:
        return False


# 判断是否为ip
# 是ip 返回真
# 非ip 返回假
def isIP(str):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(str):
        return True
    else:
        return False


# 检测IP是否境外IP
# 是境外ip则返回真
# 否则返回假
def check_ip(ip):
    try:
        ip = ip.strip()
        if not isIP(ip): return False
        if re.search(lan_ip, ip): return False
        if (find(ip)[0:2] != u'中国') and (find(ip)[0:3] != u'局域网') and (find(ip)[0:4] != u'共享地址') and (
                find(ip)[0:4] != u'本机地址'):
            return True
        return False
    except:
        return False


# 分析字符是否包含反弹shell特征、境外ip类信息
# 匹配成功则返回恶意特征信息
# 否则返回空
def analysis_strings(strings):
    try:
        mal = check_shell(strings)
        if mal: return mal
        if check_contents_ip(strings): return strings
        return ""
    except:
        return ""


# 分析文件是否包含恶意特征、反弹shell特征、境外ip类信息
# 存在返回恶意特征
# 不存在返回空
def analysis_file(file):
    try:
        SCAN_TYPE = get_value('SCAN_TYPE')
        DEBUG = get_value('DEBUG')
        if not os.path.exists(file): return ""
        if os.path.isdir(file): return ""
        if " " in file: return ""
        if 'GScan' in file: return ""
        if os.path.splitext(file)[1] == '.log': return ""
        if (os.path.getsize(file) == 0) or (round(os.path.getsize(file) / float(1024 * 1024)) > 10): return ""
        strings = os.popen("strings %s" % file).readlines()
        if len(strings) > 200: return ""
        time.sleep(0.01)
        for str in strings:
            mal = check_shell(str)
            if mal:
                if DEBUG: print(u'bash shell :%s' % mal)
                return mal
            # 完全扫描会带入恶意特征扫描
            if SCAN_TYPE == 2:
                time.sleep(0.01)
                for malware in malware_infos:
                    if malware.replace('\n', '') in str:
                        if DEBUG: print(u'malware :%s' % malware)
                        return malware
            if check_contents_ip(str):
                if DEBUG: print(u'境外IP操作类 :%s' % str)
                return str
        return ""
    except:
        return ""


# 恶意特征列表list
malware_infos = []
# 获取恶意特征信息
get_malware_info()
