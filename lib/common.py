# coding:utf-8
import os, sys, json
from imp import reload

if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf-8')


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


# 分析字符串是否包含反弹shell或者恶意下载执行的特征
def check_shell(content):
    try:
        # 反弹shell类
        if (('bash' in content) and (
                ('/dev/tcp/' in content) or ('telnet ' in content) or ('nc ' in content) or (
                ('exec ' in content) and ('socket' in content)) or ('curl ' in content) or (
                        'wget ' in content) or (
                        'lynx ' in content))) or (".decode('base64')" in content):
            return True
        elif ('/dev/tcp/' in content) and (('exec ' in content) or ('ksh -c' in content)):
            return True
        elif ('exec ' in content) and (('socket.' in content) or (".decode('base64')" in content)):
            return True
        # 下载执行类
        elif (('wget ' in content) or ('curl ' in content)) and (
                (' -O ' in content) or (' -s ' in content)) and (
                ' http' in content) and (
                ('php ' in content) or ('perl' in content) or ('python ' in content) or ('sh ' in content) or (
                'bash ' in content)):
            return True
        return False
    except:
        return False