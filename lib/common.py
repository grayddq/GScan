# coding:utf-8
import os, sys


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


def align(string, width=40):
    width=40
    string_width = get_str_width(string)
    if width > string_width:
        return string + ' ' * (width - string_width)
    else:
        return string


'''
# 字符串对齐
def align(string, length=0):
    if length == 0:
        return string
    slen = len(string)
    re = string
    if isinstance(string, str):
        placeholder = ' '
    else:
        placeholder = u'　'
    while slen < length:
        re += placeholder
        slen += 1
    return re
'''


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
