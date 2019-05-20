# coding:utf-8
from __future__ import print_function
import os, sys, json, re, time, pwd, logging
from imp import reload
from lib.core.ip.ip import *
from lib.core.globalvar import *

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

# 恶意特征列表list
malware_infos = []


# 颜色打印前端，根据特征赋予字符不同的颜色
# 用于用户端视觉效果的打印。
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


# 获取字符串宽度，包含汉语、字符、数字等
# 返回：字符串长度大小
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


# 对齐字符串，用于用户视觉上的打印
# 返回：对其后字符串
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


# 数组去重功能
# 返回：去重后数组
def reRepeat(old):
    new_li = []
    for i in old:
        if i not in new_li:
            new_li.append(i)
    return new_li


# 获取文件的最近的改动时间
# 返回:文件更改时间戳
def get_file_attribute(file):
    try:
        # 文件最近修改时间
        ctime = os.stat(file).st_mtime
        cctime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ctime))
        # 文件所属者uid
        uid = os.stat(file).st_uid
        username = pwd.getpwuid(uid).pw_name
        return cctime, username
    except:
        return "", ""


# 获取进程的开始时间
# 返回：进程开始时间
def get_process_start_time(pid):
    user, stime = '', ''
    try:
        pro_info = os.popen("ps -eo pid,user,lstart 2>/dev/null| grep -v 'grep'|grep " + pid).read().splitlines()
        for infos in pro_info:
            info = infos.strip()
            if pid == info.split(' ')[0].strip():
                user = info.split(' ', 2)[1].strip()
                sstime = info.split(' ', 2)[2].strip()
                stime = os.popen("date -d " + sstime + " '+%Y-%m-%d %H:%M:%S' 2>/dev/null").read().splitlines()
                return user, stime[0]
        return user, stime
    except:
        return user, stime


# 检测风险结果，进行全局变量结果录入
# 每个风险详情包含几项
# 1、风险检测大项 checkname
# 2、风险名称 vulname
# 3、异常文件 file
# 4、异常进程 pid
# 4、所属用户 user
# 4、异常信息 info
# 6、异常时间 mtime
# 7、风险等级 level 存在风险-可疑
# 7、建议手工确认步骤 consult
# 返回：检测项恶意信息数组
def malice_result(checkname, vulname, file, pid, info, consult, level, mtime='', user='', programme=''):
    mtime_temp, user_temp = '', ''
    if file:
        mtime_temp, user_temp = get_file_attribute(file)
    if pid:
        mtime_temp, user_temp = get_process_start_time(pid)
    if not mtime: mtime = mtime_temp
    if not user: user = user_temp
    malice_info = {u'检测项': checkname, u'风险名称': vulname, u'异常文件': file, u'进程PID': pid, u'异常时间': mtime, u'所属用户': user,
                   u'异常信息': ' '.join(info.split()), u'手工排查确认': consult, u'风险级别': level, u'处理方案': programme}
    result_info = get_value('RESULT_INFO')
    result_info.append(malice_info)
    set_value('RESULT_INFO', result_info)


# 结果内容输出到文件
def result_output_file(tag):
    DEBUG = get_value('DEBUG')
    RESULT_INFO = get_value('RESULT_INFO')
    info = []
    for result in RESULT_INFO:
        if result[u'检测项'] == tag:
            info.append(result)
    if len(info) > 0:
        new = reRepeat(info)
        file_write('-' * 30 + '\n')
        file_write(tag + '\n')
        if DEBUG: print(tag)
        for info in new:
            file_write(json.dumps(info, ensure_ascii=False) + '\n')
            if DEBUG: print(json.dumps(info, ensure_ascii=False))
    if DEBUG: print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))


# 分析结果输出，用于用户视觉效果
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
    try:
        files = os.listdir(filepath)
        for fi in files:
            fi_d = os.path.join(filepath, fi)
            if os.path.isdir(fi_d):
                filename = filename + gci(fi_d)
            else:
                filename.append(os.path.join(filepath, fi_d))
        return filename
    except:
        return filename


# 创建日志文件
def mkfile():
    SYS_PATH = get_value('SYS_PATH')
    LOG_PATH = get_value('LOG_PATH')
    DB_PATH = get_value('DB_PATH')
    # 判断日志目录是否存在，不存在则创建日志目录
    if not os.path.exists(SYS_PATH + '/log/'): os.mkdir(SYS_PATH + '/log/')
    if not os.path.exists(SYS_PATH + '/db/'): os.mkdir(SYS_PATH + '/db/')
    # 判断日志文件是否存在，不存在则创建,存在则情况
    f = open(LOG_PATH, "w")
    f.truncate()
    f.close()
    # 判断本地数据文件是否存在，不存在则创建
    if not os.path.exists(DB_PATH):
        f = open(DB_PATH, "w")
        f.truncate()
        f.close()


# 追加文件写入
def file_write(content):
    LOG_PATH = get_value('LOG_PATH')
    with open(LOG_PATH, 'a+') as f:
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
def get_malware_info(path):
    try:
        malware_path = path + '/lib/malware/'
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
        Overseas = get_value('Overseas')
        if Overseas: return False
        if not re.search(ip_http, contents): return False
        if re.search(lan_ip, contents): return False
        for ip in re.findall(ip_re, contents):
            if (find(ip)[0:2] != u'中国') and (find(ip)[0:3] != u'局域网') and (find(ip)[0:4] != u'共享地址') and (
                    find(ip)[0:4] != u'本机地址') and (find(ip)[0:4] != u'本地链路') and (find(ip)[0:4] != u'保留地址'):
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
        Overseas = get_value('Overseas')
        if Overseas: return False
        ip = ip.strip()
        if not isIP(ip): return False
        if re.search(lan_ip, ip): return False
        if (find(ip)[0:2] != u'中国') and (find(ip)[0:3] != u'局域网') and (find(ip)[0:4] != u'共享地址') and (
                find(ip)[0:4] != u'本机地址') and (find(ip)[0:4] != u'本地链路') and (find(ip)[0:4] != u'保留地址'):
            return True
        return False
    except:
        return False


# 分析一串字符串是否包含反弹shell、获取对应字串内可能存在的文件，并判断文件是否存在恶意特征。
# 匹配成功则返回恶意特征信息
# 否则返回空
def analysis_strings(contents):
    try:
        content = contents.replace('\n', '')
        # 反弹shell类
        if check_shell(content):
            return u"反弹shell类：%s" % content
        # 境外IP操作类
        elif check_contents_ip(content):
            return u"境外ip操作类：%s" % content
        else:
            for file in content.split(' '):
                if not os.path.exists(file): continue
                if os.path.isdir(file): continue
                malware = analysis_file(file)
                if malware: return u"引用恶意文件%s，可疑内容：%s" % (file, malware)
        return ""
    except:
        return ""


# 分析文件是否包含恶意特征、反弹shell特征、境外ip类信息
# 存在返回恶意特征
# 不存在返回空
def analysis_file(file, mode='fast'):
    try:
        SCAN_TYPE = get_value('SCAN_TYPE')
        DEBUG = get_value('DEBUG')
        Overseas = get_value('Overseas')

        if not os.path.exists(file): return ""
        if os.path.isdir(file): return ""
        if (" " in file) or ("GScan" in file) or ("\\" in file) or (".jpg" in file) or (")" in file) or (
                "(" in file) or (".log" in file): return ""
        if (os.path.getsize(file) == 0) or (round(os.path.getsize(file) / float(1024 * 1024)) > 10): return ""
        strings = os.popen("strings %s 2>/dev/null" % file).read().splitlines()
        if len(strings) > 200: return ""

        time.sleep(0.01)
        for str in strings:
            if check_shell(str):
                if DEBUG: print(u'文件：%s ，bash shell :%s' % file, str)
                return u"反弹shell类：%s" % str
            # 完全扫描会带入恶意特征扫描
            if SCAN_TYPE == 2:
                time.sleep(0.01)
                for malware in malware_infos:
                    if malware.replace('\n', '') in str:
                        if DEBUG: print(u'文件：%s ，恶意特征 :%s' % file, malware)
                        return u"恶意特征类：%s，匹配规则:%s" % (str, malware)
            if Overseas: continue
            if check_contents_ip(str):
                if DEBUG: print(u'文件：%s ，境外IP操作类 :%s' % file, str)
                return u"境外ip操作类：%s" % str
        return ""
    except:
        return ""


# 写定时任务信息
def cron_write(hour='0'):
    SYS_PATH = get_value('SYS_PATH')
    if not os.path.exists('/var/spool/cron/'): return False
    if os.path.exists('/var/spool/cron/root'):
        f = open('/var/spool/cron/root', 'a+')
        # 每N小时执行一次
        if hour != '0':
            f.write('* */' + hour + ' * * * python ' + SYS_PATH + '/GScan.py --dif\n')
        else:
            f.write('0 0 * * * python ' + SYS_PATH + '/GScan.py --dif\n')
        f.close()
    else:
        f = open('/var/spool/cron/root', 'w')
        # 每N小时执行一次
        if hour != '0':
            f.write('* */' + hour + ' * * * python ' + SYS_PATH + '/GScan.py --dif\n')
        else:
            f.write('0 0 * * * python ' + SYS_PATH + '/GScan.py --dif\n')
        f.close()
    return True


# 日志输出到指定文件，用于syslog打印
def loging():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('GScan')
    SYS_PATH = get_value('SYS_PATH')
    logfile = SYS_PATH + '/log/log.log'
    fh = logging.FileHandler(logfile)
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.propagate = False
    return logger
