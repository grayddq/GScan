# coding:utf-8
import os, optparse


# 作者：咚咚呛
# 1】分析secure的日志，分析出存在爆破且成功的记录
#   1、是否存在爆破行为
#   1.1 一个IP错误20+以上(相同账户和不同账户)
#   1.2 同C端IP错误100+以上(相同账户和不同账户)
#   2、爆破行为是否成功
#   2.1 提取爆破的IP或IP端去提取成功事件
#   3、爆破成功的账户、时间、IP
# 2】分析


class SSH_Analysis:
    def __init__(self, log='', log_dir='', ip_failed_count=50, ips_failed_count=200):
        # 单IP错误的次数，超过此错误代表发生了爆破行为
        self.ip_failed_count = ip_failed_count
        # IP C端错误的次数，超过此错误代表发生了爆破行为
        self.ips_failed_count = ips_failed_count
        # 记录爆破成功的信息
        self.correct_baopo_infos = []

        # secure目录路径
        if not log:
            self.log_dir = '/var/log/' if not log_dir else log_dir
            self.dir_file_detect()
        # secure日志路径
        if log: self.attack_detect(log)

    # 遍历secure类文件去分析
    def dir_file_detect(self):
        files = [os.path.join(self.log_dir, i) for i in os.listdir(self.log_dir) if
                 (not os.path.isdir(i)) and ('secure' in i)]
        for log in files:
            self.attack_detect(log)

    # 数组去重
    def reRepeat(self, old):
        new_li = []
        for i in old:
            if i not in new_li:
                new_li.append(i)
        return new_li

    def filter(self, old, count):
        new_li = []
        for key in old:
            if old[key] > count:
                new_li.append({key: old[key]})
        return new_li

    # 实现counter函数，由于某些版本不支持，又不想过多引入库
    def Counter(self, old):
        count_dict = dict()
        for item in old:
            if item in count_dict:
                count_dict[item] += 1
            else:
                count_dict[item] = 1
        return count_dict

    # 爆破成功的信息
    def attack_detect(self, log):
        # 账户错误特征
        username_error = 'Invalid user'
        # 账户正确密码错误特征
        username_correct = 'Failed password for'
        # 成功登陆
        username_password_correct = 'Accepted password for'
        # 所有错误登陆日志ip
        failed_ip = []
        # 登陆成功日志
        correct_infos = []
        # C端ip登陆错误日志
        failed_c_ips = []
        filename = os.path.basename(log)
        year = ''
        if 'secure-' in filename and len(filename) == 15:
            year = filename[7:11]
        # 打开日志文件
        f = open(log, 'r')

        for i in f:
            if (username_error in i) and ('from' in i) and ('sshd' in i):
                failed_ip.append(i.split(': ')[1].split()[4])
            elif (username_correct in i) and ('from' in i) and ('sshd' in i):
                failed_ip.append(i.split(': ')[1].rsplit()[-4])
            elif username_password_correct in i and ('sshd' in i):
                ip = i.split(': ')[1].split()[5]
                user = i.split(': ')[1].split()[3]
                # time = i.split(' sshd[')[0]
                time = ' '.join(i.replace('  ', ' ').split(' ', 4)[:3]) + " " + year
                # 获取所有登陆成功的记录
                correct_infos.append({'ip': ip, 'user': user, 'time': time})
        # 记录登陆失败攻击源IP地址和尝试次数
        # 1.1 判断是否发生了爆破行为,failed_ip_dict为存在爆破的失败ip列表:次数
        failed_ip_dict = self.filter(dict(self.Counter(failed_ip)), self.ip_failed_count)

        # 1.2 判断是否发生了C端类的爆破行为，
        for key in failed_ip:
            failed_c_ips.append(key.rsplit('.', 1)[0])
        failed_c_ips_dict = self.filter(dict(self.Counter(failed_c_ips)), self.ips_failed_count)

        # 2、判断爆破行为是否成功，
        for correct_info in correct_infos:
            for failed in failed_ip_dict:
                if correct_info['ip'] in failed: self.correct_baopo_infos.append(correct_info)
            for failed in failed_c_ips_dict:
                if correct_info['ip'].rsplit('.', 1)[0] in failed: self.correct_baopo_infos.append(correct_info)

        self.correct_baopo_infos = self.reRepeat(self.correct_baopo_infos)


if __name__ == '__main__':
    # print SSH_Analysis(log="secure", log_dir="").correct_baopo_infos
    parser = optparse.OptionParser()
    parser.add_option("-d", "--dir", dest="dir", help=u"target dir，demo: -d /var/log/")
    parser.add_option("-f", "--file", dest="file", help=u"target file，demo: -p /var/log/secure")
    options, _ = parser.parse_args()
    options.file = 'secure'
    if options.dir or options.file:
        print(u'存在爆破且成功的信息：')
        print(SSH_Analysis(log=options.file, log_dir=options.dir).correct_baopo_infos)
    else:
        parser.print_help()
