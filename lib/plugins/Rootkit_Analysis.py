# coding:utf-8
from __future__ import print_function
import os, optparse, time, sys, json
from lib.core.common import *


# 作者：咚咚呛
# Rootkit检测,规则参考rkhunter
# 1、扫描93类rootkit特征
# 2、检查已知rootkit的内核符号表
# 3、检查已知rootkit内核文件


class Rootkit_Analysis:
    def __init__(self):
        self.name = u'Rootkit类安全检测'
        # 恶意rootkit输出
        self.rootkit = []
        # 集合内核符号表
        self.kallsyms = []
        # 各类rootkit特征，file、dir代表其特征、
        W55808A = {'name': '55808 Variant A', 'file': ['/tmp/.../r', '/tmp/.../a'], 'dir': [], 'ksyms': []}
        Adore_Rootkit = {'name': 'Adore Rootkit',
                         'file': ['/usr/secure', '/usr/doc/sys/qrt', '/usr/doc/sys/run', '/usr/doc/sys/crond',
                                  '/usr/sbin/kfd', '/usr/doc/kern/var',
                                  '/usr/doc/kern/string.o', '/usr/doc/kern/ava', '/usr/doc/kern/adore.o',
                                  '/var/log/ssh/old'],
                         'dir': ['/lib/security/.config/ssh', '/usr/doc/kern', '/usr/doc/backup', '/usr/doc/backup/txt',
                                 '/lib/backup', '/lib/backup/txt', '/usr/doc/work', '/usr/doc/sys', '/var/log/ssh',
                                 '/usr/doc/.spool', '/usr/lib/kterm'], 'ksyms': []}

        AjaKit_Rootkit = {'name': 'AjaKit Rootkit',
                          'file': ['/dev/tux/.addr', '/dev/tux/.proc', '/dev/tux/.file', '/lib/.libgh-gh/cleaner',
                                   '/lib/.libgh-gh/Patch/patch', '/lib/.libgh-gh/sb0k'],
                          'dir': ['/dev/tux', '/lib/.libgh-gh'], 'ksyms': []}

        aPa_Kit_Rootkit = {'name': 'aPa Kit Rootkit', 'file': ['/usr/share/.aPa'], 'dir': [], 'ksyms': []}

        Apache_Worm = {'name': 'Apache Worm', 'file': ['/bin/.log'], 'dir': [], 'ksyms': []}

        Ambient_Rootkit = {'name': 'Ambient Rootkit',
                           'file': ['/usr/lib/.ark?', '/dev/ptyxx/.log', '/dev/ptyxx/.file', '/dev/ptyxx/.proc',
                                    '/dev/ptyxx/.addr'],
                           'dir': ['/dev/ptyxx'], 'ksyms': []}

        Balaur_Rootkit = {'name': 'Balaur Rootkit', 'file': ['/usr/lib/liblog.o'],
                          'dir': ['/usr/lib/.kinetic', '/usr/lib/.egcs', '/usr/lib/.wormie'], 'ksyms': []}

        Beastkit_Rootkit = {'name': 'Beastkit Rootkit',
                            'file': ['/usr/sbin/arobia', '/usr/sbin/idrun', '/usr/lib/elm/arobia/elm',
                                     '/usr/lib/elm/arobia/elm/hk', '/usr/lib/elm/arobia/elm/hk.pub',
                                     '/usr/lib/elm/arobia/elm/sc', '/usr/lib/elm/arobia/elm/sd.pp',
                                     '/usr/lib/elm/arobia/elm/sdco', '/usr/lib/elm/arobia/elm/srsd'],
                            'dir': ['/lib/ldd.so/bktools'], 'ksyms': []}

        beX2_Rootkit = {'name': 'beX2 Rootkit', 'file': ['/usr/info/termcap.info-5.gz', '/usr/bin/sshd2'],
                        'dir': ['/usr/include/bex'], 'ksyms': []}

        BOBkit_Rootkit = {'name': 'BOBkit Rootkit',
                          'file': ['/usr/sbin/ntpsx', '/usr/sbin/.../bkit-ava', '/usr/sbin/.../bkit-d',
                                   '/usr/sbin/.../bkit-shd', '/usr/sbin/.../bkit-f', '/usr/include/.../proc.h',
                                   '/usr/include/.../.bash_history', '/usr/include/.../bkit-get',
                                   '/usr/include/.../bkit-dl', '/usr/include/.../bkit-screen',
                                   '/usr/include/.../bkit-sleep', '/usr/lib/.../bkit-adore.o', '/usr/lib/.../ls',
                                   '/usr/lib/.../netstat', '/usr/lib/.../lsof', '/usr/lib/.../bkit-ssh/bkit-shdcfg',
                                   '/usr/lib/.../bkit-ssh/bkit-shhk', '/usr/lib/.../bkit-ssh/bkit-pw',
                                   '/usr/lib/.../bkit-ssh/bkit-shrs', '/usr/lib/.../bkit-ssh/bkit-mots',
                                   '/usr/lib/.../uconf.inv', '/usr/lib/.../psr', '/usr/lib/.../find',
                                   '/usr/lib/.../pstree', '/usr/lib/.../slocate', '/usr/lib/.../du',
                                   '/usr/lib/.../top'],
                          'dir': ['/usr/sbin/...', '/usr/include/...', '/usr/include/.../.tmp', '/usr/lib/...',
                                  '/usr/lib/.../.ssh', '/usr/lib/.../bkit-ssh', '/usr/lib/.bkit-', '/tmp/.bkp'],
                          'ksyms': []}

        OSX_Boonana_A_Trojan = {'name': 'OSX Boonana-A Trojan',
                                'file': ['/Library/StartupItems/OSXDriverUpdates/OSXDriverUpdates',
                                         '/Library/StartupItems/OSXDriverUpdates/StartupParameters.plist'],
                                'dir': ['/var/root/.jnana'], 'ksyms': []}

        cb_Rootkit = {'name': 'cb Rootkit',
                      'file': ['/dev/srd0', '/lib/libproc.so.2.0.6', '/dev/mounnt', '/etc/rc.d/init.d/init',
                               '/usr/bin/.zeen/..%/cl', '/usr/bin/.zeen/..%/.x.tgz', '/usr/bin/.zeen/..%/statdx',
                               '/usr/bin/.zeen/..%/wted', '/usr/bin/.zeen/..%/write', '/usr/bin/.zeen/..%/scan',
                               '/usr/bin/.zeen/..%/sc', '/usr/bin/.zeen/..%/sl2', '/usr/bin/.zeen/..%/wroot',
                               '/usr/bin/.zeen/..%/wscan', '/usr/bin/.zeen/..%/wu', '/usr/bin/.zeen/..%/v',
                               '/usr/bin/.zeen/..%/read', '/usr/lib/sshrc', '/usr/lib/ssh_host_key',
                               '/usr/lib/ssh_host_key.pub', '/usr/lib/ssh_random_seed', '/usr/lib/sshd_config',
                               '/usr/lib/shosts.equiv', '/usr/lib/ssh_known_hosts', '/u/zappa/.ssh/pid',
                               '/usr/bin/.system/..%/tcp.log', '/usr/bin/.zeen/..%/curatare/attrib',
                               '/usr/bin/.zeen/..%/curatare/chattr', '/usr/bin/.zeen/..%/curatare/ps',
                               '/usr/bin/.zeen/..%/curatare/pstree', '/usr/bin/.system/..%/.x/xC.o'],
                      'dir': ['/usr/bin/.zeen', '/usr/bin/.zeen/..%/curatare', '/usr/bin/.zeen/..%/scan',
                              '/usr/bin/.system/..%'], 'ksyms': []}

        CiNIK_Worm = {'name': 'CiNIK Worm', 'file': ['/tmp/.cinik'], 'dir': ['/tmp/.font-unix/.cinik'], 'ksyms': []}

        CX_Rootkit = {'name': 'CX Rootkit',
                      'file': ['/usr/lib/ldlibso', '/usr/lib/configlibso', '/usr/lib/shklibso', '/usr/lib/randomlibso',
                               '/usr/lib/ldlibstrings.so', '/usr/lib/ldlibdu.so', '/usr/lib/ldlibns.so',
                               '/usr/include/db'],
                      'dir': ['/usr/include/cxk'], 'ksyms': []}

        Abuse_Kit = {'name': 'Abuse Kit', 'file': ['/dev/mdev', '/usr/lib/libX.a'], 'dir': [], 'ksyms': []}

        Devil_Rootkit = {'name': 'Devil Rootkit',
                         'file': ['/var/lib/games/.src', '/dev/dsx', '/dev/caca', '/dev/pro', '/bin/bye',
                                  '/bin/homedir', '/usr/bin/xfss', '/usr/sbin/tzava',
                                  '/usr/doc/tar/.../.dracusor/stuff/holber',
                                  '/usr/doc/tar/.../.dracusor/stuff/sense',
                                  '/usr/doc/tar/.../.dracusor/stuff/clear',
                                  '/usr/doc/tar/.../.dracusor/stuff/tzava',
                                  '/usr/doc/tar/.../.dracusor/stuff/citeste',
                                  '/usr/doc/tar/.../.dracusor/stuff/killrk',
                                  '/usr/doc/tar/.../.dracusor/stuff/searchlog',
                                  '/usr/doc/tar/.../.dracusor/stuff/gaoaza',
                                  '/usr/doc/tar/.../.dracusor/stuff/cleaner',
                                  '/usr/doc/tar/.../.dracusor/stuff/shk',
                                  '/usr/doc/tar/.../.dracusor/stuff/srs',
                                  '/usr/doc/tar/.../.dracusor/utile.tgz',
                                  '/usr/doc/tar/.../.dracusor/webpage', '/usr/doc/tar/.../.dracusor/getpsy',
                                  '/usr/doc/tar/.../.dracusor/getbnc',
                                  '/usr/doc/tar/.../.dracusor/getemech',
                                  '/usr/doc/tar/.../.dracusor/localroot.sh',
                                  '/usr/doc/tar/.../.dracusor/stuff/old/sense'],
                         'dir': ['/usr/doc/tar/.../.dracusor'], 'ksyms': []}

        Diamorphine_LKM = {'name': 'Diamorphine LKM', 'file': [], 'dir': [],
                           'ksyms': ['diamorphine', 'module_hide', 'module_hidden', 'is_invisible', 'hacked_getdents',
                                     'hacked_kill']}

        Dica_Kit_Rootkit = {'name': 'Dica-Kit Rootkit',
                            'file': ['/lib/.sso', '/lib/.so', '/var/run/...dica/clean', '/var/run/...dica/dxr',
                                     '/var/run/...dica/read', '/var/run/...dica/write', '/var/run/...dica/lf',
                                     '/var/run/...dica/xl', '/var/run/...dica/xdr', '/var/run/...dica/psg',
                                     '/var/run/...dica/secure', '/var/run/...dica/rdx', '/var/run/...dica/va',
                                     '/var/run/...dica/cl.sh', '/var/run/...dica/last.log', '/usr/bin/.etc',
                                     '/etc/sshd_config', '/etc/ssh_host_key', '/etc/ssh_random_seed'],
                            'dir': ['/var/run/...dica', '/var/run/...dica/mh', '/var/run/...dica/scan'], 'ksyms': []}

        Dreams_Rootkit = {'name': 'Dreams Rootkit',
                          'file': ['/dev/ttyoa', '/dev/ttyof', '/dev/ttyop', '/usr/bin/sense', '/usr/bin/sl2',
                                   '/usr/bin/logclear', '/usr/bin/(swapd)', '/usr/bin/initrd', '/usr/bin/crontabs',
                                   '/usr/bin/snfs', '/usr/lib/libsss', '/usr/lib/libsnf.log', '/usr/lib/libshtift/top',
                                   '/usr/lib/libshtift/ps', '/usr/lib/libshtift/netstat', '/usr/lib/libshtift/ls',
                                   '/usr/lib/libshtift/ifconfig', '/usr/include/linseed.h', '/usr/include/linpid.h',
                                   '/usr/include/linkey.h', '/usr/include/linconf.h', '/usr/include/iceseed.h',
                                   '/usr/include/icepid.h', '/usr/include/icekey.h', '/usr/include/iceconf.h'],
                          'dir': ['/dev/ida/.hpd', '/usr/lib/libshtift'], 'ksyms': []}

        Duarawkz_Rootkit = {'name': 'Duarawkz Rootkit', 'file': ['/usr/bin/duarawkz/loginpass'],
                            'dir': ['/usr/bin/duarawkz'], 'ksyms': []}

        Ebury_sshd_backdoor = {'name': 'Ebury sshd backdoor',
                               'file': ['/lib/libns2.so', '/lib64/libns2.so', '/lib/libns5.so', '/lib64/libns5.so',
                                        '/lib/libpw3.so', '/lib64/libpw3.so', '/lib/libpw5.so', '/lib64/libpw5.so',
                                        '/lib/libsbr.so', '/lib64/libsbr.so', '/lib/libslr.so', '/lib64/libslr.so',
                                        '/lib/tls/libkeyutils.so.1', '/lib64/tls/libkeyutils.so.1'],
                               'dir': [], 'ksyms': []}

        ENYE_LKM = {'name': 'ENYE LKM', 'file': ['/etc/.enyelkmHIDE^IT.ko', '/etc/.enyelkmOCULTAR.ko'], 'dir': [],
                    'ksyms': []}

        Flea_Rootkit = {'name': 'Flea Rootkit', 'file': ['/etc/ld.so.hash', '/lib/security/.config/ssh/sshd_config',
                                                         '/lib/security/.config/ssh/ssh_host_key',
                                                         '/lib/security/.config/ssh/ssh_host_key.pub',
                                                         '/lib/security/.config/ssh/ssh_random_seed', '/usr/bin/ssh2d',
                                                         '/usr/lib/ldlibns.so', '/usr/lib/ldlibps.so',
                                                         '/usr/lib/ldlibpst.so',
                                                         '/usr/lib/ldlibdu.so', '/usr/lib/ldlibct.so'],
                        'dir': ['/lib/security/.config/ssh', '/dev/..0', '/dev/..0/backup'], 'ksyms': []}

        FreeBSD_Rootkit = {'name': 'FreeBSD Rootkit',
                           'file': ['/dev/ptyp', '/dev/ptyq', '/dev/ptyr', '/dev/ptys', '/dev/ptyt',
                                    '/dev/fd/.88/freshb-bsd', '/dev/fd/.88/fresht', '/dev/fd/.88/zxsniff',
                                    '/dev/fd/.88/zxsniff.log', '/dev/fd/.99/.ttyf00', '/dev/fd/.99/.ttyp00',
                                    '/dev/fd/.99/.ttyq00', '/dev/fd/.99/.ttys00', '/dev/fd/.99/.pwsx00', '/etc/.acid',
                                    '/usr/lib/.fx/sched_host.2', '/usr/lib/.fx/random_d.2', '/usr/lib/.fx/set_pid.2',
                                    '/usr/lib/.fx/setrgrp.2', '/usr/lib/.fx/TOHIDE', '/usr/lib/.fx/cons.saver',
                                    '/usr/lib/.fx/adore/ava/ava', '/usr/lib/.fx/adore/adore/adore.ko', '/bin/sysback',
                                    '/usr/local/bin/sysback'],
                           'dir': ['/dev/fd/.88', '/dev/fd/.99', '/usr/lib/.fx', '/usr/lib/.fx/adore'], 'ksyms': []}

        Fu_Rootkit = {'name': 'Fu Rootkit', 'file': ['/sbin/xc', '/usr/include/ivtype.h', '/bin/.lib'], 'dir': [],
                      'ksyms': []}

        Fuckit_Rootkit = {'name': 'Fuckit Rootkit',
                          'file': ['/lib/libproc.so.2.0.7', '/dev/proc/.bash_profile', '/dev/proc/.bashrc',
                                   '/dev/proc/.cshrc', '/dev/proc/fuckit/hax0r', '/dev/proc/fuckit/hax0rshell',
                                   '/dev/proc/fuckit/config/lports', '/dev/proc/fuckit/config/rports',
                                   '/dev/proc/fuckit/config/rkconf', '/dev/proc/fuckit/config/password',
                                   '/dev/proc/fuckit/config/progs', '/dev/proc/fuckit/system-bins/init',
                                   '/usr/lib/libcps.a', '/usr/lib/libtty.a'],
                          'dir': ['/dev/proc', '/dev/proc/fuckit', '/dev/proc/fuckit/system-bins', '/dev/proc/toolz'],
                          'ksyms': []}

        GasKit_Rootkit = {'name': 'GasKit Rootkit', 'file': ['/dev/dev/gaskit/sshd/sshdd'],
                          'dir': ['/dev/dev', '/dev/dev/gaskit', '/dev/dev/gaskit/sshd'], 'ksyms': []}

        Heroin_LKM = {'name': 'Heroin LKM', 'file': [], 'dir': [], 'ksyms': ['heroin']}

        HjC_Kit_Rootkit = {'name': 'HjC Kit Rootkit', 'file': [], 'dir': ['/dev/.hijackerz'], 'ksyms': []}

        ignoKit_Rootkit = {'name': 'ignoKit Rootkit',
                           'file': ['/lib/defs/p', '/lib/defs/q', '/lib/defs/r', '/lib/defs/s', '/lib/defs/t',
                                    '/usr/lib/defs/p', '/usr/lib/defs/q', '/usr/lib/defs/r', '/usr/lib/defs/s',
                                    '/usr/lib/defs/t', '/usr/lib/.libigno/pkunsec',
                                    '/usr/lib/.libigno/.igno/psybnc/psybnc'],
                           'dir': ['/usr/lib/.libigno', '/usr/lib/.libigno/.igno'], 'ksyms': []}

        iLLogiC_Rootkit = {'name': 'iLLogiC Rootkit',
                           'file': ['/dev/kmod', '/dev/dos', '/usr/lib/crth.o', '/usr/lib/crtz.o', '/etc/ld.so.hash',
                                    '/usr/bin/sia', '/usr/bin/ssh2d', '/lib/security/.config/sn',
                                    '/lib/security/.config/iver', '/lib/security/.config/uconf.inv',
                                    '/lib/security/.config/ssh/ssh_host_key',
                                    '/lib/security/.config/ssh/ssh_host_key.pub', '/lib/security/.config/ssh/sshport',
                                    '/lib/security/.config/ssh/ssh_random_seed', '/lib/security/.config/ava',
                                    '/lib/security/.config/cleaner', '/lib/security/.config/lpsched',
                                    '/lib/security/.config/sz', '/lib/security/.config/rcp',
                                    '/lib/security/.config/patcher', '/lib/security/.config/pg',
                                    '/lib/security/.config/crypt', '/lib/security/.config/utime',
                                    '/lib/security/.config/wget', '/lib/security/.config/instmod',
                                    '/lib/security/.config/bin/find', '/lib/security/.config/bin/du',
                                    '/lib/security/.config/bin/ls', '/lib/security/.config/bin/psr',
                                    '/lib/security/.config/bin/netstat', '/lib/security/.config/bin/su',
                                    '/lib/security/.config/bin/ping', '/lib/security/.config/bin/passwd'],
                           'dir': ['/lib/security/.config', '/lib/security/.config/ssh', '/lib/security/.config/bin',
                                   '/lib/security/.config/backup', '/root/%%%/.dir', '/root/%%%/.dir/mass-scan',
                                   '/root/%%%/.dir/flood'], 'ksyms': []}

        OSX_Inqtana = {'name': 'OSX Inqtana Variant A',
                       'file': ['/Users/w0rm-support.tgz', '/Users/InqTest.class', '/Users/com.openbundle.plist',
                                '/Users/com.pwned.plist', '/Users/libavetanaBT.jnilib'],
                       'dir': ['/Users/de', '/Users/javax'], 'ksyms': []}

        OSX_Inqtana2 = {'name': 'OSX Inqtana Variant B',
                        'file': ['/Users/w0rms.love.apples.tgz', '/Users/InqTest.class', '/Users/InqTest.java',
                                 '/Users/libavetanaBT.jnilib', '/Users/InqTanaHandler', '/Users/InqTanaHandler.bundle'],
                        'dir': ['/Users/de', '/Users/javax'], 'ksyms': []}

        OSX_Inqtana3 = {'name': 'OSX Inqtana Variant C',
                        'file': ['/Users/applec0re.tgz', '/Users/InqTest.class', '/Users/InqTest.java',
                                 '/Users/libavetanaBT.jnilib', '/Users/environment.plist', '/Users/pwned.c',
                                 '/Users/pwned.dylib'],
                        'dir': ['/Users/de', '/Users/javax'], 'ksyms': []}

        IntoXonia_NG_Rootkit = {'name': 'IntoXonia-NG Rootkit', 'file': [], 'dir': [],
                                'ksyms': ['funces', 'ixinit', 'tricks', 'kernel_unlink', 'rootme', 'hide_module',
                                          'find_sys_call_tbl']}

        Irix_Rootkit = {'name': 'Irix Rootkit', 'file': [],
                        'dir': ['/dev/pts/01', '/dev/pts/01/backup', '/dev/pts/01/etc', '/dev/pts/01/tmp'], 'ksyms': []}

        Jynx_Rootkit = {'name': 'Jynx Rootkit',
                        'file': ['/xochikit/bc', '/xochikit/ld_poison.so', '/omgxochi/bc', '/omgxochi/ld_poison.so',
                                 '/var/local/^^/bc', '/var/local/^^/ld_poison.so'],
                        'dir': ['/xochikit', '/omgxochi', '/var/local/^^'], 'ksyms': []}

        Jynx2_Rootkit = {'name': 'Jynx2 Rootkit', 'file': ['/XxJynx/reality.so'], 'dir': ['/XxJynx'], 'ksyms': []}

        KBeast_Rootkit = {'name': 'KBeast Rootkit',
                          'file': ['/usr/_h4x_/ipsecs-kbeast-v1.ko', '/usr/_h4x_/_h4x_bd', '/usr/_h4x_/acctlog'],
                          'dir': ['/usr/_h4x_'],
                          'ksyms': ['h4x_delete_module', 'h4x_getdents64', 'h4x_kill', 'h4x_open', 'h4x_read',
                                    'h4x_rename', 'h4x_rmdir', 'h4x_tcp4_seq_show', 'h4x_write']}

        OSX_Keydnap_backdoor = {'name': 'OSX Keydnap backdoor',
                                'file': ['/Applications/Transmission.app/Contents/Resources/License.rtf',
                                         '/Volumes/Transmission/Transmission.app/Contents/Resources/License.rtf',
                                         '/Library/LaunchAgents/com.apple.iCloud.sync.daemon.plist',
                                         '/Library/LaunchAgents/com.geticloud.icloud.photo.plist'],
                                'dir': ['/Library/Application%Support/com.apple.iCloud.sync.daemon/'], 'ksyms': []}

        Kitko_Rootkit = {'name': 'Kitko Rootkit', 'file': [], 'dir': ['/usr/src/redhat/SRPMS/...'], 'ksyms': []}

        KNARK_FILES = {'name': 'Knark Rootkit', 'file': ['/proc/knark/pids'], 'dir': ['/proc/knark'], 'ksyms': []}

        KOMPLEX_FILES = {'name': 'OSX Komplex Trojan',
                         'file': ['/Users/Shared/.local/kextd', '/Users/Shared/com.apple.updates.plist',
                                  '/Users/Shared/start.sh'], 'dir': [], 'ksyms': []}

        LINUXV_FILES = {'name': 'ld-linuxv rootkit', 'file': ['/lib/ld-linuxv.so.1'],
                        'dir': ['/var/opt/_so_cache', '/var/opt/_so_cache/ld', '/var/opt/_so_cache/lc'], 'ksyms': []}

        LION_FILES = {'name': 'Lion Worm', 'file': ['/bin/in.telnetd', '/bin/mjy', '/usr/man/man1/man1/lib/.lib/mjy',
                                                    '/usr/man/man1/man1/lib/.lib/in.telnetd',
                                                    '/usr/man/man1/man1/lib/.lib/.x', '/dev/.lib/lib/scan/1i0n.sh',
                                                    '/dev/.lib/lib/scan/hack.sh', '/dev/.lib/lib/scan/bind',
                                                    '/dev/.lib/lib/scan/randb', '/dev/.lib/lib/scan/scan.sh',
                                                    '/dev/.lib/lib/scan/pscan', '/dev/.lib/lib/scan/star.sh',
                                                    '/dev/.lib/lib/scan/bindx.sh', '/dev/.lib/lib/scan/bindname.log',
                                                    '/dev/.lib/lib/1i0n.sh', '/dev/.lib/lib/lib/netstat',
                                                    '/dev/.lib/lib/lib/dev/.1addr', '/dev/.lib/lib/lib/dev/.1logz',
                                                    '/dev/.lib/lib/lib/dev/.1proc', '/dev/.lib/lib/lib/dev/.1file'],
                      'dir': [], 'ksyms': []}

        LOCKIT_FILES = {'name': 'Lockit Rootkit',
                        'file': ['/usr/lib/libmen.oo/.LJK2/ssh_config', '/usr/lib/libmen.oo/.LJK2/ssh_host_key',
                                 '/usr/lib/libmen.oo/.LJK2/ssh_host_key.pub',
                                 '/usr/lib/libmen.oo/.LJK2/ssh_random_seed*', '/usr/lib/libmen.oo/.LJK2/sshd_config',
                                 '/usr/lib/libmen.oo/.LJK2/backdoor/RK1bd', '/usr/lib/libmen.oo/.LJK2/backup/du',
                                 '/usr/lib/libmen.oo/.LJK2/backup/ifconfig',
                                 '/usr/lib/libmen.oo/.LJK2/backup/inetd.conf', '/usr/lib/libmen.oo/.LJK2/backup/locate',
                                 '/usr/lib/libmen.oo/.LJK2/backup/login', '/usr/lib/libmen.oo/.LJK2/backup/ls',
                                 '/usr/lib/libmen.oo/.LJK2/backup/netstat', '/usr/lib/libmen.oo/.LJK2/backup/ps',
                                 '/usr/lib/libmen.oo/.LJK2/backup/pstree', '/usr/lib/libmen.oo/.LJK2/backup/rc.sysinit',
                                 '/usr/lib/libmen.oo/.LJK2/backup/syslogd', '/usr/lib/libmen.oo/.LJK2/backup/tcpd',
                                 '/usr/lib/libmen.oo/.LJK2/backup/top', '/usr/lib/libmen.oo/.LJK2/clean/RK1sauber',
                                 '/usr/lib/libmen.oo/.LJK2/clean/RK1wted', '/usr/lib/libmen.oo/.LJK2/hack/RK1parse',
                                 '/usr/lib/libmen.oo/.LJK2/hack/RK1sniff', '/usr/lib/libmen.oo/.LJK2/hide/.RK1addr',
                                 '/usr/lib/libmen.oo/.LJK2/hide/.RK1dir', '/usr/lib/libmen.oo/.LJK2/hide/.RK1log',
                                 '/usr/lib/libmen.oo/.LJK2/hide/.RK1proc',
                                 '/usr/lib/libmen.oo/.LJK2/hide/RK1phidemod.c',
                                 '/usr/lib/libmen.oo/.LJK2/modules/README.modules',
                                 '/usr/lib/libmen.oo/.LJK2/modules/RK1hidem.c',
                                 '/usr/lib/libmen.oo/.LJK2/modules/RK1phide',
                                 '/usr/lib/libmen.oo/.LJK2/sshconfig/RK1ssh'],
                        'dir': ['/usr/lib/libmen.oo/.LJK2'], 'ksyms': []}

        MOKES_FILES = {'name': 'Mokes backdoor', 'file': [
            '/tmp/ss0-[0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9].sst',
            '/tmp/aa0-[0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9].aat',
            '/tmp/kk0-[0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9].kkt',
            '/tmp/dd0-[0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9].ddt'],
                       'dir': [], 'ksyms': []}

        MRK_FILES = {'name': 'MRK RootKit',
                     'file': ['/dev/ida/.inet/pid', '/dev/ida/.inet/ssh_host_key', '/dev/ida/.inet/ssh_random_seed',
                              '/dev/ida/.inet/tcp.log'], 'dir': ['/dev/ida/.inet', '/var/spool/cron/.sh'], 'ksyms': []}

        MOODNT_FILES = {'name': 'Mood-NT Rootkit',
                        'file': ['/sbin/init__mood-nt-_-_cthulhu', '/_cthulhu/mood-nt.init', '/_cthulhu/mood-nt.conf',
                                 '/_cthulhu/mood-nt.sniff'], 'dir': ['/_cthulhu'], 'ksyms': []}

        NIO_FILES = {'name': 'Ni0 Rootkit',
                     'file': ['/var/lock/subsys/...datafile.../...net...', '/var/lock/subsys/...datafile.../...port...',
                              '/var/lock/subsys/...datafile.../...ps...', '/var/lock/subsys/...datafile.../...file...'],
                     'dir': ['/tmp/waza', '/var/lock/subsys/...datafile...', '/usr/sbin/es'], 'ksyms': []}

        OHHARA_FILES = {'name': 'Ohhara Rootkit',
                        'file': ['/var/lock/subsys/...datafile.../...datafile.../in.smbd.log'],
                        'dir': ['/var/lock/subsys/...datafile...', '/var/lock/subsys/...datafile.../...datafile...',
                                '/var/lock/subsys/...datafile.../...datafile.../bin',
                                '/var/lock/subsys/...datafile.../...datafile.../usr/bin',
                                '/var/lock/subsys/...datafile.../...datafile.../usr/sbin',
                                '/var/lock/subsys/...datafile.../...datafile.../lib/security'], 'ksyms': []}

        OPTICKIT_FILES = {'name': 'Optic Kit Rootkit', 'file': [],
                          'dir': ['/dev/tux', '/usr/bin/xchk', '/usr/bin/xsf', '/usr/bin/ssh2d'], 'ksyms': []}

        OSXRK_FILES = {'name': 'OSXRK',
                       'file': ['/dev/.rk/nc', '/dev/.rk/diepu', '/dev/.rk/backd', '/Library/StartupItems/opener',
                                '/Library/StartupItems/opener.sh', '/System/Library/StartupItems/opener',
                                '/System/Library/StartupItems/opener.sh'],
                       'dir': ['/dev/.rk', '/Users/LDAP-daemon', '/tmp/.work'], 'ksyms': []}

        OZ_FILES = {'name': 'Oz Rootkit', 'file': ['/dev/.oz/.nap/rkit/terror'], 'dir': ['/dev/.oz'], 'ksyms': []}

        PHALANX_FILES = {'name': 'Phalanx Rootkit',
                         'file': ['/uNFuNF', '/etc/host.ph1', '/bin/host.ph1', '/usr/share/.home.ph1/phalanx',
                                  '/usr/share/.home.ph1/cb', '/usr/share/.home.ph1/kebab'],
                         'dir': ['/usr/share/.home.ph1', '/usr/share/.home.ph1/tty'], 'ksyms': []}

        PHALANX2_FILES = {'name': 'Phalanx2 Rootkit',
                          'file': ['/etc/khubd.p2/.p2rc', '/etc/khubd.p2/.phalanx2', '/etc/khubd.p2/.sniff',
                                   '/etc/khubd.p2/sshgrab.py', '/etc/lolzz.p2/.p2rc', '/etc/lolzz.p2/.phalanx2',
                                   '/etc/lolzz.p2/.sniff', '/etc/lolzz.p2/sshgrab.py', '/etc/cron.d/zupzzplaceholder',
                                   '/usr/lib/zupzz.p2/.p-2.3d', '/usr/lib/zupzz.p2/.p2rc'],
                          'dir': ['/etc/khubd.p2', '/etc/lolzz.p2', '/usr/lib/zupzz.p2'], 'ksyms': []}

        PORTACELO_FILES = {'name': 'Portacelo Rootkit',
                           'file': ['/var/lib/.../.ak', '/var/lib/.../.hk', '/var/lib/.../.rs', '/var/lib/.../.p',
                                    '/var/lib/.../getty', '/var/lib/.../lkt.o', '/var/lib/.../show',
                                    '/var/lib/.../nlkt.o', '/var/lib/.../ssshrc', '/var/lib/.../sssh_equiv',
                                    '/var/lib/.../sssh_known_hosts', '/var/lib/.../sssh_pid ~/.sssh/known_hosts'],
                           'dir': [], 'ksyms': []}

        PROTON_FILES = {'name': 'OSX Proton backdoor', 'file': ['Library/LaunchAgents/com.apple.xpcd.plist',
                                                                '/Library/LaunchAgents/com.Eltima.UpdaterAgent.plist',
                                                                '/Library/.rand/updateragent.app', '/tmp/Updater.app'],
                        'dir': ['/Library/.rand', '/Library/.cachedir', '/Library/.random'], 'ksyms': []}

        REDSTORM_FILES = {'name': 'R3dstorm Toolkit',
                          'file': ['/var/log/tk02/see_all', '/var/log/tk02/.scris', '/bin/.../sshd/sbin/sshd1',
                                   '/bin/.../hate/sk', '/bin/.../see_all'],
                          'dir': ['/var/log/tk02', '/var/log/tk02/old', '/bin/...'], 'ksyms': []}

        RHSHARPES_FILES = {'name': 'RH-Sharpe Rootkit',
                           'file': ['/bin/lps', '/usr/bin/lpstree', '/usr/bin/ltop', '/usr/bin/lkillall',
                                    '/usr/bin/ldu', '/usr/bin/lnetstat', '/usr/bin/wp', '/usr/bin/shad',
                                    '/usr/bin/vadim', '/usr/bin/slice', '/usr/bin/cleaner', '/usr/include/rpcsvc/du'],
                           'dir': [], 'ksyms': []}

        RSHA_FILES = {'name': 'RSHA Rootkit',
                      'file': ['/bin/kr4p', '/usr/bin/n3tstat', '/usr/bin/chsh2', '/usr/bin/slice2',
                               '/usr/src/linux/arch/alpha/lib/.lib/.1proc', '/etc/rc.d/arch/alpha/lib/.lib/.1addr'],
                      'dir': ['/etc/rc.d/rsha', '/etc/rc.d/arch/alpha/lib/.lib'], 'ksyms': []}

        SHUTDOWN_FILES = {'name': 'Shutdown Rootkit',
                          'file': ['/usr/man/man5/..%/.dir/scannah/asus', '/usr/man/man5/..%/.dir/see',
                                   '/usr/man/man5/..%/.dir/nscd', '/usr/man/man5/..%/.dir/alpd', '/etc/rc.d/rc.local%'],
                          'dir': ['/usr/man/man5/..%/.dir', '/usr/man/man5/..%/.dir/scannah',
                                  '/etc/rc.d/rc0.d/..%/.dir'], 'ksyms': []}

        SCALPER_FILES = {'name': 'Scalper Worm', 'file': ['/tmp/.a', '/tmp/.uua'], 'dir': [], 'ksyms': []}

        SHV4_FILES = {'name': 'SHV4 Rootkit',
                      'file': ['/etc/ld.so.hash', '/lib/libext-2.so.7', '/lib/lidps1.so', '/lib/libproc.a',
                               '/lib/libproc.so.2.0.6', '/lib/ldd.so/tks', '/lib/ldd.so/tkp', '/lib/ldd.so/tksb',
                               '/lib/security/.config/sshd', '/lib/security/.config/ssh/ssh_host_key',
                               '/lib/security/.config/ssh/ssh_host_key.pub',
                               '/lib/security/.config/ssh/ssh_random_seed', '/usr/include/file.h',
                               '/usr/include/hosts.h', '/usr/include/lidps1.so', '/usr/include/log.h',
                               '/usr/include/proc.h', '/usr/sbin/xntps', '/dev/srd0'],
                      'dir': ['/lib/ldd.so', '/lib/security/.config', '/lib/security/.config/ssh'], 'ksyms': []}

        SHV5_FILES = {'name': 'SHV5 Rootkit',
                      'file': ['/etc/sh.conf', '/lib/libproc.a', '/lib/libproc.so.2.0.6', '/lib/lidps1.so',
                               '/lib/libsh.so/bash', '/usr/include/file.h', '/usr/include/hosts.h',
                               '/usr/include/log.h', '/usr/include/proc.h', '/lib/libsh.so/shdcf2',
                               '/lib/libsh.so/shhk', '/lib/libsh.so/shhk.pub', '/lib/libsh.so/shrs',
                               '/usr/lib/libsh/.bashrc', '/usr/lib/libsh/shsb', '/usr/lib/libsh/hide',
                               '/usr/lib/libsh/.sniff/shsniff', '/usr/lib/libsh/.sniff/shp', '/dev/srd0'],
                      'dir': ['/lib/libsh.so', '/usr/lib/libsh', '/usr/lib/libsh/utilz', '/usr/lib/libsh/.backup'],
                      'ksyms': []}

        SINROOTKIT_FILES = {'name': 'Sin Rootkit',
                            'file': ['/dev/.haos/haos1/.f/Denyed', '/dev/ttyoa', '/dev/ttyof', '/dev/ttyop',
                                     '/dev/ttyos', '/usr/lib/.lib', '/usr/lib/sn/.X', '/usr/lib/sn/.sys',
                                     '/usr/lib/ld/.X', '/usr/man/man1/...', '/usr/man/man1/.../.m',
                                     '/usr/man/man1/.../.w'],
                            'dir': ['/usr/lib/sn', '/usr/lib/man1/...', '/dev/.haos'], 'ksyms': []}

        SLAPPER_FILES = {'name': 'Slapper Worm',
                         'file': ['/tmp/.bugtraq', '/tmp/.uubugtraq', '/tmp/.bugtraq.c', '/tmp/httpd', '/tmp/.unlock',
                                  '/tmp/update', '/tmp/.cinik', '/tmp/.b'], 'dir': [], 'ksyms': []}

        SNEAKIN_FILES = {'name': 'Sneakin Rootkit', 'file': [], 'dir': ['/tmp/.X11-unix/.../rk'], 'ksyms': []}

        WANUKDOOR_FILES = {'name': 'Solaris Wanuk backdoor',
                           'file': ['/var/adm/sa/.adm/.lp-door.i86pc', '/var/adm/sa/.adm/.lp-door.sun4',
                                    '/var/spool/lp/admins/.lp-door.i86pc', '/var/spool/lp/admins/.lp-door.sun4',
                                    '/var/spool/lp/admins/lpshut', '/var/spool/lp/admins/lpsystem',
                                    '/var/spool/lp/admins/lpadmin', '/var/spool/lp/admins/lpmove',
                                    '/var/spool/lp/admins/lpusers', '/var/spool/lp/admins/lpfilter',
                                    '/var/spool/lp/admins/lpstat', '/var/spool/lp/admins/lpd',
                                    '/var/spool/lp/admins/lpsched', '/var/spool/lp/admins/lpc'],
                           'dir': ['/var/adm/sa/.adm'], 'ksyms': []}

        WANUKWORM_FILES = {'name': 'Solaris Wanuk Worm',
                           'file': ['/var/adm/.adm', '/var/adm/.i86pc', '/var/adm/.sun4', '/var/adm/sa/.adm',
                                    '/var/adm/sa/.adm/.i86pc', '/var/adm/sa/.adm/.sun4', '/var/adm/sa/.adm/.crontab',
                                    '/var/adm/sa/.adm/devfsadmd', '/var/adm/sa/.adm/svcadm', '/var/adm/sa/.adm/cfgadm',
                                    '/var/adm/sa/.adm/kadmind', '/var/adm/sa/.adm/zoneadmd', '/var/adm/sa/.adm/sadm',
                                    '/var/adm/sa/.adm/sysadm', '/var/adm/sa/.adm/dladm', '/var/adm/sa/.adm/bootadm',
                                    '/var/adm/sa/.adm/routeadm', '/var/adm/sa/.adm/uadmin', '/var/adm/sa/.adm/acctadm',
                                    '/var/adm/sa/.adm/cryptoadm', '/var/adm/sa/.adm/inetadm', '/var/adm/sa/.adm/logadm',
                                    '/var/adm/sa/.adm/nlsadmin', '/var/adm/sa/.adm/sacadm',
                                    '/var/adm/sa/.adm/syseventadmd', '/var/adm/sa/.adm/ttyadmd',
                                    '/var/adm/sa/.adm/consadmd', '/var/adm/sa/.adm/metadevadm', '/var/adm/sa/.i86pc',
                                    '/var/adm/sa/.sun4', '/var/adm/sa/acctadm', '/var/adm/sa/bootadm',
                                    '/var/adm/sa/cfgadm', '/var/adm/sa/consadmd', '/var/adm/sa/cryptoadm',
                                    '/var/adm/sa/devfsadmd', '/var/adm/sa/dladm', '/var/adm/sa/inetadm',
                                    '/var/adm/sa/kadmind', '/var/adm/sa/logadm', '/var/adm/sa/metadevadm',
                                    '/var/adm/sa/nlsadmin', '/var/adm/sa/routeadm', '/var/adm/sa/sacadm',
                                    '/var/adm/sa/sadm', '/var/adm/sa/svcadm', '/var/adm/sa/sysadm',
                                    '/var/adm/sa/syseventadmd', '/var/adm/sa/ttyadmd', '/var/adm/sa/uadmin',
                                    '/var/adm/sa/zoneadmd', '/var/spool/lp/admins/.lp/.crontab',
                                    '/var/spool/lp/admins/.lp/lpshut', '/var/spool/lp/admins/.lp/lpsystem',
                                    '/var/spool/lp/admins/.lp/lpadmin', '/var/spool/lp/admins/.lp/lpmove',
                                    '/var/spool/lp/admins/.lp/lpusers', '/var/spool/lp/admins/.lp/lpfilter',
                                    '/var/spool/lp/admins/.lp/lpstat', '/var/spool/lp/admins/.lp/lpd',
                                    '/var/spool/lp/admins/.lp/lpsched', '/var/spool/lp/admins/.lp/lpc'],
                           'dir': ['/var/adm/sa/.adm', '/var/spool/lp/admins/.lp'], 'ksyms': []}

        SPANISH_FILES = {'name': 'Spanish Rootkit',
                         'file': ['/dev/ptyq', '/bin/ad', '/bin/ava', '/bin/server', '/usr/sbin/rescue',
                                  '/usr/share/.../chrps', '/usr/share/.../chrifconfig', '/usr/share/.../netstat',
                                  '/usr/share/.../linsniffer', '/usr/share/.../charbd', '/usr/share/.../charbd2',
                                  '/usr/share/.../charbd3', '/usr/share/.../charbd4', '/usr/man/tmp/update.tgz',
                                  '/var/lib/rpm/db.rpm', '/var/cache/man/.cat', '/var/spool/lpd/remote/.lpq'],
                         'dir': ['/usr/share/...'], 'ksyms': []}

        SUCKIT_FILES = {'name': 'Suckit Rootkit',
                        'file': ['/sbin/initsk12', '/sbin/initxrk', '/usr/bin/null', '/usr/share/locale/sk/.sk12/sk',
                                 '/etc/rc.d/rc0.d/S23kmdac', '/etc/rc.d/rc1.d/S23kmdac', '/etc/rc.d/rc2.d/S23kmdac',
                                 '/etc/rc.d/rc3.d/S23kmdac', '/etc/rc.d/rc4.d/S23kmdac', '/etc/rc.d/rc5.d/S23kmdac',
                                 '/etc/rc.d/rc6.d/S23kmdac'],
                        'dir': ['/dev/sdhu0/tehdrakg', '/etc/.MG', '/usr/share/locale/sk/.sk12',
                                '/usr/lib/perl5/site_perl/i386-linux/auto/TimeDate/.packlist'], 'ksyms': []}

        NSDAP_FILES = {'name': 'NSDAP Rootkit',
                       'file': ['/dev/pts/01/55su', '/dev/pts/01/55ps', '/dev/pts/01/55ping', '/dev/pts/01/55login',
                                '/dev/pts/01/PATCHER_COMPLETED', '/dev/prom/sn.l', '/dev/prom/dos',
                                '/usr/lib/vold/nsdap/.kit', '/usr/lib/vold/nsdap/defines',
                                '/usr/lib/vold/nsdap/patcher', '/usr/lib/vold/nsdap/pg', '/usr/lib/vold/nsdap/cleaner',
                                '/usr/lib/vold/nsdap/utime', '/usr/lib/vold/nsdap/crypt', '/usr/lib/vold/nsdap/findkit',
                                '/usr/lib/vold/nsdap/sn2', '/usr/lib/vold/nsdap/sniffload',
                                '/usr/lib/vold/nsdap/runsniff', '/usr/lib/lpset', '/usr/lib/lpstart',
                                '/usr/bin/mc68000', '/usr/bin/mc68010', '/usr/bin/mc68020', '/usr/ucb/bin/ps',
                                '/usr/bin/m68k', '/usr/bin/sun2', '/usr/bin/mc68030', '/usr/bin/mc68040',
                                '/usr/bin/sun3', '/usr/bin/sun3x', '/usr/bin/lso', '/usr/bin/u370'],
                       'dir': ['/dev/pts/01', '/dev/prom', '/usr/lib/vold/nsdap', '/.pat'], 'ksyms': []}

        SUNOSROOTKIT_FILES = {'name': 'SunOS Rootkit',
                              'file': ['/etc/ld.so.hash', '/lib/libext-2.so.7', '/usr/bin/ssh2d', '/bin/xlogin',
                                       '/usr/lib/crth.o', '/usr/lib/crtz.o', '/sbin/login', '/lib/security/.config/sn',
                                       '/lib/security/.config/lpsched', '/dev/kmod', '/dev/dos'],
                              'dir': [], 'ksyms': []}

        SUPERKIT_FILES = {'name': 'Superkit Rootkit',
                          'file': ['/usr/man/.sman/sk/backsh', '/usr/man/.sman/sk/izbtrag', '/usr/man/.sman/sk/sksniff',
                                   '/var/www/cgi-bin/cgiback.cgi'], 'dir': ['/usr/man/.sman/sk'], 'ksyms': []}

        TBD_FILES = {'name': 'TBD(Telnet Backdoor)', 'file': ['/usr/lib/.tbd'], 'dir': [], 'ksyms': []}

        TELEKIT_FILES = {'name': 'TeLeKiT Rootkit',
                         'file': ['/usr/man/man3/.../TeLeKiT/bin/sniff', '/usr/man/man3/.../TeLeKiT/bin/telnetd',
                                  '/usr/man/man3/.../TeLeKiT/bin/teleulo', '/usr/man/man3/.../cl', '/dev/ptyr',
                                  '/dev/ptyp', '/dev/ptyq', '/dev/hda06', '/usr/info/libc1.so'],
                         'dir': ['/usr/man/man3/...', '/usr/man/man3/.../lsniff', '/usr/man/man3/.../TeLeKiT'],
                         'ksyms': []}

        TOGROOT_FILES = {'name': 'OSX Togroot Rootkit',
                         'file': ['/System/Library/Extensions/Togroot.kext/Contents/Info.plist',
                                  '/System/Library/Extensions/Togroot.kext/Contents/pbdevelopment.plist',
                                  '/System/Library/Extensions/Togroot.kext/Contents/MacOS/togrootkext'],
                         'dir': ['/System/Library/Extensions/Togroot.kext',
                                 '/System/Library/Extensions/Togroot.kext/Contents',
                                 '/System/Library/Extensions/Togroot.kext/Contents/MacOS'], 'ksyms': []}

        TORN_FILES = {'name': 'T0rn Rootkit',
                      'file': ['/dev/.lib/lib/lib/t0rns', '/dev/.lib/lib/lib/du', '/dev/.lib/lib/lib/ls',
                               '/dev/.lib/lib/lib/t0rnsb', '/dev/.lib/lib/lib/ps', '/dev/.lib/lib/lib/t0rnp',
                               '/dev/.lib/lib/lib/find', '/dev/.lib/lib/lib/ifconfig', '/dev/.lib/lib/lib/pg',
                               '/dev/.lib/lib/lib/ssh.tgz', '/dev/.lib/lib/lib/top', '/dev/.lib/lib/lib/sz',
                               '/dev/.lib/lib/lib/login', '/dev/.lib/lib/lib/in.fingerd', '/dev/.lib/lib/lib/1i0n.sh',
                               '/dev/.lib/lib/lib/pstree', '/dev/.lib/lib/lib/in.telnetd', '/dev/.lib/lib/lib/mjy',
                               '/dev/.lib/lib/lib/sush', '/dev/.lib/lib/lib/tfn', '/dev/.lib/lib/lib/name',
                               '/dev/.lib/lib/lib/getip.sh', '/usr/info/.torn/sh*', '/usr/src/.puta/.1addr',
                               '/usr/src/.puta/.1file', '/usr/src/.puta/.1proc', '/usr/src/.puta/.1logz',
                               '/usr/info/.t0rn'],
                      'dir': ['/dev/.lib', '/dev/.lib/lib', '/dev/.lib/lib/lib', '/dev/.lib/lib/lib/dev',
                              '/dev/.lib/lib/scan', '/usr/src/.puta', '/usr/man/man1/man1', '/usr/man/man1/man1/lib',
                              '/usr/man/man1/man1/lib/.lib', '/usr/man/man1/man1/lib/.lib/.backup'],
                      'ksyms': []}

        TRNKIT_FILES = {'name': 'trNkit Rootkit',
                        'file': ['/usr/lib/libbins.la', '/usr/lib/libtcs.so', '/dev/.ttpy/ulogin.sh',
                                 '/dev/.ttpy/tcpshell.sh', '/dev/.ttpy/bupdu', '/dev/.ttpy/buloc', '/dev/.ttpy/buloc1',
                                 '/dev/.ttpy/buloc2', '/dev/.ttpy/stat', '/dev/.ttpy/backps', '/dev/.ttpy/tree',
                                 '/dev/.ttpy/topk', '/dev/.ttpy/wold', '/dev/.ttpy/whoold', '/dev/.ttpy/backdoors'],
                        'dir': [], 'ksyms': []}

        TROJANIT_FILES = {'name': 'Trojanit Kit Rootkit',
                          'file': ['bin/.ls', '/bin/.ps', '/bin/.netstat', '/usr/bin/.nop', '/usr/bin/.who'], 'dir': [],
                          'ksyms': []}

        TURTLE_FILES = {'name': 'Turtle Rootkit', 'file': ['/dev/turtle2dev'], 'dir': [], 'ksyms': []}

        TUXTENDO_FILES = {'name': 'Tuxtendo Rootkit',
                          'file': ['/lib/libproc.so.2.0.7', '/usr/bin/xchk', '/usr/bin/xsf', '/dev/tux/suidsh',
                                   '/dev/tux/.addr', '/dev/tux/.cron', '/dev/tux/.file', '/dev/tux/.log',
                                   '/dev/tux/.proc', '/dev/tux/.iface', '/dev/tux/.pw', '/dev/tux/.df', '/dev/tux/.ssh',
                                   '/dev/tux/.tux', '/dev/tux/ssh2/sshd2_config', '/dev/tux/ssh2/hostkey',
                                   '/dev/tux/ssh2/hostkey.pub', '/dev/tux/ssh2/logo', '/dev/tux/ssh2/random_seed',
                                   '/dev/tux/backup/crontab', '/dev/tux/backup/df', '/dev/tux/backup/dir',
                                   '/dev/tux/backup/find', '/dev/tux/backup/ifconfig', '/dev/tux/backup/locate',
                                   '/dev/tux/backup/netstat', '/dev/tux/backup/ps', '/dev/tux/backup/pstree',
                                   '/dev/tux/backup/syslogd', '/dev/tux/backup/tcpd', '/dev/tux/backup/top',
                                   '/dev/tux/backup/updatedb', '/dev/tux/backup/vdir'],
                          'dir': ['/dev/tux', '/dev/tux/ssh2', '/dev/tux/backup'], 'ksyms': []}

        URK_FILES = {'name': 'Universal Rootkit',
                     'file': ['/dev/prom/sn.l', '/usr/lib/ldlibps.so', '/usr/lib/ldlibnet.so', '/dev/pts/01/uconf.inv',
                              '/dev/pts/01/cleaner', '/dev/pts/01/bin/psniff', '/dev/pts/01/bin/du',
                              '/dev/pts/01/bin/ls', '/dev/pts/01/bin/passwd', '/dev/pts/01/bin/ps',
                              '/dev/pts/01/bin/psr', '/dev/pts/01/bin/su', '/dev/pts/01/bin/find',
                              '/dev/pts/01/bin/netstat', '/dev/pts/01/bin/ping', '/dev/pts/01/bin/strings',
                              '/dev/pts/01/bin/bash', '/usr/man/man1/xxxxxxbin/du', '/usr/man/man1/xxxxxxbin/ls',
                              '/usr/man/man1/xxxxxxbin/passwd', '/usr/man/man1/xxxxxxbin/ps',
                              '/usr/man/man1/xxxxxxbin/psr', '/usr/man/man1/xxxxxxbin/su',
                              '/usr/man/man1/xxxxxxbin/find', '/usr/man/man1/xxxxxxbin/netstat',
                              '/usr/man/man1/xxxxxxbin/ping', '/usr/man/man1/xxxxxxbin/strings',
                              '/usr/man/man1/xxxxxxbin/bash', '/tmp/conf.inv'],
                     'dir': ['/dev/prom', '/dev/pts/01', '/dev/pts/01/bin', '/usr/man/man1/xxxxxxbin'], 'ksyms': []}

        VCKIT_FILES = {'name': 'VcKit Rootkit', 'file': [],
                       'dir': ['/usr/include/linux/modules/lib.so', '/usr/include/linux/modules/lib.so/bin'],
                       'ksyms': []}

        VAMPIRE_FILES = {'name': 'Vampire Rootkit', 'file': [], 'dir': [],
                         'ksyms': ['new_getdents', 'old_getdents', 'should_hide_file_name', 'should_hide_task_name']}

        VOLC_FILES = {'name': 'Volc Rootkit',
                      'file': ['/usr/bin/volc', '/usr/lib/volc/backdoor/divine', '/usr/lib/volc/linsniff',
                               '/etc/rc.d/rc1.d/S25sysconf', '/etc/rc.d/rc2.d/S25sysconf', '/etc/rc.d/rc3.d/S25sysconf',
                               '/etc/rc.d/rc4.d/S25sysconf', '/etc/rc.d/rc5.d/S25sysconf'],
                      'dir': ['/var/spool/.recent', '/var/spool/.recent/.files', '/usr/lib/volc',
                              '/usr/lib/volc/backup'], 'ksyms': []}

        WEAPONX_FILES = {'name': 'weaponX', 'file': ['/System/Library/Extensions/WeaponX.kext'], 'dir': ['/tmp/...'],
                         'ksyms': []}

        XZIBIT_FILES = {'name': 'Xzibit Rootkit',
                        'file': ['/dev/dsx', '/dev/caca', '/dev/ida/.inet/linsniffer', '/dev/ida/.inet/logclear',
                                 '/dev/ida/.inet/sense', '/dev/ida/.inet/sl2', '/dev/ida/.inet/sshdu',
                                 '/dev/ida/.inet/s', '/dev/ida/.inet/ssh_host_key', '/dev/ida/.inet/ssh_random_seed',
                                 '/dev/ida/.inet/sl2new.c', '/dev/ida/.inet/tcp.log', '/home/httpd/cgi-bin/becys.cgi',
                                 '/usr/local/httpd/cgi-bin/becys.cgi', '/usr/local/apache/cgi-bin/becys.cgi',
                                 '/www/httpd/cgi-bin/becys.cgi', '/www/cgi-bin/becys.cgi'],
                        'dir': ['/dev/ida/.inet'], 'ksyms': []}

        XORGSUNOS_FILES = {'name': 'X-Org SunOS Rootkit',
                           'file': ['/usr/lib/libX.a/bin/tmpfl', '/usr/lib/libX.a/bin/rps', '/usr/bin/srload',
                                    '/usr/lib/libX.a/bin/sparcv7/rps', '/usr/sbin/modcheck'],
                           'dir': ['/usr/lib/libX.a', '/usr/lib/libX.a/bin', '/usr/lib/libX.a/bin/sparcv7',
                                   '/usr/share/man...'], 'ksyms': []}

        ZARWT_FILES = {'name': 'zaRwT.KiT Rootkit',
                       'file': ['/dev/rd/s/sendmeil', '/dev/ttyf', '/dev/ttyp', '/dev/ttyn', '/rk/tulz'],
                       'dir': ['/rk', '/dev/rd/s'], 'ksyms': []}

        ZK_FILES = {'name': 'ZK Rootkit',
                    'file': ['/usr/share/.zk/zk', '/usr/X11R6/.zk/xfs', '/usr/X11R6/.zk/echo', '/etc/1ssue.net',
                             '/etc/sysconfig/console/load.zk'],
                    'dir': ['/usr/share/.zk', '/usr/X11R6/.zk'], 'ksyms': []}

        LOGIN_BACKDOOR_FILES = {'name': 'Miscellaneous login backdoors', 'file': ['/bin/.login', '/sbin/.login'],
                                'dir': [], 'ksyms': []}

        Sniffer_FILES = {'name': 'Sniffer log',
                         'file': ['/usr/lib/libice.log', '/dev/prom/sn.l', '/dev/fd/.88/zxsniff.log'],
                         'dir': [], 'ksyms': []}

        SUSPICIOUS_DIRS = {'name': 'Suspicious dir', 'file': [], 'dir': ['/usr/X11R6/bin/.,/copy', '/dev/rd/cdb'],
                           'ksyms': []}

        Apache_Door = {'name': 'Apache backdoor',
                       'file': ['/etc/apache2/mods-enabled/mod_rootme.so', '/etc/apache2/mods-enabled/mod_rootme2.so',
                                '/etc/httpd/modules/mod_rootme.so', '/etc/httpd/modules/mod_rootme2.so',
                                '/usr/apache/libexec/mod_rootme.so', '/usr/apache/libexec/mod_rootme2.so',
                                '/usr/lib/modules/mod_rootme.so', '/usr/lib/modules/mod_rootme2.so',
                                '/usr/local/apache/modules/mod_rootme.so', '/usr/local/apache/modules/mod_rootme2.so',
                                '/usr/local/apache/conf/mod_rootme.so', '/usr/local/apache/conf/mod_rootme2.so',
                                '/usr/local/etc/apache/mod_rootme.so', '/usr/local/etc/apache/mod_rootme2.so',
                                '/etc/apache/mod_rootme.so', '/etc/apache/mod_rootme2.so',
                                '/etc/httpd/conf/mod_rootme.so', '/etc/httpd/conf/mod_rootme2.so'], 'dir': [],
                       'ksyms': []}

        self.LKM_BADNAMES = ['adore.o', 'bkit-adore.o', 'cleaner.o', 'flkm.o', 'knark.o', 'modhide.o', 'mod_klgr.o',
                             'phide_mod.o', 'vlogger.o', 'p2.ko', 'rpldev.o', 'xC.o', 'strings.o', 'wkmr26.o']

        self.rootkit_rules = []
        self.rootkit_rules = [W55808A, Adore_Rootkit, AjaKit_Rootkit, aPa_Kit_Rootkit, Apache_Worm, Ambient_Rootkit,
                              Balaur_Rootkit, Beastkit_Rootkit, beX2_Rootkit, BOBkit_Rootkit,
                              OSX_Boonana_A_Trojan, cb_Rootkit, CiNIK_Worm, CX_Rootkit, Abuse_Kit, Devil_Rootkit,
                              Diamorphine_LKM, Dica_Kit_Rootkit, Dreams_Rootkit, Duarawkz_Rootkit, Ebury_sshd_backdoor,
                              ENYE_LKM, Flea_Rootkit, FreeBSD_Rootkit, Fu_Rootkit, Fuckit_Rootkit, GasKit_Rootkit,
                              Heroin_LKM, HjC_Kit_Rootkit, ignoKit_Rootkit, iLLogiC_Rootkit, OSX_Inqtana, OSX_Inqtana2,
                              OSX_Inqtana3, IntoXonia_NG_Rootkit, Irix_Rootkit, Jynx_Rootkit, Jynx2_Rootkit,
                              KBeast_Rootkit, OSX_Keydnap_backdoor, Kitko_Rootkit, KNARK_FILES, KOMPLEX_FILES,
                              LINUXV_FILES, LION_FILES, LOCKIT_FILES, MOKES_FILES, MRK_FILES, MOODNT_FILES, NIO_FILES,
                              OHHARA_FILES, OPTICKIT_FILES, OSXRK_FILES, OZ_FILES, PHALANX_FILES, PHALANX2_FILES,
                              PORTACELO_FILES, PROTON_FILES, REDSTORM_FILES, RHSHARPES_FILES, RSHA_FILES,
                              SHUTDOWN_FILES, SCALPER_FILES, SHV4_FILES, SHV5_FILES, SINROOTKIT_FILES, SLAPPER_FILES,
                              SNEAKIN_FILES, WANUKDOOR_FILES, WANUKWORM_FILES, SPANISH_FILES, SUCKIT_FILES, NSDAP_FILES,
                              SUNOSROOTKIT_FILES, SUPERKIT_FILES, TBD_FILES, TELEKIT_FILES, TOGROOT_FILES, TORN_FILES,
                              TRNKIT_FILES, TROJANIT_FILES, TURTLE_FILES, TUXTENDO_FILES, URK_FILES, VCKIT_FILES,
                              VAMPIRE_FILES, VOLC_FILES, WEAPONX_FILES, XZIBIT_FILES, XORGSUNOS_FILES, ZARWT_FILES,
                              ZK_FILES, LOGIN_BACKDOOR_FILES, Sniffer_FILES, SUSPICIOUS_DIRS, Apache_Door]

    # 获取内核符号表
    def get_kmsinfo(self):
        try:
            # cat /proc/kallsyms |awk '{print $3}'
            if os.path.exists('/proc/kallsyms'):
                self.kallsyms = os.popen("cat /proc/kallsyms 2>/dev/null|awk '{print $3}'").read().splitlines()
                return
            elif os.path.exists('/proc/ksyms'):
                self.kallsyms = os.popen("cat /proc/ksyms").read().splitlines()
            return
        except:
            return

    # 检测rootkit规则特征
    def check_rootkit_rules(self, rootkit_info):
        suspicious, malice = False, False
        try:
            for file in rootkit_info['file']:
                if os.path.exists(file):
                    malice_result(self.name, rootkit_info['name'], file, '',
                                  u'匹配到名为%s的rootkit文件规则 %s' % (rootkit_info['name'], file),
                                  u'[1]strings %s' % file, u'风险', programme=u'rm %s #删除rootkit恶意文件' % file)
                    malice = True
                    return suspicious, malice
            for dir in rootkit_info['dir']:
                if os.path.exists(dir):
                    malice_result(self.name, rootkit_info['name'], dir, '',
                                  u'匹配到名为%s的rootkit目录规则 %s' % (rootkit_info['name'], dir), u'[1]ls -a %s' % dir, u'风险',
                                  programme=u'rm -rf %s #删除rootkit恶意文件' % dir)
                    malice = True
                    return suspicious, malice

            self.get_kmsinfo()
            for kms in self.kallsyms:
                for ksyms in rootkit_info['ksyms']:
                    if ksyms in kms:
                        malice_result(self.name, rootkit_info['name'], '/proc/kallsyms', '',
                                      u'匹配到名为 %s 的rootkit内核符合表特征 %s' % (rootkit_info['name'], ksyms),
                                      u'[1]cat /proc/kallsyms', u'风险')
                        malice = True
                        return suspicious, malice
            return suspicious, malice
        except:
            return suspicious, malice

    # 检测恶意so文件
    def check_bad_LKM(self):
        suspicious, malice = False, False
        try:
            if not os.path.exists('/lib/modules/'): return suspicious, malice
            infos = os.popen(
                'find /lib/modules/ -name "*.so" -o -name "*.ko"  -o -name "*.ko.xz" 2>/dev/null').read().splitlines()
            for file in infos:
                for lkm in self.LKM_BADNAMES:
                    if lkm == os.path.basename(file):
                        malice_result(self.name, u'LKM内核模块检测', file, '', u'匹配文件 %s 具备恶意特征 %s' % (file, lkm),
                                      u'[1]cat /proc/kallsyms', u'风险', programme=u'rm %s #删除rootkit恶意文件' % file)
                        malice = True
                        return suspicious, malice
            return suspicious, malice
        except:
            return suspicious, malice

    def run(self):
        print(u'\n开始Rootkit类安全扫描')
        file_write(u'\n开始Rootkit类安全扫描\n')

        i = 0
        for rootkit_info in self.rootkit_rules:
            i += 1
            string_output(u' [%d]%s' % (i, rootkit_info['name']))
            suspicious, malice = self.check_rootkit_rules(rootkit_info)
            result_output_tag(suspicious, malice)

        string_output(u' [%d]检测LKM内核模块' % (i + 1))
        suspicious, malice = self.check_bad_LKM()
        result_output_tag(suspicious, malice)

        # 检测结果输出到文件
        result_output_file(self.name)


if __name__ == '__main__':
    info = Rootkit_Analysis()
    info.run()
