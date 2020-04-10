/*
   base from https://github.com/shakenetwork/php-malware-finder
*/

global private rule IsPhp
{
    strings:
        $php = /<\?[^x]/

    condition:
        $php and filesize < 5MB
}



rule ObfuscatedPhp
{
    strings:
        $eval = /(<\?php|[;{}])[ \t]*@?(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|shell_execute|call_user_func(_array)?)\s*\(/ nocase  // ;eval( <- this is dodgy
        $b374k = "'ev'.'al'"
        $align = /(\$\w+=[^;]*)*;\$\w+=@?\$\w+\(/  //b374k
        $weevely3 = /\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);/  // weevely3 launcher
        $c99_launcher = /;\$\w+\(\$\w+(,\s?\$\w+)+\);/  // http://bartblaze.blogspot.fr/2015/03/c99shell-not-dead.html
        $variable_variable = /\${\$[0-9a-zA-z]+}/
        $too_many_chr = /(chr\([\d]+\)\.){8}/  // concatenation of more than eight `chr()`
        $concat = /(\$[^\n\r]+\.){5}/  // concatenation of more than 5 words
        $concat_with_spaces = /(\$[^\n\r]+\. ){5}/  // concatenation of more than 5 words, with spaces
        $var_as_func = /\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\[[^\]]+\]\s*\(/
        $comment = /\/\*([^*]|\*[^\/])*\*\/\s*\(/  // eval /* comment */ (php_code)
condition:
        any of them
}

rule DodgyPhp
{
    strings:
        $basedir_bypass = /curl_init\s*\(\s*["']file:\/\// nocase
        $basedir_bypass2 = "file:file:///" // https://www.intelligentexploit.com/view-details.html?id=8719
        $disable_magic_quotes = /set_magic_quotes_runtime\s*\(\s*0/ nocase

        $execution = /(eval|assert|passthru|exec|include|system|pcntl_exec|shell_execute|base64_decode|`|array_map|ob_start|call_user_func(_array)?)\s*\(\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))/ nocase  // function that takes a callback as 1st parameter
        $execution2 = /(array_filter|array_reduce|array_walk(_recursive)?|array_walk|assert_options|uasort|uksort|usort|preg_replace_callback|iterator_apply)\s*\(\s*[^,]+,\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))/ nocase  // functions that takes a callback as 2nd parameter
        $execution3 = /(array_(diff|intersect)_u(key|assoc)|array_udiff)\s*\(\s*([^,]+\s*,?)+\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE|SERVER))\s*\[[^]]+\]\s*\)+\s*;/ nocase  // functions that takes a callback as 2nd parameter

        $htaccess = "SetHandler application/x-httpd-php"
        $iis_com = /IIS:\/\/localhost\/w3svc/
        $include = /include\s*\(\s*[^\.]+\.(png|jpg|gif|bmp)/  // Clever includes
        $ini_get = /ini_(get|set|restore)\s*\(\s*['"](safe_mode|open_basedir|disable_(function|classe)s|safe_mode_exec_dir|safe_mode_include_dir|register_globals|allow_url_include)/ nocase
        $pr = /(preg_replace(_callback)?|mb_ereg_replace|preg_filter)\s*\(.+(\/|\\x2f)(e|\\x65)['"]/  nocase // http://php.net/manual/en/function.preg-replace.php
        $register_function = /register_[a-z]+_function\s*\(\s*['"]\s*(eval|assert|passthru|exec|include|system|shell_execute|`)/  // https://github.com/nbs-system/php-malware-finder/issues/41
        $safemode_bypass = /\x00\/\.\.\/|LD_PRELOAD/
        $shellshock = /\(\)\s*{\s*[a-z:]\s*;\s*}\s*;/
        $udp_dos = /fsockopen\s*\(\s*['"]udp:\/\// nocase
        $various = "<!--#exec cmd="  //http://www.w3.org/Jigsaw/Doc/User/SSI.html#exec
        $at_eval = /@eval\s*\(/ nocase
        $double_var = /\${\s*\${/
                $extract = /extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/

    condition:
        any of them
}

rule DangerousPhp
{
    strings:
        $system = "system" fullword nocase  // localroot bruteforcers have a lot of this

        $ = "array_filter" fullword nocase
        $ = "assert" fullword nocase
        $ = "backticks" fullword nocase
        $ = "call_user_func" fullword nocase
        $ = "eval" fullword nocase
        $ = "exec" fullword nocase
        $ = "fpassthru" fullword nocase
        $ = "fsockopen" fullword nocase
        $ = "function_exists" fullword nocase
        $ = "getmygid" fullword nocase
        $ = "shmop_open" fullword nocase
        $ = "mb_ereg_replace_callback" fullword nocase
        $ = "passthru" fullword nocase
        $ = /pcntl_(exec|fork)/ fullword nocase
        $ = "php_uname" fullword nocase
        $ = "phpinfo" fullword nocase
        $ = "posix_geteuid" fullword nocase
        $ = "posix_getgid" fullword nocase
        $ = "posix_getpgid" fullword nocase
        $ = "posix_getppid" fullword nocase
        $ = "posix_getpwnam" fullword nocase
        $ = "posix_getpwuid" fullword nocase
        $ = "posix_getsid" fullword nocase
        $ = "posix_getuid" fullword nocase
        $ = "posix_kill" fullword nocase
        $ = "posix_setegid" fullword nocase
        $ = "posix_seteuid" fullword nocase
        $ = "posix_setgid" fullword nocase
        $ = "posix_setpgid" fullword nocase
        $ = "posix_setsid" fullword nocase
        $ = "posix_setsid" fullword nocase
        $ = "posix_setuid" fullword nocase
        $ = "preg_replace_callback" fullword
        $ = "proc_open" fullword nocase
        $ = "proc_close" fullword nocase
        $ = "popen" fullword nocase
        $ = "register_shutdown_function" fullword nocase
        $ = "register_tick_function" fullword nocase
        $ = "shell_exec" fullword nocase
        $ = "shm_open" fullword nocase
        $ = "show_source" fullword nocase
        $ = "socket_create(AF_INET, SOCK_STREAM, SOL_TCP)" nocase
        $ = "stream_socket_pair" nocase
        $ = "suhosin.executor.func.blacklist" nocase
        $ = "unregister_tick_function" fullword nocase
        $ = "win32_create_service" fullword nocase
        $ = "xmlrpc_decode" fullword nocase 
        $ = /ob_start\s*\(\s*[^\)]/  //ob_start('assert'); echo $_REQUEST['pass']; ob_end_flush();

        $whitelist = /escapeshellcmd|escapeshellarg/ nocase

    condition:
        not $whitelist and (5 of them or #system > 250)
}

rule HiddenInAFile
{
    strings:
        $gif = {47 49 46 38 ?? 61} // GIF8[version]a
        $png = {89 50 4E 47 0D 0a 1a 0a} // \X89png\X0D\X0A\X1A\X0A
        $jpeg = {FF D8 FF E0 ?? ?? 4A 46 49 46 } // https://raw.githubusercontent.com/corkami/pics/master/JPG.png

    condition:
        ($gif at 0 or $png at 0 or $jpeg at 0 )  and ( ObfuscatedPhp or DodgyPhp or DangerousPhp)
}


rule CloudFlareBypass
{
    strings:
        $ = "chk_jschl"
        $ = "jschl_vc"
        $ = "jschl_answer"

    condition:
        2 of them // Better be safe than sorry
}

private rule IRC
{
    strings:
        $ = "USER" fullword nocase
        $ = "PASS" fullword nocase
        $ = "PRIVMSG" fullword nocase
        $ = "MODE" fullword nocase
        $ = "PING" fullword nocase
        $ = "PONG" fullword nocase
        $ = "JOIN" fullword nocase
        $ = "PART" fullword nocase

    condition:
        5 of them
}

private rule b64
{
    strings:
        $user_agent = "SFRUUF9VU0VSX0FHRU5UCg"
        $eval = "ZXZhbCg"
        $system = "c3lzdGVt"
        $preg_replace = "cHJlZ19yZXBsYWNl"
        $exec = "ZXhlYyg"
        $base64_decode = "YmFzZTY0X2RlY29kZ"
        $perl_shebang = "IyEvdXNyL2Jpbi9wZXJsCg"
        $cmd_exe = "Y21kLmV4ZQ"
        $powershell = "cG93ZXJzaGVsbC5leGU"

    condition:
        any of them
}

private rule hex
{
    strings:
        $globals = "\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53" nocase
        $eval = "\\x65\\x76\\x61\\x6C\\x28" nocase
        $exec = "\\x65\\x78\\x65\\x63" nocase
        $system = "\\x73\\x79\\x73\\x74\\x65\\x6d" nocase
        $preg_replace = "\\x70\\x72\\x65\\x67\\x5f\\x72\\x65\\x70\\x6c\\x61\\x63\\x65" nocase
        $http_user_agent = "\\x48\\124\\x54\\120\\x5f\\125\\x53\\105\\x52\\137\\x41\\107\\x45\\116\\x54" nocase
        $base64_decode = "\\x61\\x73\\x65\\x36\\x34\\x5f\\x64\\x65\\x63\\x6f\\x64\\x65\\x28\\x67\\x7a\\x69\\x6e\\x66\\x6c\\x61\\x74\\x65\\x28" nocase
    
    condition:
        any of them
}

private rule Hpack
{
    strings:
    $globals = "474c4f42414c53" nocase
        $eval = "6576616C28" nocase
        $exec = "65786563" nocase
        $system = "73797374656d" nocase
        $preg_replace = "707265675f7265706c616365" nocase
        $base64_decode = "61736536345f6465636f646528677a696e666c61746528" nocase
    
    condition:
        any of them
}

private rule strrev
{
    strings:
        $globals = "slabolg" nocase fullword
        $preg_replace = "ecalper_gerp" nocase fullword
        $base64_decode = "edoced_46esab" nocase fullword
        $gzinflate = "etalfnizg" nocase fullword
    
    condition:
        any of them
}


rule SuspiciousEncoding
{
    condition:
        b64 or hex or strrev or Hpack
}
