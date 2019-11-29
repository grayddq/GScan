import "magic"

rule Webshell_obfuscated_1 {
	meta:
		description = "Webshell-obfuscated. Need further analysis /missed/helper.php"
        author = "Farhan Faisal"
        date = "2018/07/17"
        score = 60
		hash = "316c188bbbf34d92c840e32f7c1b148f"
	strings:
		$ss1 = "foreach(array"
		$ss2 = "''.''."
		$ss3 = "()"
	condition:
		filesize > 110KB and filesize < 130KB and (#ss1 > 1) and (#ss2 > 8) and $ss3
}

rule Webshell_obfuscated_2 {
	meta:
		description = "Webshell-obfuscated. Need further analysis /missed/decode.php"
        author = "Farhan Faisal"
        date = "2018/07/21"
        score = 60
        hash = "d8577ec2847469fefcfb6839af524166"
	strings:
		$ss1 = "GLOBALS"
		$ss2 = "]."
		$aa1 = "foreach ($_POST"
		$aa2 = "str_split"
		$aa3 = "rawurldecode"
		$aa4 = "str_rot13"
		$aa5 = "phpversion"
		$aa6 = "is_writable"
		$aa7 = "file_put_contents"
	condition:
		(#ss1 > 1) and (#ss2 > 90) and (all of ($aa*))
}


rule Webshell_obfuscated_3 {
	meta:
		description = "Webshell-obfuscated. Need further analysis /missed/baer.php"
        author = "Farhan Faisal"
        date = "2018/07/21"
        score = 60
        hash = "f2d7553b97d8e0a0258e48c3ca42a7d2"
	strings:
		$bb = /[0-9a-zA-Z]{80}/
		$aa1 = "array"
		$aa2 = "();"
		$xx1 = "TextareaAutosize.prototype.componentDidMount"
		$xx2 = "ZoneScore.prototype.scoreOffsetAt"
	condition:
		(#bb > 40000) and (#aa1 > 3) and ($aa2) and not (any of ($xx*))
}

rule Webshell_obfuscated_4_hexa {
	meta:
		description = "Webshell-obfuscated. Need further analysis /missed/prv8.php"
        author = "Farhan Faisal"
        date = "2018/07/21"
        score = 60
        hash = "994efbd230e21cc85a5acf39652cee26"
	strings:
		$s = "\\x"
		$xx1 = "SimplePie"
		$xx2 = "CRYPT_DES_MODE"
		$xx3 = "Nette Framework"
		$xx4 = "X-Poedit-KeywordsList"  /* Evolve theme language file PO*/
		$xx5 = "PREG_CLASS_SEARCH_EXCLUDE"  /*prestashop search.php core file */
		$xx6 = "SwiftMailer"
		$xx7 = "minify@mullie.eu"
		$xx8 = "e.moment=a()"
		$xx9 = "underscorejs.org"
	condition:
		(#s > 200) and not (any of ($xx*))
}



rule Webshell_obfuscated_5_GLOBAL_sort {
	meta:
		description = "Webshell-obfuscated 5. Use GLOBAL and sort. Need further analysis /missed/db_connector.php"
        author = "Farhan Faisal"
        date = "2018/07/21"
        score = 60
        hash = "e1cf9ccce21bb609ba3c19cc6a7d0b80"
	strings:
		$s1 = "GLOBALS"
		$s2 = "eval"
		$xx1 = "]["
		$xx2 = "\\x"
	condition:
		(all of ($s*)) and (#xx1 > 30) and (#xx2 > 20) and (filesize < 30KB)
}


rule Webshell_obfuscated_6_weirdChar {
	meta:
		description = "Webshell-obfuscated 6. weird char. Need further analysis /missed/baklswty.php"
        author = "Farhan Faisal"
        date = "2018/07/22"
        score = 60
        hash = "3454e48b6d84b816c0dcd6abd79ad05a"
	strings:
		$s1 = "php"
		$s2 = "function"
		$s3 = "rawurl"
		$s4 = "decode"
		$s5 = "eval"
		$xx1 = "=>"
	condition:
		(all of ($s*)) and (#xx1 > 40) and filesize < 8KB
}

rule Webshell_obfuscated_IRCBOT_1 {
	meta:
		description = "Webshell-obfuscated 6. weird char. Need further analysis /missed/boxpeiur.php"
        author = "Farhan Faisal"
        date = "2018/07/22"
        score = 60
        hash = "18b07c5e3f4521ef7a3b141250ef9707"
	strings:
		$s1 = "gethostbyaddr"
		$s2 = "CURLOPT"
		$s3 = "chmod"
		$xx1 = "'#"
	condition:
		filesize < 8KB and (#xx1 > 10) and (all of ($s*))
}

