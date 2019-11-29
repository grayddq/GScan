rule malicious_php_checker_php_sapi_name {
	meta:
		description = "malicious - small php checker (php_sapi_name)"
                author = "Farhan Faisal"
                date = "2018/07/19"
                score = 80

	strings:
		$s1 = "error_reporting"
		$s2 = "stristr(php_sapi_name"
		$s3 = "404.html"
		$s4 = "exit();"

	condition:
		(all of ($s*)) and filesize < 300
}



rule Redirector_JSfile_small {
	meta:
		description = "Redirector - small js redirector"
                author = "Farhan Faisal"
                date = "2018/07/19"
                score = 80
        strings:
		$s1 = /^var/
		$s2 = "document["
	condition:
		(all of ($s*)) and filesize < 500
}

rule Redirector_HTML_small {
	meta:
		description = "Redirector - small HTML redirector"
                author = "Farhan Faisal"
                date = "2018/07/19"
                score = 80
	strings:
		$s1 = "<head>"
		$s2 = "<meta"
		$s3 = "http-equiv=\"refresh\""
		$s4 = "content=\"0"
	condition:
		all of them and filesize < 200
}

rule eval_for_POST_smallest_backdoor {
	meta:
		description = "Eval for post data - smallest"
                author = "Farhan Faisal"
                date = "2018/07/21"
                score = 80
	strings:
		$s1 = "POST"
		$s2 = "eval"
	condition:
		all of them and filesize < 50
}

rule PHPcheck_small_oneliner_1 {
	meta:
		description = "PHP checker - one-liner"
                author = "Farhan Faisal"
                date = "2018/07/21"
                score = 80
	strings:
		$s1 = /^\<\?php/
		$s2 = "base64_decode"
		$s3 = "GET"
		$s4 = "POST"
	condition:
		($s1 and $s2) and ($s3 or $s4) and (filesize < 100)
}


/*rule SmallPHP_Unknown_1 {
	meta:
		description = "Small PHP - Unknown 1"
                author = "Farhan Faisal"
                date = "2018/07/21"
                score = 80
	strings:
		$s1 = "$_REQUEST"
		$s2 = "php"
	condition:
		filesize < 300 and ( any of ($s*) )
}*/


rule SmallPHP_Unknown_include_1 {
	meta:
		description = "Small PHP - obfuscated include 1. Sample file in missed/index.2php and index3.php"
             	author = "Farhan Faisal"
                date = "2018/07/21"
                score = 80
	strings:
		$s1 = "php"
		$s2 = "include"
		$xx1 = "\\"
	condition:
		filesize < 200 and (all of ($s*)) and (#xx1 > 10)
}


rule SmallPHP_Unknown_2 {
	meta:
		description = "Small PHP - obfuscated unknown 2. Sample file in missed/opn-post.php"
                author = "Farhan Faisal"
                date = "2018/07/21"
                score = 80
	strings:
		$s1 = "str_replace"
		$s2 = "php"
		$xx1 = "="
	condition:
		filesize < 350 and (all of ($s*)) and (#xx1 > 7)
}


rule SmallPHP_read_suspected {
	meta:
		description = "Small PHP - obfuscated unknown 2. Sample file in missed/lerbim.php"
                author = "Farhan Faisal"
                date = "2018/07/21"
                score = 80
	strings:
		$s1 = "set_time_limit"
		$s2 = "php"
		$s3 = "suspected"
		$s4 = "scandir"
	condition:
		(all of ($s*)) and filesize < 350
}


rule SmallPHP_unknown_3 {
	meta:
		description = "Small PHP - obfuscated unknown 2. Sample file in missed/menu-getTicketAssignment.php"
                author = "Farhan Faisal"
             	date = "2018/07/21"
                score = 80
	strings:
		$s1 = "REQUEST"
		$s2 = "array"
		$xx1 = "("
	condition:
		filesize < 300 and (all of ($s*)) and (#xx1 > 5)
}

rule SmallPHP_Unknown_4 {
	meta:
		description = "Small PHP - obfuscated unknown 3. Sample file in missed/sample.php"
                author = "Farhan Faisal"
                date = "2019/07/11"
                score = 80
                hash = "cff7f38ae7f833337c158825cd2bda35"
	strings:
		$s1 = "include"
		$s2 = "php"
		$s3 = "file_get_contents"
		$xx1 = "/*"
		$xx2 = "*/"
	condition:
		filesize < 300 and (all of ($s*)) and (#xx1 > 1) and (#xx2 > 1)
}


rule SmallPHP_Unknown_5_obfuscated {
	meta:
		description = "Small PHP - obfuscated unknown 3. Sample file in missed/edit.php"
                author = "Farhan Faisal"
                date = "2019/07/11"
                score = 80
                hash = "5ddd03245b38e5ae8e83ae733d8c4b9d"
	strings:
		$ss = /([A-Za-z0-9+\/]{4}){3,}([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/
		$s2 = "eval"
		$xx1 = "="
		$xx2 = "{"
	condition:
		($ss) or filesize < 2KB and (all of ($s*)) and (#xx1 > 5) and (#xx2 > 10)
}

