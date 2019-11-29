import "magic"

rule generic_dangerous_php_call {
        meta:
                description = "Generic - dangerous file with many dangerous php call"
                author = "Farhan Faisal"
                date = "2018/07/17"
                score = 40
        strings:
                $s0 = "base64_decode"
                $s1 = "file_put_contents"
             	$s2 = "is_callable"
                $s3 = "$_SERVER"
                $s4 = "move_uploaded_file"
                $s5 = "eval"
                $s6 = "gzuncompress"
                $s7 = "ini_set"
                $s8 = "set_time_limit"
                $s9 = "error_reporting"
                $s10 = "memory_limit"
                $s11 = "stream_context_create"
                $s12 = "stream_socket_client"
		$s13 = "scandir"
		$s14 = "pathinfo"
		$s15 = "php_uname"
		$s16 = "is_readable"
		$s17 = "get_magic_quotes_gpc"
		$a1 = "SMTP"  			/* exclude phpmailer */
		$a2 = "CutyCapt"		/* exclude thumb.php */
		$a3 = "HighlightRules"		/* exclude textHighlighter */
		$a4 = "array_filter"		/* exclude wpide function list js file*/
		$a5 = "preview_theme_stylesheet_filter"
        condition:
                (8 of ($s*)) and not ($a1 or $a2 or $a3 or ($a4 or $a5))
}



rule generic_obfuscated_code_PROBABLE_scan {
        meta:
             	description = "Generic - detection of obfuscated code (base64_decode)"
                author = "Farhan Faisal"
                date = "2018/07/17"
                score = 60
        strings:
                $s1 = /= \"[0-9a-zA-Z]{1000-600000}/
                $s2 = /=\"[0-9a-zA-Z]{1000-600000}/
                $s3 = /[0-9a-zA-Z]{1000-600000}/
                $aa1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678900000000000000000000000000000000000000000000000000000000000000000000000000000000000000011111111111111111222"
                $aa2 = "effgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz11223344556677889900abacbcbdcdcededfefegfgfhghgihihjijikjkjlklkmlmlnmnmononpopoqpqprqrqsrsrtstsubcbcdcdedefefgfabcadefbghicjkl"
                $bb = /[0-9a-zA-Z]{80}/
                /* exclusion list by strings content */
                /*$cc1 = "image/png;base64"
                $cc2 = "application/font-woff"
                $cc3 = "data:application/x-font-woff"
                $cc4 = "image/gif"
                $cc5 = "image/svg+xml"
                $cc6 = "data:img/png"
                $cc7 = "data:image/jpeg;base64"
                $cc8 = "data:application/json" */
        condition:
                ($s1 or $s2 or $s3) or (#bb > 10 and #bb < 600)   /*and #bb < 600  */
                /*and not ( $cc1 or $cc2 or $cc3 or $cc4 or $cc5 or $cc6 or $cc7 or $cc8 )  */
                and
                  ( magic.mime_type() != "application/vnd.ms-opentype" ) and
                  ( magic.mime_type() != "application/octet-stream" ) and
                  ( magic.mime_type() != "image/png" ) and
                  ( magic.mime_type() != "image/jpeg" ) and
                  ( magic.mime_type() != "application/pdf" ) and
                  ( magic.mime_type() != "image/vnd.adobe.photoshop" )
                and not
                ($aa1 or $aa2)
		and
		  (
                        magic.mime_type() == "text/x-php" or
                        magic.mime_type() == "text/x-c++"
                  )
}

rule generic_webshell_long_base64code {
        meta:
                description = "Webshell-GENERIC. Obfuscated/long base46 code."
                author = "Farhan Faisal"
                date = "2018/07/21"
                score = 60
        strings:
		        $s1 = /= \"[0-9a-zA-Z]{1000-600000}/
                $s2 = /=\"[0-9a-zA-Z]{1000-600000}/
                $s3 = /[0-9a-zA-Z]{1000-600000}/
                $bb = /[0-9a-zA-Z]{80}/  
        condition:
                ($s1 or $s2 or $s3) or (#bb > 600) and not (#bb < 599) 
		and 
			(
			magic.mime_type() == "text/x-php" or
			magic.mime_type() == "text/x-c++"
			)
}
