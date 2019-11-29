

rule phpmailer_Real_Leaf_phpMailer {
	meta:
		description = "phpMailer - Real Leaf phpMailer"
                author = "Farhan Faisal"
                date = "2018/07/19"
                score = 60
	strings:
		$s1 = "leafmailer.pw"
	condition:
		$s1
}


rule phpmailer_shock_priv8_phpMailer {
        meta:
                description = "phpMailer - Shock Priv8 phpMailer"
                author = "Farhan Faisal"
                date = "2018/07/19"
                score = 60
        strings:
		$s1 = "PHP Mailer"
                $s2 = "Priv8"
		$s3 = "Mailer"
		$s4 = "abcdefghijklmnopqrstuvwxyz0123456789"
		$s5 = "multipart/form-data"
		$a1 = "lrtrim"
		$a2 = "str_replace"
		$a3 = "whitespace"
        condition:
                ($s1 and $s2 and $s3 and $s4 and $s5) and (#a1 > 14) and (#a2 > 11) and (#a3 > 8)
}



rule phpmailer_Xsender_phpmailer {
	meta:
             	description = "phpMailer - Xsender mailer"
                author = "Farhan Faisal"
                date = "2018/07/19"
                score = 60
	strings:
		$s1 = "multipart/form-data"
		$s5 = "chunk_split"
		$s6 = "base64_encode"
		$s7 = "MIME-Version"
		$s8 = "xsenderid"
		$a1 = "str_replace"
		$a2 = "sanitize"
		$a3 = "textarea"
	condition:
		(all of ($s*)) and ( #a1 > 24) and (#a2 > 7) and (#a3 > 6)
}

rule phpmailer_Xsender_V1_phpmailer {
        meta:
             	description = "phpMailer - Xsender V1 mailer"
                author = "Farhan Faisal"
                date = "2018/07/19"
                score = 60
        strings:
                $s1 = "multipart/form-data"
                $s2 = "ob_gzhandler"
                $s3 = "fuck"
                $s4 = "shit"
                $s5 = "chunk_split"
                $s6 = "base64_encode"
             	$s7 = "MIME-Version"
                $s8 = "xsenderid"
		$s9 = "tatata"
                $s10 = "Ukraine (UA)"
		$s11 = "Randommix"
		$s12 = "xSenderV1"
		$s13 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                $a1 = "str_replace"
                $a2 = "sanitize"
                $a3 = "textarea"
        condition:
                (all of ($s*)) and ( #a1 > 30) and (#a2 > 6) and (#a3 > 4)
}



rule phpMailer_class_generic_customized_by_Acyba {
	meta:
		description = "phpMailer class - phpmailer.sourceforge.net - Customized by Acyba"
                author = "Farhan Faisal"
                date = "2018/07/19"
                score = 60
	strings:
		$s1 = "phpmailer.sourceforge.net"
		$s2 = "Andy Prevost"
		$s3 = "PHPMAILER_LANG"
		$aa = "mail("
	condition:
		(#aa > 5) and (all of ($s*))
}
