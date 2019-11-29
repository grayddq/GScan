
rule Uploader_small_uploader_1 {
	meta:
		description = "Uploader - Clear form,obfuscated handler"
                author = "Farhan Faisal"
                date = "2018/07/17"
                score = 60
		hash = "ecf1130eb57297296953f36970657994"
	strings:
		$s1 = "error_reporting(0)"
		$s2 = "<form"
		$s3 = "multipart/form-data"
		$s4 = "$_REQUEST"

	condition:
		all of them and (filesize < 1KB)
}



rule Uploader_small_uploader_2_clear {
	meta:
		description = "Uploader - simple, clear"
        author = "Farhan Faisal"
        date = "2019/07/11"
        score = 60
		hash = "a5398e7617983b1a85dd203b46055449"
	strings:
		$s1 = "<form"
		$s2 = "multipart/form-data"
		$s3 = "is_uploaded_file"
		$s4 = "move_uploaded_file"
	condition:
		all of them and (filesize < 1KB)
}

