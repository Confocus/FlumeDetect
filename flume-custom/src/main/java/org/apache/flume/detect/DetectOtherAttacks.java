package org.apache.flume.detect;

public class DetectOtherAttacks implements DetectAttacks{
	
	private String[] OtherAttackRegex = {
			"(?i:(?:[\\;\\|\\`]\\W*?\\bcc|\\b(wget|curl))\\b|\\/cc(?:[\'\"\\|\\;\\`\\-\\s]|$))",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"(?:\b(?:(?:n(?:et(?:\\b\\W+?\\blocalgroup|\\.exe)|(?:map|c)\\.exe)|t(?:racer(?:oute|t)|elnet\\.exe|clsh8?|ftp)|(?:w(?:guest|sh)|rcmd|ftp)\\.exe|"
			+ "echo\\b\\W*?\\by+)\\b|c(?:md(?:(?:\\.exe|32)\\b|\\b\\W*?\\/c)|d(?:\\b\\W*?[\\/]|\\W*?\\.\\.)|hmod.{0,40}?\\+.{0,3}x))|[\\;\\|\\`]\\W*?\\b(?:(?:c(?:h(?:grp|mod|own|sh)|md|pp)|"
			+ "p(?:asswd|ython|erl|ing|s)|n(?:asm|map|c)|f(?:inger|tp)|(?:kil|mai)l|(?:xte)?rm|ls(?:of)?|telnet|uname|echo|id)\\b|g(?:\\+\\+|cc\\b)))",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"\\b(?:(?:n(?:map|et|c)|w(?:guest|sh)|telnet|rcmd|ftp)\\.exe\\b|cmd(?:(?:32)?\\.exe\\b|\\b\\W*?\\/c))",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"(?:\\((?:\\W*?(?:objectc(?:ategory|lass)|homedirectory|[gu]idnumber|cn)\\b\\W*?=|[^\\w\\x80-\\xFF]*?[\\!\\&\\|][^\\w\\x80-\\xFF]*?\\()|\\)"
			+ "[^\\w\\x80-\\xFF]*?\\([^\\w\\x80-\\xFF]*?[\\!\\&\\|])",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"<!--\\W*?#\\W*?(?:e(?:cho|xec)|printenv|include|cmd)",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"(?i:(\\binclude\\s*\\([^)]*|mosConfig_absolute_path|_CONF\\[path\\]|_SERVER\\[DOCUMENT_ROOT\\]|GALLERY_BASEDIR|path\\[docroot\\]|"
			+ "appserv_root|config\\[root_dir\\])=(ht|f)tps?:\\/\\/)",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"(?:\\b(?:\\.(?:ht(?:access|passwd|group)|www_?acl)|global\\.asa|httpd\\.conf|boot\\.ini)\\b|\\/etc\\/)",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"<\\?(?!xml)",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"(?i)(?:\\b(?:f(?:tp_(?:nb_)?f?(?:ge|pu)t|get(?:s?s|c)|scanf|write|open|read)|gz(?:(?:encod|writ)e|compress|open|read)|s(?:ession_start|candir)|"
			+ "read(?:(?:gz)?file|dir)|move_uploaded_file|(?:proc_|bz)open|call_user_func)|\\$_(?:(?:pos|ge)t|session))\\b",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"(?i)(?:\\x5c|(?:%(?:2(?:5(?:2f|5c)|%46|f)|c(?:0%(?:9v|af)|1%1c)|u(?:221[56]|002f)|%32(?:%46|F)|e0%80%af|1u|5c)|\\/))(?:%(?:2(?:(?:52)?e|%45)|"
			+ "(?:e0%8|c)0%ae|u(?:002e|2024)|%32(?:%45|E))|\\.){2}(?:\\x5c|(?:%(?:2(?:5(?:2f|5c)|%46|f)|c(?:0%(?:9v|af)|1%1c)|u(?:221[56]|002f)|%32(?:%46|F)|e0%80%af|1u|5c)|\\/))",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"(HTTrack|harvest|audit|dirbuster|pangolin|nmap|sqln|-scan|hydra|Parser|libwww|BBBike|sqlmap|w3af|owasp|Nikto|fimap|havij|PycURL|zmeu|BabyKrokodil|netsparker|httperf|bench| SF/)"
	};
	
	@Override
	public void Detect() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public String getAttackType() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getAttackAction() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getAttackRegex() {
		// TODO Auto-generated method stub
		return null;
	}

}
