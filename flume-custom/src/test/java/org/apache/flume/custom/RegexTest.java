package org.apache.flume.custom;

import org.apache.flume.custom.*;
import org.apache.flume.detect.RegexMatch;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexTest{
	
	private static String regex1 = "(/\\*!?|"	//eg. "/*!?"			 "?"represents non-greedy mode.
			+ "\\*/|"							//eg. "*/"
			+ "[';]--|"							//eg. ";--"			     "[]"represents a set
			+ "--[\\s\\r\\n\\v\\f]|"			//eg. "--	"			
			+ "(?:--[^-]*?-)|"					//eg. "--4-"			 "?:" means non acquisition matching; "^" means starting position;"-" means a non- character. 
			+ "([^\\-&])#.*?[\\s\\r\\n\\v\\f]|" //eg. "a#c	"			 "^" means exclusion.	
			+ ";?\\x00)";     
	
	private static String regex = 
			"(?:\\b(?:(?:n(?:et(?:\\b\\W+?\\blocalgroup|\\.exe)|"		//"\\W" means "[^A-Za-z0-9_]" 
	+ "(?:map|c)\\.exe)|"
	+ "t(?:racer(?:oute|t)|elnet\\.exe|clsh8?|ftp)|(?:w(?:guest|sh)|rcmd|ftp)\\.exe|echo\\b\\W*?\\by+)\\b|"
	+ "c(?:md(?:(?:\\.exe|32)\\b|\\b\\W*?\\/c)|d(?:\\b\\W*?[\\/]|\\W*?\\.\\.)|hmod.{0,40}?\\+.{0,3}x))|"
	+ "[\\;\\|\\`]\\W*?\\b(?:(?:c(?:h(?:grp|mod|own|sh)|md|pp)|"
	+ "p(?:asswd|ython|erl|ing|s)|n(?:asm|map|c)|f(?:inger|tp)|(?:kil|mai)l|(?:xte)?rm|ls(?:of)?|telnet|uname|echo|id)\\b|g(?:\\+\\+|cc\\b)))";
	
	//"et(?:\\b\\W+?\\blocalgroup|\\.exe)" means "et % localgroup" or "et.exe"
	//"(?:et(?:\\b\\W+?\\blocalgroup|\\.exe)|(?:map|c)\\.exe)" means "map.exe" or "c.exe" or "et.exe" or "et % localgroup"
	//"|":所在括号的前半部全是，后半部全是。
	
	private static String r = "(?i:(?:(?:s(?:t(?:d(?:dev(_pop|_samp)?)?|r(?:_to_date|cmp))|u(?:b(?:str(?:ing(_index)?)?|(?:dat|tim)e)|m)|e(?:c(?:_to_time|ond)|ssion_user)|ys(?:tem_user|date)|ha(1|2)?|oundex|chema|ig?n|pace|qrt)|"
			+ "i(?:s(null|_(free_lock|ipv4_compat|ipv4_mapped|ipv4|ipv6|not_null|not|null|used_lock))?|n(?:et6?_(aton|ntoa)|s(?:ert|tr)|terval)?|f(null)?)|u(?:n(?:compress(?:ed_length)?|ix_timestamp|hex)|tc_(date|time|timestamp)|"
			+ "p(?:datexml|per)|uid(_short)?|case|ser)|l(?:o(?:ca(?:l(timestamp)?|te)|g(2|10)?|ad_file|wer)|ast(_day|_insert_id)?|e(?:(?:as|f)t|ngth)|case|trim|pad|n)|t(?:ime(stamp|stampadd|stampdiff|diff|_format|_to_sec)?|"
			+ "o_(base64|days|seconds|n?char)|r(?:uncate|im)|an)|m(?:a(?:ke(?:_set|date)|ster_pos_wait|x)|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:nth(name)?|d)|d5)|r(?:e(?:p(?:lace|eat)|lease_lock|verse)|o(?:w_count|und)|a(?:dians|nd)|ight|trim|pad)|"
			+ "f(?:i(?:eld(_in_set)?|nd_in_set)|rom_(base64|days|unixtime)|o(?:und_rows|rmat)|loor)|a(?:es_(?:de|en)crypt|s(?:cii(str)?|in)|dd(?:dat|tim)e|(?:co|b)s|tan2?|vg)|p(?:o(?:sition|w(er)?)|eriod_(add|diff)|rocedure_analyse|assword|i)|"
			+ "b(?:i(?:t_(?:length|count|x?or|and)|n(_to_num)?)|enchmark)|e(?:x(?:p(?:ort_set)?|tract(value)?)|nc(?:rypt|ode)|lt)|v(?:a(?:r(?:_(?:sam|po)p|iance)|lues)|ersion)|g(?:r(?:oup_conca|eates)t|et_(format|lock))|o(?:(?:ld_passwo)?rd|ct(et_length)?)|"
			+ "we(?:ek(day|ofyear)?|ight_string)|n(?:o(?:t_in|w)|ame_const|ullif)|(rawton?)?hex(toraw)?|qu(?:arter|ote)|(pg_)?sleep|year(week)?|d?count|xmltype|hour)\\W*\\(|\\b(?:(?:s(?:elect\\b(?:.{1,100}?\\b(?:(?:length|count|top)\\b.{1,100}?\\bfrom|"
			+ "from\\b.{1,100}?\\bwhere)|.*?\\b(?:d(?:ump\\b.*\\bfrom|ata_type)|(?:to_(?:numbe|cha)|inst)r))|p_(?:sqlexec|sp_replwritetovarbin|sp_help|addextendedproc|is_srvrolemember|prepare|sp_password|execute(?:sql)?|makewebtask|oacreate)|"
			+ "ql_(?:longvarchar|variant))|xp_(?:reg(?:re(?:movemultistring|ad)|delete(?:value|key)|enum(?:value|key)s|addmultistring|write)|terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process|e(?:xecresultset|numdsn)|"
			+ "availablemedia|loginconfig|cmdshell|filelist|dirtree|makecab|ntsec)|u(?:nion\\b.{1,100}?\\bselect|tl_(?:file|http))|d(?:b(?:a_users|ms_java)|elete\\b\\W*?\\bfrom)|group\\b.*\\bby\\b.{1,100}?\\bhaving|open(?:rowset|owa_util|query)|"
			+ "load\\b\\W*?\\bdata\\b.*\\binfile|(?:n?varcha|tbcreato)r|autonomous_transaction)\\b|i(?:n(?:to\\b\\W*?\\b(?:dump|out)file|sert\\b\\W*?\\binto|ner\\b\\W*?\\bjoin)\\b|(?:f(?:\\b\\W*?\\(\\W*?\\bbenchmark|null\\b)|snull\\b)\\W*?\\()|"
			+ "print\\b\\W*?\\@\\@|cast\\b\\W*?\\()|c(?:(?:ur(?:rent_(?:time(?:stamp)?|date|user)|(?:dat|tim)e)|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|ast|r32)\\W*\\(|o(?:(?:n(?:v(?:ert(?:_tz)?)?|cat(?:_ws)?|nection_id)|"
			+ "(?:mpres)?s|ercibility|alesce|t)\\W*\\(|llation\\W*\\(a))|d(?:(?:a(?:t(?:e(?:(_(add|format|sub))?|diff)|abase)|y(name|ofmonth|ofweek|ofyear)?)|e(?:(?:s_(de|en)cryp|faul)t|grees|code)|ump)\\W*\\(|bms_\\w+\\.\\b)|(?:;\\W*?\\b(?:shutdown|drop)|"
			+ "\\@\\@version)\\b|\butl_inaddr\\b|\\bsys_context\\b|'(?:s(?:qloledb|a)|msdasql|dbo)'))";
			
	
	private static String str = "(?i:(?:(?:s(?:t(?:d(?:dev(_pop|_samp)?)?|r(?:_to_date|cmp))|u(?:b(?:str(?:ing(_index)?)?|(?:dat|tim)e)|m)|e(?:c(?:_to_time|ond)|ssion_user)|ys(?:tem_user|date)|ha(1|2)?|oundex|chema|ig?n|pace|qrt)|i(?:s(null|_(free_lock|ipv4_compat|ipv4_mapped|ipv4|ipv6|not_null|not|null|used_lock))?|n(?:et6?_(aton|ntoa)|s(?:ert|tr)|terval)?|f(null)?)|u(?:n(?:compress(?:ed_length)?|ix_timestamp|hex)|tc_(date|time|timestamp)|p(?:datexml|per)|uid(_short)?|case|ser)|l(?:o(?:ca(?:l(timestamp)?|te)|g(2|10)?|ad_file|wer)|ast(_day|_insert_id)?|e(?:(?:as|f)t|ngth)|case|trim|pad|n)|t(?:ime(stamp|stampadd|stampdiff|diff|_format|_to_sec)?|o_(base64|days|seconds|n?char)|r(?:uncate|im)|an)|m(?:a(?:ke(?:_set|date)|ster_pos_wait|x)|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:nth(name)?|d)|d5)|r(?:e(?:p(?:lace|eat)|lease_lock|verse)|o(?:w_count|und)|a(?:dians|nd)|ight|trim|pad)|f(?:i(?:eld(_in_set)?|nd_in_set)|rom_(base64|days|unixtime)|o(?:und_rows|rmat)|loor)|a(?:es_(?:de|en)crypt|s(?:cii(str)?|in)|dd(?:dat|tim)e|(?:co|b)s|tan2?|vg)|p(?:o(?:sition|w(er)?)|eriod_(add|diff)|rocedure_analyse|assword|i)|b(?:i(?:t_(?:length|count|x?or|and)|n(_to_num)?)|enchmark)|e(?:x(?:p(?:ort_set)?|tract(value)?)|nc(?:rypt|ode)|lt)|v(?:a(?:r(?:_(?:sam|po)p|iance)|lues)|ersion)|g(?:r(?:oup_conca|eates)t|et_(format|lock))|o(?:(?:ld_passwo)?rd|ct(et_length)?)|we(?:ek(day|ofyear)?|ight_string)|n(?:o(?:t_in|w)|ame_const|ullif)|(rawton?)?hex(toraw)?|qu(?:arter|ote)|(pg_)?sleep|year(week)?|d?count|xmltype|hour)\\W*?\\(|\\b(?:(?:s(?:elect\b(?:.{1,100}?\b(?:(?:length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(?:d(?:ump\b.*?\bfrom|ata_type)|(?:to_(?:numbe|cha)|inst)r))|p_(?:sqlexec|sp_replwritetovarbin|sp_help|addextendedproc|is_srvrolemember|prepare|sp_password|execute(?:sql)?|makewebtask|oacreate)|ql_(?:longvarchar|variant))|xp_(?:reg(?:re(?:movemultistring|ad)|delete(?:value|key)|enum(?:value|key)s|addmultistring|write)|terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process|e(?:xecresultset|numdsn)|availablemedia|loginconfig|cmdshell|filelist|dirtree|makecab|ntsec)|u(?:nion\b.{1,100}?\bselect|tl_(?:file|http))|d(?:b(?:a_users|ms_java)|elete\b\\W*?\\bfrom)|group\\b.*?\\bby\\b.{1,100}?\\bhaving|open(?:rowset|owa_util|query)|load\\b\\W*?\\bdata\\b.*?\\binfile|(?:n?varcha|tbcreato)r|autonomous_transaction)\\b|i(?:n(?:to\\b\\W*?\\b(?:dump|out)file|sert\\b\\W*?\\binto|ner\\b\\W*?\\bjoin)\\b|(?:f(?:\\b\\W*?\\(\\W*?\\bbenchmark|null\\b)|snull\\b)\\W*?\\()|print\\b\\W*?\\@\\@|cast\\b\\W*?\\()|c(?:(?:ur(?:rent_(?:time(?:stamp)?|date|user)|(?:dat|tim)e)|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|ast|r32)\\W*?\\(|o(?:(?:n(?:v(?:ert(?:_tz)?)?|cat(?:_ws)?|nection_id)|(?:mpres)?s|ercibility|alesce|t)\\W*?\\(|llation\\W*?\\(a))|d(?:(?:a(?:t(?:e(?:(_(add|format|sub))?|diff)|abase)|y(name|ofmonth|ofweek|ofyear)?)|e(?:(?:s_(de|en)cryp|faul)t|grees|code)|ump)\\W*?\\(|bms_\\w+\\.\\b)|(?:;\\W*?\\b(?:shutdown|drop)|\\@\\@version)\\b|\\butl_inaddr\\b|\\bsys_context\\b|'(?:s(?:qloledb|a)|msdasql|dbo)'))";	
	
	public static void main(String[] args){
		
		if(RegexMatch.matches(r, str)){
			//System.out.println(str);
			System.out.println("attack.");
		}
		else{
			System.out.println("unattack.");
		}
	}
}
