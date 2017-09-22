package org.apache.flume.detect;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DetectSqlAttacks implements DetectAttacks{
	private String[] SqlAttackRegex = {
			"(/\\*!?|\\*/|[';]--|--[\\s\\r\\n\\v\\f]|(?:--[^-]*?-)|([^\\-&])#.*?[\\s\\r\\n\\v\\f]|;?\\x00)",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"(?i:(?:\\A|[^\\d])0x[a-f\\d]{3,}[a-f\\d]*)+",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"(^[\"'`´’‘;]+|[\"'`´’‘;]+$)",
			"(?i:(\\!\\=|\\&\\&|\\|\\||>>|<<|>=|<=|<>|<=>|xor|rlike|regexp|isnull)|(?:not\\s+between\\s+0\\s+and)|(?:is\\s+null)|(like\\s+null)"
			+ "|(?:(?:^|\\W)in[+\\s]*\\([\\s\\d\"]+[^()]*\\))|(?:xor|<>|rlike(?:\\s+binary)?)|(?:regexp\\s+binary))",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"(?i:([\\s'\"`´’‘\\(\\)]*?)\\b([\\d\\w]++)([\\s'\"`´’‘\\(\\)]*?)(?:(?:=|<=>|r?like|sounds\\s+like|regexp)([\\s'\"`´’‘\\(\\)]*?)\\2\\b|"
			+ "(?:!=|<=|>=|<>|<|>|\\^|is\\s+not|not\\s+like|not\\s+regexp)([\\s'\"`´’‘\\(\\)]*?)(?!\2)([\\d\\w]+)\\b))",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"(?i:([\\s'\"`´’‘\\(\\)]*?)\\b([\\d\\w]++)([\\s'\"`´’‘\\(\\)]*?)(?:(?:=|<=>|r?like|sounds\\s+like|regexp)"
			+ "([\\s'\"`´’‘\\(\\)]*?)\\2\\b|(?:!=|<=|>=|<>|<|>|\\^|is\\s+not|not\\s+like|not\\s+regexp)([\\s'\"`´’‘\\(\\)]*?)(?!\\2)([\\d\\w]+)\\b))",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"(?i:(?:m(?:s(?:ysaccessobjects|ysaces|ysobjects|ysqueries|ysrelationships|ysaccessstorage|ysaccessxml|ysmodules|ysmodules2|db)|aster\\.\\.sysdatabases|ysql\\.db)|"
			+ "s(?:ys(?:\\.database_name|aux)|chema(?:\\W*\\(|_name)|qlite(_temp)?_master)|d(?:atabas|b_nam)e\\W*\\(|information_schema|pg_(catalog|toast)|northwind|tempdb))",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			"(?i:(?:\\b(?:(?:s(?:ys\\.(?:user_(?:(?:t(?:ab(?:_column|le)|rigger)|object|view)s|c(?:onstraints|atalog))|all_tables|tab)|elect\\b.{0,40}\\b(?:substring|users?|ascii))|"
			+ "m(?:sys(?:(?:queri|ac)e|relationship|column|object)s|ysql\\.(db|user))|c(?:onstraint_type|harindex)|waitfor\\b\\W*?\\bdelay|attnotnull)\\b|(?:locate|instr)\\W+\\()|\\@\\@spid\\b)|"
			+ "\\b(?:(?:s(?:ys(?:(?:(?:process|tabl)e|filegroup|object)s|c(?:o(?:nstraint|lumn)s|at)|dba|ibm)|ubstr(?:ing)?)|user_(?:(?:(?:constrain|objec)t|tab(?:_column|le)|ind_column|user)s|password|group)"
			+ "|a(?:tt(?:rel|typ)id|ll_objects)|object_(?:(?:nam|typ)e|id)|pg_(?:attribute|class)|column_(?:name|id)|xtype\\W+\\bchar|mb_users|rownum)\\b|t(?:able_name\\b|extpos\\W+\\()))",
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////	
			"(?i:(?:(?:s(?:t(?:d(?:dev(_pop|_samp)?)?|r(?:_to_date|cmp))|u(?:b(?:str(?:ing(_index)?)?|(?:dat|tim)e)|m)|e(?:c(?:_to_time|ond)|ssion_user)|ys(?:tem_user|date)|ha(1|2)?|oundex|chema|ig?n|pace|qrt)|"
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
			+ "\\@\\@version)\\b|\butl_inaddr\\b|\\bsys_context\\b|'(?:s(?:qloledb|a)|msdasql|dbo)'))"
	
	};
	
	
	@Override
	public String getAttackType() {
		// TODO Auto-generated method stub
		return "Sql attack.";
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

	@Override
	public void Detect() {
		// TODO Auto-generated method stub
//		Pattern pattern = Pattern.compile(r);
//		RegexMatch.match(r, str);
	}

}
