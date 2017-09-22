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
			"(?i:([\\s'\"`´’‘\\(\\)]*?)\\b([\\d\\w]++)([\\s'\"`´’‘\\(\\)]*?)(?:(?:=|<=>|r?like|sounds\\s+like|regexp)([\\s'\"`´’‘\\(\\)]*?)\\2\\b|"
			+ "(?:!=|<=|>=|<>|<|>|\\^|is\\s+not|not\\s+like|not\\s+regexp)([\\s'\"`´’‘\\(\\)]*?)(?!\2)([\\d\\w]+)\\b))"
			
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
