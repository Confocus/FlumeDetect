package org.apache.flume.custom;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DetectSqlAttacks implements DetectAttacks{
	
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
