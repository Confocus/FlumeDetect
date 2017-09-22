package org.apache.flume.detect;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexMatch {
	
	public RegexMatch(){
		
	}
	
	public static boolean match(String regEx, String str){
		Pattern pattern = Pattern.compile(regEx);
		Matcher matcher = pattern.matcher(str);
		boolean rs = matcher.matches();
		return rs;
	}
	
	public static boolean find(String regEx, String str){
		Pattern pattern = Pattern.compile(regEx);
		Matcher matcher = pattern.matcher(str);
		boolean rs = matcher.find();
		return rs;
	}
	
}
