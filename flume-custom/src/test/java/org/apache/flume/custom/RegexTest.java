package org.apache.flume.custom;

import org.apache.flume.custom.*;
import org.apache.flume.custom.RegexMatch;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexTest{
	//private static String r = "(/\\*!?|\\*/|[';]--|--[\\s\\r\\n\\v\\f]|(?:--[^-]*?-)|([^\\-&])#.*?[\\s\\r\\n\\v\\f]|;?\\x00)";     
	private static String r = "/\\*!?";
	private static String str = "/*!?";
	
	public static void main(String[] args){
		Pattern pattern = Pattern.compile(r);
		
		if(RegexMatch.match(r, str)){
			System.out.println("attack.");
		}
		else{
			System.out.println("unattack.");
		}
	}
}
