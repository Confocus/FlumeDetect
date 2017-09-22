package org.apache.flume.custom;

import org.apache.flume.custom.*;
import org.apache.flume.custom.RegexMatch;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexTest{
	
	private static String regex = "(/\\*!?|"	//eg. "/*!?"			 "?"represents non-greedy mode.
			+ "\\*/|"							//eg. "*/"
			+ "[';]--|"							//eg. ";--"			     "[]"represents a set
			+ "--[\\s\\r\\n\\v\\f]|"			//eg. "--	"			
			+ "(?:--[^-]*?-)|"					//eg. "--4-"			 "?:" means non acquisition matching; "^" means starting position;"-" means a non- character. 
			+ "([^\\-&])#.*?[\\s\\r\\n\\v\\f]|" //eg. "a#c	"			 "^" means exclusion.	
			+ ";?\\x00)";     
	
	private static String r = ";?\\x00";
	private static String str = "/*";
	
	public static void main(String[] args){
		
		if(RegexMatch.match(regex, str)){
			System.out.println("attack.");
		}
		else{
			System.out.println("unattack.");
		}
	}
}
