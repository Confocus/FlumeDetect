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
	
	private static String r = "(?:et(?:\\b\\W+?\\blocalgroup|\\.exe)|"		
	+ "(?:map|c)\\.exe)";
	private static String str = "SELECT/*avoid-spaces*/password/**/FROM/**/Members";
	
	public static void main(String[] args){
		
		if(RegexMatch.find(regex1, str)){
			System.out.println("attack.");
		}
		else{
			System.out.println("unattack.");
		}
	}
}
