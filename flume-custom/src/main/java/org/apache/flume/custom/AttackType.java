package org.apache.flume.custom;

public class AttackType {
	String rule = "(/\\*!?|" // "/*!?"is a kind of attack
			+ "\\*/|"
			+ "[';]--|"
			+ "--[\\s\\r\\n\\v\\f]|"
			+ "(?:--[^-]*?-)|"
			+ "([^\\-&])#.*?[\\s\\r\\n\\v\\f]|"
			+ ";?\\x00)";
	
	String action = "Comment symbol detection.";
	
	public AttackType(){
		
	}
			
}
