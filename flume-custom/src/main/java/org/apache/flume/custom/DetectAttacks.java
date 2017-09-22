package org.apache.flume.custom;

public interface DetectAttacks {
	public void Detect();
	
	public String getAttackType();
	
	public String getAttackAction();
	
	public String getAttackRegex();
	
}
