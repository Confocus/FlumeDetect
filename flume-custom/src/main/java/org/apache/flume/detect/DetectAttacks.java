package org.apache.flume.detect;

public interface DetectAttacks {
	public void Detect();
	
	public String getAttackType();
	
	public String getAttackAction();
	
	public String getAttackRegex();
	
}
