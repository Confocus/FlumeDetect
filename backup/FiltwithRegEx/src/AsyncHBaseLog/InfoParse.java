package AsyncHBaseLog;

import java.sql.Date;

public class InfoParse {
	private String srcip;
	private String dstip;
	private java.sql.Date date;
	private String time;
	private int atype;
	private String srcloc;
	private String dstloc;
	
	public String getSrcloc(){
		return this.srcloc;
	}
	public void setSrcloc(String srcloc){
		this.srcloc = srcloc;
	}
	
	public String getDstloc(){
		return this.dstloc;
	}
	public void setDstloc(String dstloc){
		this.dstloc = dstloc;
	}
	
	
	public String getSrcip(){
		return this.srcip;
	}
	public void setSrcip(String srcip){
		this.srcip = srcip;
	}
	
	public String getDstip(){
		return this.dstip;
	}
	public void setDstip(String dstip){
		this.dstip = dstip;
	}
	
	public java.sql.Date getDate(){
		return this.date;
	}
	public void setDate(java.sql.Date date){
		this.date = date;
	}
	
	public String getTime(){
		return this.time;
	}
	public void setTime(String time){
		this.time = time;
	}
	
	public int getAType(){
		return this.atype;
	}
	public void setAType(int atype){
		this.atype = atype;
	}
}
