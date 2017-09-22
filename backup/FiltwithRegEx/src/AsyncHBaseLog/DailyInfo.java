package AsyncHBaseLog;


public class DailyInfo {
	java.sql.Date date;
	Integer total;
	public void SetDate(java.sql.Date date){
		this.date = date;
	}
	
	public void SetTotal(Integer total){
		this.total = total;
	}
	
	public java.sql.Date GetDate(){
		return this.date;
	}
	
	public Integer GetTotal(){
		return this.total;
	}
}
