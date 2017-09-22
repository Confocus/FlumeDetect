package AsyncHBaseLog;

public class Info {
	
	private String content;
	private int sorttime;
	Info(){
		content = "";
		sorttime = 0;
	}
	public String getContent(){
		return this.content;
	}
	public void setContent(String content){
		this.content = content;
	}
	public int getSorttime(){
		return this.sorttime;
	}
	
	public void setSorttime(int sorttime){
		this.sorttime = sorttime;
	}
}

/*private String content;
private String createBy;
public String getContent() {
    return content;
}
public void setContent(String content) {
    this.content = content;
}
public String getCreateBy() {
    return createBy;
}
public void setCreateBy(String createBy) {
    this.createBy = createBy;
}*/