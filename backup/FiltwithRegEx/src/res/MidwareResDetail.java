package res;

public class MidwareResDetail implements ResDetail{
	/* value:中间件日志扫描数量 ，中间件日志入侵数量 ，中间件日志覆盖数量 ，其他
     格式：[100,212,103,20]*/
	private int sc;//ScanCount;
	private int ic;//IntrusionCount;
	private int cc;//CoverCount;
	private int oc;//OtherCount;
	
	public MidwareResDetail(){//构造函数如果不设置为是public的就不能构造这个类的对象
		sc = 0;
		ic = 0;
		cc = 0;
		oc = 0;
	}
	
	public void Setsc(int sc){
		this.sc = sc;
	}
	public void Setic(int ic){
		this.ic = ic;
	}
	public void Setcc(int cc){
		this.cc = cc;
	}
	public void Setoc(int oc){
		this.oc = oc;
	}
	
	public int Getsc(){
		return sc;
	}
	public int Getic(){
		return ic;
	}
	public int Getcc(){
		return cc;
	}
	public int Getoc(){
		return oc;
	}
}
