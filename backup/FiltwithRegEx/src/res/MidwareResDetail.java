package res;

public class MidwareResDetail implements ResDetail{
	/* value:�м����־ɨ������ ���м����־�������� ���м����־�������� ������
     ��ʽ��[100,212,103,20]*/
	private int sc;//ScanCount;
	private int ic;//IntrusionCount;
	private int cc;//CoverCount;
	private int oc;//OtherCount;
	
	public MidwareResDetail(){//���캯�����������Ϊ��public�ľͲ��ܹ��������Ķ���
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
