package AsyncHBaseLog;

public class Total {
	private int scan;
	private int attack;
	private float cover;
	private int other;
	private int total;
	
	public int GetScan(){
		return this.scan;
	}
	
	public int GetAttack(){
		return this.attack;
	}
	
	public float GetCover(){
		return this.cover;
	}
	
	public int GetOther(){
		return this.other;
	}
	
	public int GetTotal(){
		return this.total;
	}
	
	public void SetScan(int scan){
		this.scan = scan;
	}
	
	public void SetAttack(int attack){
		this.attack = attack;
	}
	
	public void SetCover(float cover){
		this.cover = cover;
	}
	
	public void SetOther(int other){
		this.other = other;
	}
	
	public void SetTotal(int total){
		this.total = total;
	}

}
