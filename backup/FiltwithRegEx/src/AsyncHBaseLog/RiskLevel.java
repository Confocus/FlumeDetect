package AsyncHBaseLog;

public class RiskLevel {
	/*private boolean bWebAttack; //low level
	private boolean bSqlAttack; //middle level
	private boolean bMSAttack; //middle level
	private boolean bScanFileAttack; //high level
*/	
	
	private static boolean bLowLevel;
	private static boolean bMidLevel;
	private static boolean bHighLevel;
	
	public static int labnTotal;//abnormal total
	public static int linsTotal;//attack total
	
	public static int mabnTotal;//abnormal total
	public static int minsTotal;
	
	public static int habnTotal;//abnormal total
	public static int hinsTotal;
	
	//判断是否已经扫描过了这个类型的日志
	public static boolean bsql;//m
	public static boolean bms;//m
	public static boolean bscanfile;//h
	
	public static boolean biisstart;//sql中间件日志开始
	public static boolean biisend;
	public static boolean bmsstart;//数据库日志开始
	public static boolean bmsend;
	
	RiskLevel(){
		bLowLevel = false;
		bMidLevel = false;
		bHighLevel = false;
		labnTotal = 0;
		linsTotal = 0;
		mabnTotal = 0;
		minsTotal = 0;
		habnTotal = 0;
		hinsTotal = 0;
		bsql = false;
		bms = false;
		bscanfile = false;
		
		biisstart = false;
		biisend = false;
		bmsstart = false;
		bmsend = false;
	}
	
	public static void SetLowLevel(){
		bLowLevel = true;
	}
	
	public static void SetMidLevel(){
		bMidLevel = true;
	}
	
	public static void SetHighLevel(){
		bHighLevel = true;
	}
	
	public static int GetRiskLevel(){
		if(bHighLevel){
			return 3;
		}else if(bMidLevel){
			return 2;
		}else if(bLowLevel){
			return 1;
		}else{
			return 0;
		}
	}
	
	public static int GetRiskValue(){
		if(bHighLevel){
			return (int)(70 + 30 * (float)hinsTotal / (float)habnTotal);
			//return hinsTotal;
		}else if(bMidLevel){
			return (int)(30 + 40 * (float)minsTotal / (float)mabnTotal);
			
		}else if(bLowLevel){
			return (int)(0 + 30 * (float)linsTotal / (float)labnTotal);
			
		}else{
			return 0;
		}
		//return 1;
	}
}
