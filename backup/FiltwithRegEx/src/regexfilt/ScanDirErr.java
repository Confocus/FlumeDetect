package regexfilt;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import res.ResDetail;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ScanDirErr implements ErrorDes{
	/*private String ip;
	private int secs;
	private int sece;
	private int count;*/
	private int totalattack = 0;
	private String regex = 
			"\\[[a-zA-Z]{3}\\s[a-zA-Z]{3}\\s[0-9]{2}\\s"
			+ "([0-9]{2}):([0-9]{2}):([0-9]{2})\\s"
			+ "[0-9]{4}\\]\\s\\[error\\]\\s"
			+ "\\[client\\s([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\]\\s"
			+ "File does not exist:\\s[a-zA-Z]{1}:.+";
	
	public class ScanDirObj{
		private String ip;
		private int secs;
		private int sece;
		private int count;
		ScanDirObj(){
			ip = "";
			secs = 0;
			sece = 0;
			count = 0;
		}
	}
	
	static ArrayList<String> alScanDir = new ArrayList<String>();
	//static ArrayList<ScanDir> alScanDirObj = new ArrayList<ScanDir>();
	static Map<String, ScanDirObj> mpScanDirObj = new HashMap<String, ScanDirObj>();		
	
	
	
	/*ScanDirDes(){
		ip = "";
		secs = 0;
		sece = 0;
		count = 0;
	}
	
	@Override
	public void SetMember() {
		// TODO Auto-generated method stub
		
	}
	
	public void SetIp(String ip){
		this.ip = ip;
	}
	
	public void SetSecs(int secs){
		this.secs = secs;
	}
	
	public void SetSece(int sece){
		this.sece = sece;
	}
	
	public void SetCount(int c){
		this.count = c;
	}
	
	public String GetIp(){
		return ip;
	}
	
	public int GetSecs(){
		return secs;
	}
	
	public int GetSece(){
		return sece;
	}
	
	public int GetCount(){
		return count;
	}*/
	
	@Override
	public void ErrorDescription() {
		System.out.println("Scanning directory error.");
	}
	
	@Override
	public int Detecte(){
		int DetectionRes = 0;
		FileInputStream fis = null;
		BufferedReader br = null;
		int matchcount = 0;
		int secdur = 0;
		int secend = 0;
		//int totalattack = 0;
		
		try{
			//C:\Users\Henrry\Desktop\log_http_apache\segroup-error.log
			//C://Users//Henrry//Desktop//testfile2.txt
			fis = new FileInputStream("C://Users//Henrry//Desktop//log_http_apache//segroup-error.log");
			br = new BufferedReader(new InputStreamReader(fis));
			String str = null;  
			StringBuilder sec = new StringBuilder("");
			Pattern pattern = Pattern.compile(regex);
			//Matcher matcher = new Matcher();
				while((str = br.readLine()) != null){
					
					//System.out.println(str); 
					if(RegexMatch.match(regex, str)){
						this.totalattack++;
						sec.delete(0, sec.length());
						sec.append("");
						//如果匹配就提取需要的数据
						
						Matcher matcher = pattern.matcher(str);
						matcher.matches();
						//System.out.println(matcher.group());
						sec.append(matcher.group(1));
				    	sec.append(matcher.group(2));
				    	sec.append(matcher.group(3));
				    	secdur = Integer.valueOf(sec.toString());
		    			secdur = (secdur / 10000) * 3600 + ((secdur % 10000) / 100) * 60 + (secdur % 100);
				    	if(!mpScanDirObj.containsKey(matcher.group(4))){//以IP为键
				    		//alScanDir.add(matcher.group(4));
				    		ScanDirObj sd = new ScanDirObj();
				    		//sd.SetIp(matcher.group(4));
				    		sd.ip = matcher.group(4);
				    		
				    		if(sd.count == 0){
								sd.secs = secdur;
				    		}
				    		sd.count++;
				    		//sd.SetCount( + 1);
				    		sd.sece = secdur;
				    		mpScanDirObj.put(matcher.group(4), sd);
				    	}else{
				    		ScanDirObj sd = mpScanDirObj.get(matcher.group(4));
				    		/*secdur = Integer.valueOf(sec.toString());
			    			secdur = (secdur / 10000) * 3600 + ((secdur % 10000) / 100) * 60 + (secdur % 100);*/
				    		sd.sece = secdur;
				    		sd.count++;
				    		//sd.SetCount(sd.GetCount() + 1);
				    		mpScanDirObj.put(matcher.group(4), sd);
				    	}

				    	
					}
					
					//System.out.println(str); 
				}
				
				
				for (Map.Entry<String, ScanDirObj> entry : mpScanDirObj.entrySet())
				{
					int c = entry.getValue().count;
					int t = entry.getValue().sece - entry.getValue().secs;
					if(t < 0){
						t = t + 24 * 3600;
					}
					if(c > 10){//只提取了日志中大于10次的IP
						System.out.println("IP:" + entry.getKey() + " ScanCount:" + c);// + " IntervalTime:" + t
						//DetectionRes = true;
					}
					
		        }
				
		}
		catch(FileNotFoundException  ex){
			System.out.println("FileNotFoundException"); 
			ex.printStackTrace();
		}
		catch (IOException ex) {
			// TODO Auto-generated catch block
			System.out.println("IOException"); 
			ex.printStackTrace();
		}
		finally{
			try {
				br.close();
				fis.close();
				System.out.println("Total attack:" + this.totalattack); 
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}
		System.out.println("Level:" + WarnLevel());
		return WarnLevel();
	}

	@Override
	public int WarnLevel() {
		// TODO Auto-generated method stub
		if(this.totalattack > 0 & this.totalattack <= 5){
			return 1;
		}
		else if(this.totalattack <= 10){
			return 2;
		}
		else
		{
			return 3;
		}
	}

	@Override
	public ResDetail ReturnResult() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void StoreMySQL() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void ParseRecord(String record) {
		// TODO Auto-generated method stub
		
	}
	

}
