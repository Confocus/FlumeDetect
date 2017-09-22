package regexfilt;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
//import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

//import regexfilt.ScanDirErr.ScanDirObj;
import res.MidwareResDetail;
import res.ResDetail;

//Completed!

public class MidwareErr implements ErrorDes{
	//private String regex = ".*select.*";
	private int ScanCount = 0;
	private int totalattack = 0;
	//参看sql注入语句大全
	//正则表达式中是否可以嵌套正则表达式以避免冗长？
	private String MidwareRegex = "([0-9]{4}-[0-9]{2}-[0-9]{2})\\s"
			+ "([0-9]{2}:[0-9]{2}:[0-9]{2})\\s"
			+ "([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\s"
			+ "(?:(?:GET)|(?:POST))\\s"//"?:"表示不捕获分组获取的内容
			+ "/[a-zA-Z0-9_\\-\\.\\s\\(\\)\\=]*";
	///*\\s-\\s[0-9]{1,3}\\s-\\s";*/
			/*+ "([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})";*/
	/*"/\\s-\\s[0-9]{1,3}\\s-\\s"
			+ "([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\s";*/
	//后续需要改进匹配规则
	private String[] SqlAttacks = {
			".*select.*", ".*%20or.%20*", ".*\\+and\\+.*",
			".*from.*", ".*%20where%20.*",
			".*%20like%20.*", ".*\'.*", ".*\".*", 
			".*%20union%20.*", ".*%20xor%20.*", ".*%20order%20by%20.*", 
			".*version().*", 
			".*database().*", ".*%20limit%20.*", 
			".*%20exists%20.*", 
			".*%20group_concat.*", //SELECT group_concat(town) FROM
			".*%20count.*",//select count(*) from admin
			".*sysobjects%20.*",//select top 1 name from bbs.dbo.sysobjects where
			//".*%.*", ".*%20top%20.*", 
			".*%20asc.*",//from Admin where Asc(mid(pass,5,1))=51) 
			".*mid.*", ".*unicode.*", 
			".*%20substring.*", 
			".*exec%20.*", 
			".*master\\\\\\\\.dbo.*", 
			".*@@version.*", ".*%20len.*"
			};
	//下边的匹配规则暂时可以先不要
	private String[] XSSAttacks = {
			/*".*<script>.*", ".*</script>.*", ".*alert.*",
			".*javascript:alert.*", ".*<img src=>.*", ".*<iframe>.*", ".*</iframe>.*",
			".*alert\\(document.cookie\\).*"*/
			};
	private String[] Struts2Attacks = {
			/*".*xwork.*", ".*getRuntime\\(\\).*", ".*exec\\(%23cmd\\).*", ".*cmd\\.exe.*", 
			".*java\\.lang\\.Runtime.*"*/
			};
	private String[] ScandirAttacks = {
			/*".*ewebeditor.*", ".*fckeditor.*", ".*webeditor.*", 
			".*upload\\.asp.*", ".*upload\\.aspx.*", ".*upload\\.php.*", ".*upload\\.jsp.*", ".*upload_file\\.asp.*", 
			".*upload_file\\.aspx.*", ".*upload_file\\.php.*", ".*upload_file\\.jsp.*", ".*admin.*", 0
			".*manager.*", ".*manage.*"*/
			};
	private String[] ReadFileAttacks = {
			//".*/etc/passwd.*", ".*/etc/shadow.*"
			};
	private String[] DownloadAttacks = {
			/*".*file=\\.\\./\\.\\./.*", ".*filename=\\.\\./.*"*/
			};
	private String[] WebshellAttacks = {
			/*".*diy\\.asp.*",".*diy\\.cer.*", ".*\\.asa.*", ".*\\.asa;\\..*",
			".*webshell\\.asp.*",  ".*webshell\\.aspx.*", ".*webshell\\.php.*", ".*webshell\\.jsp.*", 
			".*shell\\.asp.*", ".*shell\\.aspx.*", ".*shell\\.php.*", ".*shell\\.jsp.*", ".*phpsky\\.php.*",
			".*pwn\\.jsp.*", ".*pwn\\.jsx.*", ".*one8\\.jsp.*", ".*jspspy\\.jsp.*", ".*JFloer\\.jsp.*",
			".*asp;\\.jpg.*", ".*asp;\\..*", ".*aspx;\\.jpg.*", ".*aspx;\\..*", ".*aspxspy\\.aspx.*",
			".*aspspy\\.asp.*", ".*phpspy\\.php.*"*/
			};

	
	public boolean DetectRecord(String str){
		//Pattern pattern = Pattern.compile(r);
		boolean flag = false;
		for(String r : SqlAttacks){
			Pattern pattern = Pattern.compile(r);
			if(RegexMatch.match(r, str)){
				//System.out.println(str);
				flag = true;
				break;
			}
		}
		if(flag){
			return flag;
		}
		for(String r : XSSAttacks){
			Pattern pattern = Pattern.compile(r);
			if(RegexMatch.match(r, str)){
				flag = true;
				break;
			}
		}
		if(flag){
			return flag;
		}
		for(String r : Struts2Attacks){
			Pattern pattern = Pattern.compile(r);
			if(RegexMatch.match(r, str)){
				flag = true;
				
				break;
			}
		}
		if(flag){
			return flag;
		}
		for(String r : ScandirAttacks){
			Pattern pattern = Pattern.compile(r);
			if(RegexMatch.match(r, str)){
				flag = true;
				break;
			}
		}
		if(flag){
			return flag;
		}
		for(String r : ReadFileAttacks){
			Pattern pattern = Pattern.compile(r);
			if(RegexMatch.match(r, str)){
				flag = true;
				break;
			}
		}
		if(flag){
			return flag;
		}
		for(String r : DownloadAttacks){
			Pattern pattern = Pattern.compile(r);
			if(RegexMatch.match(r, str)){
				flag = true;
				break;
			}
		}
		if(flag){
			return flag;
		}
		for(String r : WebshellAttacks){
			Pattern pattern = Pattern.compile(r);
			if(RegexMatch.match(r, str)){
				flag = true;
				break;
			}
		}
		return flag;
	}
	
	@Override
	public void ErrorDescription() {
		// TODO Auto-generated method stub
		System.out.println("Middleware error.");
		
	}

	@Override
	public int Detecte() {
		boolean DetectionRes = false;
		FileInputStream fis = null;
		BufferedReader br = null;
		boolean flag = false;
		//int totalattack = 0;
		//String r = "";
		
		try{
			//C:\Users\Henrry\Desktop\log_http_apache\segroup-error.log
			//C://Users//Henrry//Desktop//testfile2.txt
			fis = new FileInputStream("C://Users//Henrry//Desktop//select.txt");
			br = new BufferedReader(new InputStreamReader(fis));
			String str = null;  
			//StringBuilder sec = new StringBuilder("");
			//Pattern pattern = Pattern.compile(regex);
			System.out.println("Running...");
			//Matcher matcher = new Matcher();
				while((str = br.readLine()) != null){//读入每一行然后匹配
					//System.out.println(str);
					//DetectRecord(str);
					flag = false;
					ScanCount++;
					ParseRecord(str);//test code
					//System.out.println(str); 
					//针对每一条记录去匹配一遍关键字
					for(String r : SqlAttacks){
						Pattern pattern = Pattern.compile(r);
						if(RegexMatch.match(r, str)){
							flag = true;
							this.totalattack++;
							//System.out.println(r + "_Suspected SQL attack:" + str);
							break;
						}
					}
					
					if(flag){
						continue;
					}
					for(String r : XSSAttacks){
						Pattern pattern = Pattern.compile(r);
						if(RegexMatch.match(r, str)){
							flag = true;
							this.totalattack++;
							//System.out.println(r + "_Suspected XSS attack:" + str);
							break;
						}
					}
					if(flag){
						continue;
					}
					for(String r : Struts2Attacks){
						Pattern pattern = Pattern.compile(r);
						if(RegexMatch.match(r, str)){
							flag = true;
							this.totalattack++;
							//System.out.println(r + "_Suspected Structs2 attack:" + str);
							break;
						}
					}
					if(flag){
						continue;
					}
					for(String r : ScandirAttacks){
						Pattern pattern = Pattern.compile(r);
						if(RegexMatch.match(r, str)){
							flag = true;
							this.totalattack++;
							//System.out.println(r + "_Suspected scanning directory attack:" + str);
							break;
						}
					}
					if(flag){
						continue;
					}
					for(String r : ReadFileAttacks){
						Pattern pattern = Pattern.compile(r);
						if(RegexMatch.match(r, str)){
							flag = true;
							this.totalattack++;
							//System.out.println(r + "_Suspected reading any file attack:" + str);
							break;
						}
					}
					if(flag){
						continue;
					}
					for(String r : DownloadAttacks){
						Pattern pattern = Pattern.compile(r);
						if(RegexMatch.match(r, str)){
							flag = true;
							this.totalattack++;
							//System.out.println(r + "_Suspected downloading any file attack:" + str);
							break;
						}
					}
					if(flag){
						continue;
					}
					for(String r : WebshellAttacks){
						Pattern pattern = Pattern.compile(r);
						if(RegexMatch.match(r, str)){
							flag = true;
							this.totalattack++;
							//System.out.println(r + "_Suspected webshell attack:" + str);
							break;
						}
					}
					//System.out.println(str); 
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
		MidwareResDetail mrd = (MidwareResDetail)ReturnResult();
		System.out.println("Scan items:" + mrd.Getsc());
		System.out.println("Intrusion items:" + mrd.Getic());
		
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
		MidwareResDetail mrd = new MidwareResDetail();
		
		mrd.Setsc(this.ScanCount);
		mrd.Setic(this.totalattack);
		mrd.Setcc(0);
		mrd.Setoc(0);
		
		return mrd;
	}

	@Override
	public void StoreMySQL() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void ParseRecord(String record) {
		// TODO Auto-generated method stub
		Pattern pattern = Pattern.compile(MidwareRegex);
		
		if(RegexMatch.match(MidwareRegex, record)){
			Matcher matcher = pattern.matcher(record);
			matcher.matches();
			System.out.println(matcher.group(1));
			/*System.out.println(matcher.group(2));
			System.out.println(matcher.group(3));
			System.out.println(matcher.group(4));*///谨防errorIndexOutOfBoundsException
		}
	}

}
