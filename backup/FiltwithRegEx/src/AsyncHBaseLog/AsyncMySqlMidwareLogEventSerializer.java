package AsyncHBaseLog;

import com.google.common.base.Preconditions;  
import com.google.common.base.Throwables;  
import com.google.common.collect.Lists;


import regexfilt.RecordDetect;
import regexfilt.RegexMatch;
import res.IPLocation;

import org.apache.flume.*;  
import org.apache.flume.conf.Configurable;  
import org.apache.flume.sink.AbstractSink;  
import org.slf4j.Logger;  
import org.slf4j.LoggerFactory;  
   
import java.sql.Connection;  
import java.sql.DriverManager;  
import java.sql.PreparedStatement;  
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;  

public class AsyncMySqlMidwareLogEventSerializer extends AbstractSink implements Configurable{

	private Logger LOG = LoggerFactory.getLogger(AsyncMySqlMidwareLogEventSerializer.class);
	private String hostname;
    private String port;
    private String databaseName;
    private String tableName;
    private String user;
    private String password;
    private PreparedStatement preparedStatementContent;
    private Connection conn;
    private int batchSize;
    
    private String TableNamePrase;
    private PreparedStatement preparedStatementPrase;

    private String TableNameMidware;
    private PreparedStatement preparedStatementInfo;
    
    private String TableDailyInfo;
    private PreparedStatement preparedStatementDaily;
    
    private String TableOther;
    private PreparedStatement preparedStatementOther;
    /*Statement statementOther;
    String sqlins = "insert into other values (1,";*/
        //" (risklevel) values (?)");
    
    private int total;//中间件日志条目总数
    
    private int sqltotal;
    private int sqlinstotal;
    private int sftotal;
    private int sfinstotal;
    private int mwtype;
    private int risklevel;
    
    
    static public int instotal;//判定为入侵的条目总数
    static public int abntotal;
    static public int riskvalue;
    
    private int tmpsqltotal = 0;
    private int tmpsftotal = 0;
    private boolean bflag = false;//如果没有判断出这种攻击，才进行下一轮攻击类型匹配
    private boolean bsqlflag = false;
    private boolean bsfflag = false;
    

    /*Map<java.sql.Date, Integer> MapDailyTotal = new HashMap<java.sql.Date, Integer>();
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");*/

    //********************************这两个算是中间件攻击********************************
    private String[] SqlAttack = {
    		".*select.*",
    		".*%20or%20.*",
    		".*\\+and\\+.*",
    		".*%20and%20.*",
    		".*%20like%20.*",
    		".*from.*",
    		".*where.*",
    		".*\".*",
    		".*\'.*"
    		};
    
    private String[] ScanFileAttack = {
    		".*ewebeditor.*",
    		".*fckeditor.*"
    };
    
    //判断目录下的日志是否为中间件日志
    static String iisregex = "([0-9]{4}-[0-9]{2}-[0-9]{2})\\s"
			+ "[0-9]{2}:[0-9]{2}:[0-9]{2}\\s"
			+ "(?:(?:W3SVC[0-9]+\\s)*)"
			+ "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\s"
			+ "(?:(?:POST)|(?:GET))\\s"
			+ "/.*";
    
    static String apacheregex = "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\s"
			+ "-\\s-\\s"
			+ "\\[([0-9]{4}-[0-9]{2}-[0-9]{2})\\s"
			+ "[0-9]{2}:[0-9]{2}:[0-9]{2}\\]\\s"
			+ "\"(?:(?:POST)|(?:GET))\\s"
			+ "http://.*";
    
    ////********************************这两个算是中间件攻击********************************
    
    //匹配并提取IP的正则表达式
    private String regexip = "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}";
    
	
	public AsyncMySqlMidwareLogEventSerializer() {  
		total = 0;
		instotal = 0;
		sqltotal = 0;
		sqlinstotal = 0;
		sftotal = 0;
		sfinstotal = 0;
		abntotal = 0;
		System.out.println("MysqlSink start...");
    }  
	
	private void processMidware(String content, IPLocation iploc,
			List<Info> infos, List<InfoParse> infops){
		String[] loc;
		String sloc = "0.0.0.0";
		Pattern patternip = Pattern.compile(regexip);

     	//*******************操作第一张表*******************
     	Info info=new Info();
     	//一条记录过长就不添加到数据库了
		if(content.length() < 10000){			
			info.setContent(content);
			infos.add(info);
		}
		else{
			content = content.substring(0, 9999);
			info.setContent(content);
			infos.add(info);
			//break;
		}
            
			//*******************操作第二张表*******************
		if(mwtype == 1){
			//添加源ip
            String[] SplitRecord = content.split("\\s+");
            InfoParse infop = new InfoParse();
            infop.setDstip(SplitRecord[2]);
            //添加目标IPtmp
            Matcher matcherip = patternip.matcher(SplitRecord[8]);
            if(matcherip.find()){
            	infop.setSrcip(SplitRecord[8]);
            	sloc = SplitRecord[8];
            }
            else{
            	matcherip = patternip.matcher(SplitRecord[9]);
            	if(matcherip.find()){
            		infop.setSrcip(SplitRecord[9]);
            		sloc = SplitRecord[9];
            	}else{
            		infop.setSrcip("Unknown");
            	}
            }
            
            //添加date
            
            java.sql.Date date = GeneralFunc.strToDate(SplitRecord[0]);
            infop.setDate(date);
            
            //添加time
            infop.setTime(SplitRecord[1]);
            //添加atype
            infop.setAType(1);//4代表中间件攻击
            //location
            if(!sloc.equals("0.0.0.0")){
            	loc = iploc.find(sloc);
            	infop.setSrcloc(loc[2]);
            }
            else{
            	infop.setSrcloc("Unknown");
            }
            
            sloc = "0.0.0.0";
            infop.setDstloc("Local");
            
            infops.add(infop);
            
            //break;
		}else if(mwtype == 2){
			String[] SplitRecord = content.split("\\s+");
            InfoParse infop = new InfoParse();
            infop.setDstip(SplitRecord[0]);
            infop.setSrcip("Unknown");
            infop.setSrcloc("Unknown");
            infop.setAType(1);
            SplitRecord[3] = SplitRecord[3].substring(1, SplitRecord[3].length());
            java.sql.Date date = GeneralFunc.strToDate(SplitRecord[3]);
            infop.setDate(date);
            
            
            
            infop.setDstloc("Local");
            SplitRecord[4] = SplitRecord[4].substring(0, SplitRecord[4].length() - 1);
            infop.setTime(SplitRecord[4]);
            infops.add(infop);
		}

	}
	
	public void start() {
        super.start();
        try {
            //调用Class.forName()方法加载驱动程序
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        String url = "jdbc:mysql://" + hostname + ":" + port + "/" + databaseName;
        //调用DriverManager对象的getConnection()方法，获得一个Connection对象

        try {//因为只能对一个数据库操作，所以hostname、user、password是同一个
            conn = DriverManager.getConnection(url, user, password);
            conn.setAutoCommit(false);
            //创建一个Statement对象
            //记得修改这里
            
           // statementOther = conn.createStatement();
            
            preparedStatementOther = conn.prepareStatement("insert into " + TableOther +
                    " (risklevel) values (?)");
           
            preparedStatementDaily = conn.prepareStatement("insert into " + TableDailyInfo +
                    " (date,total) values (?,?)");
            preparedStatementContent = conn.prepareStatement("insert into " + tableName +
                    " (content,sorttime) values (?,?)");
            preparedStatementPrase = conn.prepareStatement("insert into " + TableNamePrase +
                    " (date,time,srcip,dstip,attacktype,srcloc,dstloc) values (?, ?, ?, ?, ?, ?, ?)");
            preparedStatementInfo = conn.prepareStatement("insert into " + TableNameMidware +
                    " (scan,attack,cover,other,total) values (?, ?, ?, ?, ?)");

        } catch (SQLException e) {
            e.printStackTrace();
            System.exit(1);
        }

    }
	
	public void stop() {
        super.stop();
        if (preparedStatementContent != null) {
            try {
            	preparedStatementContent.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        
        if (preparedStatementDaily != null) {
            try {
            	preparedStatementDaily.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        
        if (preparedStatementOther != null) {
            try {
            	preparedStatementOther.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        
        if (preparedStatementPrase != null) {
            try {
            	preparedStatementPrase.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        
        if (preparedStatementInfo != null) {
            try {
            	preparedStatementPrase.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }

        if (conn != null) {
            try {
                conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
	
	@Override
	public Status process() throws EventDeliveryException {
		// TODO Auto-generated method stub
		
		Status result = Status.READY;
        Channel channel = getChannel();
        Transaction transaction = channel.getTransaction();
        Event event;
        
        IPLocation iploc = new IPLocation();
		IPLocation.load("//tool//mydata4vipday2.dat");
		
		String content;
		
		List<Info> infos = Lists.newArrayList();
	    List<InfoParse> infops = Lists.newArrayList();
	    List<DailyInfo> dinfos = Lists.newArrayList();
		
		Pattern patternip = Pattern.compile(regexip);
		Pattern patternIIS = Pattern.compile(iisregex);
        Pattern patternApache = Pattern.compile(apacheregex);
        
        //int tmpsqltotal = 0;//判断是否连续有4
        /*int tmpsqltotal = 0;
        int tmpsftotal = 0;
        boolean bflag = false;//如果没有判断出这种攻击，才进行下一轮攻击类型匹配
    	boolean bsqlflag = false;
    	boolean bsfflag = false;*/
    	boolean bSubmit = false;//是否只需要执行下面的提交
    	boolean bBlank = false;//判断文件是不是空
        //int psCount = 0;
        
    	Map<java.sql.Date, Integer> MapDailyTotal = new HashMap<java.sql.Date, Integer>();
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");
    	
        transaction.begin();
        try {//假设处理的都是中间件日志
            for (int i = 0; i < batchSize; i++) {
                event = channel.take();
                //RiskLevel.biisstart = true;
                if (event != null) {//对事件进行处理
                	RiskLevel.biisstart = true;
                	bBlank = true;
                	total++;//event 的 body 为   "exec tail$i , abel"
                    content = new String(event.getBody());
                    Matcher matcherIIS = patternIIS.matcher(content);
                    Matcher matcherApache = patternApache.matcher(content);
                    
                    //处理daily表
                    java.sql.Date dailyinfo;
                    if(matcherIIS.find()){
                    	mwtype = 1;
                    	dailyinfo = GeneralFunc.strToDate(matcherIIS.group(1));
                    }else if(matcherApache.find()){
                    	mwtype = 2;
                    	dailyinfo = GeneralFunc.strToDate(matcherApache.group(1));
                	}else{
                		continue;
                	}
                    
                    if(!MapDailyTotal.containsKey(dailyinfo)){
                    	MapDailyTotal.put(dailyinfo, 1);
                    }else{
                    	Integer itotal = MapDailyTotal.get(dailyinfo) + 1;
                    	MapDailyTotal.put(dailyinfo, itotal);
                    }
                    
                                     
                    for(String r : SqlAttack){                    	
                    	Pattern pattern = Pattern.compile(r);
                     	Matcher matcher = pattern.matcher(content);
                     	if(matcher.find()){
                     		//预处理
                     		if(RiskLevel.GetRiskLevel() < 3){
                     			RiskLevel.SetMidLevel();
                     		}
                     		sqltotal++;//记录有多少次异常
                     		abntotal++;//
                     		bsqlflag = true;
                     		tmpsqltotal++;
                     		
                     		processMidware(content, iploc, infos, infops);
                     		break;
                     	}
                     	else{
                     		//tmpsqltotal = 0;
                     		bsqlflag = false;
                     	}
                    }
                    
                    if( (tmpsqltotal == 4) && bsqlflag){
             			instotal += 4;//
             			sqlinstotal += 4;//记录有多少次是入侵
             		}
             		else if( (tmpsqltotal > 4) && bsqlflag){
             			instotal++;
             			sqlinstotal++;
             		}
                    
                    if(bsqlflag)//从sql攻击中找到了关键字
                    {
                    	bsqlflag = false;
                    	//找到了这类攻击，就把其它的连续次数置为0
                    	tmpsftotal = 0;//说明sf攻击不连续了
                    	continue;
                    }else{
                    	tmpsqltotal = 0;//sql攻击不连续了
                    }

                    for(String r : ScanFileAttack){
                    	
                    	Pattern pattern = Pattern.compile(r);
                     	Matcher matcher = pattern.matcher(content);
                     	if(matcher.find()){
                     		//预处理
                     		if(RiskLevel.GetRiskLevel() < 3){
                     			RiskLevel.SetHighLevel();
                     		}
                     		sftotal++;//记录有多少次异常
                     		abntotal++;//
                     		bsfflag = true;
                     		tmpsftotal++;                   		
                     		processMidware(content, iploc, infos, infops);                		
                     		break;
                     	}else{//这里的代码每次都会运行，不知道为什么？
                     		//tmpsftotal = 0;
                     		bsfflag = false;
                     		//tmpsqltotal = 0;//发现没发现sf攻击，都要给tmpsqltotal置为0
                     		//tmpsftotal = 0;
                     	}
                    }
                    if( (tmpsftotal == 4) && bsfflag){
             			instotal += 4;//
             			sfinstotal += 4;//记录有多少次是入侵
             		}
             		else if( (tmpsftotal > 4) && bsfflag){
             			instotal++;
             			sfinstotal++;
             		}
                    if(bsfflag){
                    	bsfflag = false;
                    	//找到了这类攻击，就把其它的连续次数置为0
                    	tmpsqltotal = 0;
                    }else{
                    	//否则把自身的连续次数置为0
                    	tmpsftotal = 0;
                    }
                    
            } else {
            		bSubmit = true;
            		RiskLevel.biisend = true;
                    result = Status.BACKOFF;
                    break;
                }
         }
            //LOG.debug("afterLoop........");
          if(RiskLevel.GetRiskLevel() == 2 && bSubmit){//处于
        	  RiskLevel.mabnTotal +=  sqltotal;
        	  RiskLevel.minsTotal += sqlinstotal;
        	  
        	  riskvalue = RiskLevel.GetRiskValue();
          }
          RiskLevel.bsql = true;
           
          if(RiskLevel.GetRiskLevel() == 3 && bSubmit){//处于
        	  RiskLevel.habnTotal +=  sftotal;
        	  RiskLevel.hinsTotal += sfinstotal;
        	  
        	  riskvalue = RiskLevel.GetRiskValue();
          }
          RiskLevel.bscanfile = true;
         
          
        for (Map.Entry<java.sql.Date, Integer> entry : MapDailyTotal.entrySet()){
        	DailyInfo df = new DailyInfo();
        	df.SetDate(entry.getKey());
        	df.SetTotal(entry.getValue());
        	dinfos.add(df);
        }
            
        if (infos.size() > 0) {
        	//bSubmit = true;
        	preparedStatementContent.clearBatch();
            for (Info temp : infos) {
            	preparedStatementContent.setString(1, temp.getContent());
            	preparedStatementContent.setInt(2, temp.getSorttime());
            	preparedStatementContent.addBatch();
            }
            preparedStatementContent.executeBatch();
            conn.commit();
        }
        
        if (infops.size() > 0) {
        	
        	preparedStatementPrase.clearBatch();
            for (InfoParse temp : infops) {
            	preparedStatementPrase.setDate(1, temp.getDate());
            	preparedStatementPrase.setString(2, temp.getTime());
            	preparedStatementPrase.setString(3, temp.getSrcip());
            	preparedStatementPrase.setString(4, temp.getDstip());
            	preparedStatementPrase.setInt(5, temp.getAType());
            	preparedStatementPrase.setString(6, temp.getSrcloc());
            	preparedStatementPrase.setString(7, temp.getDstloc());
            	preparedStatementPrase.addBatch();
            }
            preparedStatementPrase.executeBatch();
            conn.commit();
        }
        
        if(dinfos.size() > 0){
        	preparedStatementDaily.clearBatch();
        	for(DailyInfo dinfo : dinfos){//46272
        		preparedStatementDaily.setDate(1, (java.sql.Date) dinfo.GetDate());
        		preparedStatementDaily.setInt(2, dinfo.GetTotal());
        		preparedStatementDaily.addBatch();
        	}
        	 preparedStatementDaily.executeBatch();
             conn.commit();
        }
       
        if(bSubmit && bBlank){
        	preparedStatementInfo.clearBatch();
            preparedStatementInfo.setInt(1, abntotal - instotal);
            preparedStatementInfo.setInt(2, instotal);
            preparedStatementInfo.setFloat(3, 0);
            preparedStatementInfo.setInt(4, 0);
            preparedStatementInfo.setInt(5, abntotal);
            preparedStatementInfo.addBatch();
            preparedStatementInfo.executeBatch();
            conn.commit();
            //preparedStatementInfo.executeUpdate();
            //同步等待MS日志传来的判断结果
            //如果担心iis日志极少，在还没有执行ms日志分析的情况下就跑到了这里。可以sleep几秒。
            //但是后续的改进最好使用同步互斥机制
            //如果没有MSStart日志，或者等到MS日志上传完毕，再处理风险等级
            if(!RiskLevel.bscanfile || !RiskLevel.bmsstart){//判断完并不是高级，才需要等待低级去同步
            	while(!(RiskLevel.biisend && RiskLevel.bmsend)){
                	////起到循环等待同步的作用。保证中度威胁等级的数据都已经传入RiskLevel类
                }
            }

            /*sqlins = sqlins + Integer.toString(riskvalue) + ")";
            statementOther.execute(sqlins);*/
            //保证只操作一次数据库，就在中间件这个类中操作即可
            preparedStatementOther.clearBatch();
            preparedStatementOther.setInt(1, riskvalue);
            preparedStatementOther.addBatch();
            preparedStatementOther.executeBatch();
            //preparedStatementOther.execute();
            //preparedStatementOther.executeUpdate();

            conn.commit();
        }
        
        
        transaction.commit();
    } catch (Exception e) {
            try {
                transaction.rollback();
            } catch (Exception e2) {
                LOG.error("Exception in rollback. Rollback might not have been" +
                        "successful.", e2);
            }
            LOG.error("Failed to commit transaction." +
                    "Transaction rolled back.", e);
            Throwables.propagate(e);
        } finally {
            transaction.close();
        }
        return result;
	}

	
	
	@Override
	public void configure(Context context) {
		// TODO Auto-generated method stub
		hostname = context.getString("hostname");
        Preconditions.checkNotNull(hostname, "hostname must be set!!");
        port = context.getString("port");
        Preconditions.checkNotNull(port, "port must be set!!");
        databaseName = context.getString("databaseName");
        Preconditions.checkNotNull(databaseName, "databaseName must be set!!");
        tableName = context.getString("tableName");
        Preconditions.checkNotNull(tableName, "tableName must be set!!");
        user = context.getString("user");
        Preconditions.checkNotNull(user, "user must be set!!");
        password = context.getString("password");
        Preconditions.checkNotNull(password, "password must be set!!");
        batchSize = context.getInteger("batchSize", 100);
        Preconditions.checkNotNull(batchSize > 0, "batchSize must be a positive number!!");
        
        TableNamePrase = "ids_an_data";
        TableNameMidware = "webtotalinfo";
        TableDailyInfo = "dateinfo";
        TableOther = "other";
	}

}

/*for(String r : ScanFileAttack){
                   	
                   	if(RiskLevel.GetRiskLevel() < 3){
                   		RiskLevel.SetHighLevel();
                   	}
                   	
	                Pattern pattern = Pattern.compile(r);
	                Matcher matcher = pattern.matcher(content);
	                if(matcher.find()){
	                	tmpsftotal++;
	                 	if(tmpsftotal == 4){
	                 		instotal += 4;
	                 		sfinstotal += 4;
	                 	}
	                 	else if(tmpsftotal > 4){
	                 		instotal++;
	                 		sfinstotal ++;
	                 	}
	                 		//*******************操作第一张表*******************
	                 	Info info=new Info();
	                 		//一条记录过长就不添加到数据库了
	        			if(content.length() < 10000){
	        					
	        				info.setContent(content);
	        				infos.add(info);
	        			}
	        			else{
	        				content = content.substring(0, 9999);
	        				info.setContent(content);
	        				infos.add(info);
	        				break;
	        			}
	                        
	        				//*******************操作第二张表*******************
	        			if(mwtype == 1){
	        				//添加源ip
	        				String[] SplitRecord = content.split("\\s+");
		                    InfoParse infop = new InfoParse();
		                    infop.setDstip(SplitRecord[2]);
		                    //添加目标IPtmp
		                    Matcher matcherip = patternip.matcher(SplitRecord[8]);
		                    if(matcherip.find()){
		                        infop.setSrcip(SplitRecord[8]);
		                        sloc = SplitRecord[8];
		                    }
		                    else{
		                        matcherip = patternip.matcher(SplitRecord[9]);
		                        if(matcherip.find()){
		                        	infop.setSrcip(SplitRecord[9]);
		                        	sloc = SplitRecord[9];
		                        }else{
		                        	infop.setSrcip("Unknown");
		                        }
		                    }
		                        
		                    //添加date
		                        
		                    java.sql.Date date = GeneralFunc.strToDate(SplitRecord[0]);
		                    infop.setDate(date);
		                        
		                    //添加time
		                    infop.setTime(SplitRecord[1]);
		                    //添加atype
		                    infop.setAType(4);//4代表中间件攻击
		                    //location
		                    if(!sloc.equals("0.0.0.0")){
		                        loc = iploc.find(sloc);
		                        infop.setSrcloc(loc[2]);
		                    }
		                    else{
		                        infop.setSrcloc("Unknown");
		                    }
		                        
		                    sloc = "0.0.0.0";
		                    infop.setDstloc("Local");
		                        
		                    infops.add(infop);
		                        
		                    break;
	        			}else if(mwtype == 2){
	        				String[] SplitRecord = content.split("\\s+");
		                    InfoParse infop = new InfoParse();
		                    infop.setDstip(SplitRecord[0]);
		                    infop.setSrcip("Unknown");
		                    infop.setSrcloc("Unknown");
		                    infop.setAType(4);
		                    SplitRecord[3] = SplitRecord[3].substring(1, SplitRecord[3].length());
		                    java.sql.Date date = GeneralFunc.strToDate(SplitRecord[3]);
		                    infop.setDate(date);
		                        
		                    infop.setDstloc("Local");
		                    SplitRecord[4] = SplitRecord[4].substring(0, SplitRecord[4].length() - 1);
		                    infop.setTime(SplitRecord[4]);
		                    infops.add(infop);
	        			}
	                       
	        		}
	                else{
	                	tmpsftotal = 0;
	                }

	            }*/


/*if (infos.size() > 0) {
	preparedStatementContent.clearBatch();
    for (Info temp : infos) {
    	preparedStatementContent.setString(1, temp.getContent());
    	preparedStatementContent.setInt(2, temp.getSorttime());
    	preparedStatementContent.addBatch();
    }
    preparedStatementContent.executeBatch();
    if (infops.size() > 0) {
    	preparedStatementPrase.clearBatch();
        for (InfoParse temp : infops) {
        	preparedStatementPrase.setDate(1, temp.getDate());
        	preparedStatementPrase.setString(2, temp.getTime());
        	preparedStatementPrase.setString(3, temp.getSrcip());
        	preparedStatementPrase.setString(4, temp.getDstip());
        	preparedStatementPrase.setInt(5, temp.getAType());
        	preparedStatementPrase.setString(6, temp.getSrcloc());
        	preparedStatementPrase.setString(7, temp.getDstloc());
        	preparedStatementPrase.addBatch();
        }
    }
    preparedStatementPrase.executeBatch();

    
    if(dinfos.size() > 0){
    	preparedStatementDaily.clearBatch();
    	for(DailyInfo dinfo : dinfos){
    		preparedStatementDaily.setDate(1, (java.sql.Date) dinfo.GetDate());
    		preparedStatementDaily.setInt(2, dinfo.GetTotal());
    		preparedStatementDaily.addBatch();
    	}
    }
    preparedStatementDaily.executeBatch();
    
    preparedStatementInfo.clearBatch();
    preparedStatementInfo.setInt(1, abntotal - instotal);
    preparedStatementInfo.setInt(2, instotal);
    preparedStatementInfo.setFloat(3, 0);
    preparedStatementInfo.setInt(4, 0);
    preparedStatementInfo.setInt(5, total);
    preparedStatementInfo.addBatch();
    preparedStatementInfo.executeBatch();
    
    //同步等待MS日志传来的判断结果
    if(!RiskLevel.bscanfile){//判断完并不是高级，才需要等待低级去同步
    	while(!(RiskLevel.bsql && RiskLevel.bms)){
        	////起到循环等待同步的作用。保证中度威胁等级的数据都已经传入RiskLevel类
        }
    }
    
    //保证只操作一次数据库，就在中间件这个类中操作即可
    preparedStatementOther.clearBatch();
    preparedStatementOther.setInt(1, riskvalue);
    preparedStatementOther.addBatch();
    preparedStatementOther.executeBatch();
    preparedStatementOther.executeUpdate();
    
    conn.commit();
}*/