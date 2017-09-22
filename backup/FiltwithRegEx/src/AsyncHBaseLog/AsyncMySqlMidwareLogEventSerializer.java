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
    
    private int total;//�м����־��Ŀ����
    
    private int sqltotal;
    private int sqlinstotal;
    private int sftotal;
    private int sfinstotal;
    private int mwtype;
    private int risklevel;
    
    
    static public int instotal;//�ж�Ϊ���ֵ���Ŀ����
    static public int abntotal;
    static public int riskvalue;
    
    private int tmpsqltotal = 0;
    private int tmpsftotal = 0;
    private boolean bflag = false;//���û���жϳ����ֹ������Ž�����һ�ֹ�������ƥ��
    private boolean bsqlflag = false;
    private boolean bsfflag = false;
    

    /*Map<java.sql.Date, Integer> MapDailyTotal = new HashMap<java.sql.Date, Integer>();
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");*/

    //********************************�����������м������********************************
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
    
    //�ж�Ŀ¼�µ���־�Ƿ�Ϊ�м����־
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
    
    ////********************************�����������м������********************************
    
    //ƥ�䲢��ȡIP��������ʽ
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

     	//*******************������һ�ű�*******************
     	Info info=new Info();
     	//һ����¼�����Ͳ���ӵ����ݿ���
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
            
			//*******************�����ڶ��ű�*******************
		if(mwtype == 1){
			//���Դip
            String[] SplitRecord = content.split("\\s+");
            InfoParse infop = new InfoParse();
            infop.setDstip(SplitRecord[2]);
            //���Ŀ��IPtmp
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
            
            //���date
            
            java.sql.Date date = GeneralFunc.strToDate(SplitRecord[0]);
            infop.setDate(date);
            
            //���time
            infop.setTime(SplitRecord[1]);
            //���atype
            infop.setAType(1);//4�����м������
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
            //����Class.forName()����������������
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        String url = "jdbc:mysql://" + hostname + ":" + port + "/" + databaseName;
        //����DriverManager�����getConnection()���������һ��Connection����

        try {//��Ϊֻ�ܶ�һ�����ݿ����������hostname��user��password��ͬһ��
            conn = DriverManager.getConnection(url, user, password);
            conn.setAutoCommit(false);
            //����һ��Statement����
            //�ǵ��޸�����
            
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
        
        //int tmpsqltotal = 0;//�ж��Ƿ�������4
        /*int tmpsqltotal = 0;
        int tmpsftotal = 0;
        boolean bflag = false;//���û���жϳ����ֹ������Ž�����һ�ֹ�������ƥ��
    	boolean bsqlflag = false;
    	boolean bsfflag = false;*/
    	boolean bSubmit = false;//�Ƿ�ֻ��Ҫִ��������ύ
    	boolean bBlank = false;//�ж��ļ��ǲ��ǿ�
        //int psCount = 0;
        
    	Map<java.sql.Date, Integer> MapDailyTotal = new HashMap<java.sql.Date, Integer>();
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");
    	
        transaction.begin();
        try {//���账��Ķ����м����־
            for (int i = 0; i < batchSize; i++) {
                event = channel.take();
                //RiskLevel.biisstart = true;
                if (event != null) {//���¼����д���
                	RiskLevel.biisstart = true;
                	bBlank = true;
                	total++;//event �� body Ϊ   "exec tail$i , abel"
                    content = new String(event.getBody());
                    Matcher matcherIIS = patternIIS.matcher(content);
                    Matcher matcherApache = patternApache.matcher(content);
                    
                    //����daily��
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
                     		//Ԥ����
                     		if(RiskLevel.GetRiskLevel() < 3){
                     			RiskLevel.SetMidLevel();
                     		}
                     		sqltotal++;//��¼�ж��ٴ��쳣
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
             			sqlinstotal += 4;//��¼�ж��ٴ�������
             		}
             		else if( (tmpsqltotal > 4) && bsqlflag){
             			instotal++;
             			sqlinstotal++;
             		}
                    
                    if(bsqlflag)//��sql�������ҵ��˹ؼ���
                    {
                    	bsqlflag = false;
                    	//�ҵ������๥�����Ͱ�����������������Ϊ0
                    	tmpsftotal = 0;//˵��sf������������
                    	continue;
                    }else{
                    	tmpsqltotal = 0;//sql������������
                    }

                    for(String r : ScanFileAttack){
                    	
                    	Pattern pattern = Pattern.compile(r);
                     	Matcher matcher = pattern.matcher(content);
                     	if(matcher.find()){
                     		//Ԥ����
                     		if(RiskLevel.GetRiskLevel() < 3){
                     			RiskLevel.SetHighLevel();
                     		}
                     		sftotal++;//��¼�ж��ٴ��쳣
                     		abntotal++;//
                     		bsfflag = true;
                     		tmpsftotal++;                   		
                     		processMidware(content, iploc, infos, infops);                		
                     		break;
                     	}else{//����Ĵ���ÿ�ζ������У���֪��Ϊʲô��
                     		//tmpsftotal = 0;
                     		bsfflag = false;
                     		//tmpsqltotal = 0;//����û����sf��������Ҫ��tmpsqltotal��Ϊ0
                     		//tmpsftotal = 0;
                     	}
                    }
                    if( (tmpsftotal == 4) && bsfflag){
             			instotal += 4;//
             			sfinstotal += 4;//��¼�ж��ٴ�������
             		}
             		else if( (tmpsftotal > 4) && bsfflag){
             			instotal++;
             			sfinstotal++;
             		}
                    if(bsfflag){
                    	bsfflag = false;
                    	//�ҵ������๥�����Ͱ�����������������Ϊ0
                    	tmpsqltotal = 0;
                    }else{
                    	//��������������������Ϊ0
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
          if(RiskLevel.GetRiskLevel() == 2 && bSubmit){//����
        	  RiskLevel.mabnTotal +=  sqltotal;
        	  RiskLevel.minsTotal += sqlinstotal;
        	  
        	  riskvalue = RiskLevel.GetRiskValue();
          }
          RiskLevel.bsql = true;
           
          if(RiskLevel.GetRiskLevel() == 3 && bSubmit){//����
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
            //ͬ���ȴ�MS��־�������жϽ��
            //�������iis��־���٣��ڻ�û��ִ��ms��־����������¾��ܵ����������sleep���롣
            //���Ǻ����ĸĽ����ʹ��ͬ���������
            //���û��MSStart��־�����ߵȵ�MS��־�ϴ���ϣ��ٴ�����յȼ�
            if(!RiskLevel.bscanfile || !RiskLevel.bmsstart){//�ж��겢���Ǹ߼�������Ҫ�ȴ��ͼ�ȥͬ��
            	while(!(RiskLevel.biisend && RiskLevel.bmsend)){
                	////��ѭ���ȴ�ͬ�������á���֤�ж���в�ȼ������ݶ��Ѿ�����RiskLevel��
                }
            }

            /*sqlins = sqlins + Integer.toString(riskvalue) + ")";
            statementOther.execute(sqlins);*/
            //��ֻ֤����һ�����ݿ⣬�����м��������в�������
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
	                 		//*******************������һ�ű�*******************
	                 	Info info=new Info();
	                 		//һ����¼�����Ͳ���ӵ����ݿ���
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
	                        
	        				//*******************�����ڶ��ű�*******************
	        			if(mwtype == 1){
	        				//���Դip
	        				String[] SplitRecord = content.split("\\s+");
		                    InfoParse infop = new InfoParse();
		                    infop.setDstip(SplitRecord[2]);
		                    //���Ŀ��IPtmp
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
		                        
		                    //���date
		                        
		                    java.sql.Date date = GeneralFunc.strToDate(SplitRecord[0]);
		                    infop.setDate(date);
		                        
		                    //���time
		                    infop.setTime(SplitRecord[1]);
		                    //���atype
		                    infop.setAType(4);//4�����м������
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
    
    //ͬ���ȴ�MS��־�������жϽ��
    if(!RiskLevel.bscanfile){//�ж��겢���Ǹ߼�������Ҫ�ȴ��ͼ�ȥͬ��
    	while(!(RiskLevel.bsql && RiskLevel.bms)){
        	////��ѭ���ȴ�ͬ�������á���֤�ж���в�ȼ������ݶ��Ѿ�����RiskLevel��
        }
    }
    
    //��ֻ֤����һ�����ݿ⣬�����м��������в�������
    preparedStatementOther.clearBatch();
    preparedStatementOther.setInt(1, riskvalue);
    preparedStatementOther.addBatch();
    preparedStatementOther.executeBatch();
    preparedStatementOther.executeUpdate();
    
    conn.commit();
}*/