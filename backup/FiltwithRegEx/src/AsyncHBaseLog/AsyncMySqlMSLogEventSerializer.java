package AsyncHBaseLog;

import com.google.common.base.Preconditions;  
import com.google.common.base.Throwables;  
import com.google.common.collect.Lists;

//import regexfilt.MidwareErr;
import regexfilt.RecordDetect;
import regexfilt.RegexMatch;
import res.IPLocation;

import org.apache.flume.*;  
import org.apache.flume.conf.Configurable;  
import org.apache.flume.sink.AbstractSink;  
import org.slf4j.Logger;  
import org.slf4j.LoggerFactory;  
   
import java.sql.Connection;
import java.sql.Date;
//import java.sql.Date;
import java.sql.DriverManager;  
import java.sql.PreparedStatement;  
import java.sql.SQLException;
import java.text.SimpleDateFormat;
//import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;  

public class AsyncMySqlMSLogEventSerializer extends AbstractSink implements Configurable{

	private Logger LOG = LoggerFactory.getLogger(AsyncMySqlMSLogEventSerializer.class);
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

    private String TableNameMS;
    private PreparedStatement preparedStatementInfo;
    
    private String TableDailyInfo;
    private PreparedStatement preparedStatementDaily;
    
    private String TableOther;
    private PreparedStatement preparedStatementOther;
    
    private int total;
    private int mstotal;
    private int msinstotal;

    static public int instotal;
    static public int abntotal;
    static public int riskvalue;
    
    private boolean bmsflag;
    
    ////********************************��в�ȼ��Ǵ����������������жϵ�********************************
    
    private String[] MSAttack = {
    		".*Login\\sfailed\\sfor\\suser\\s\'sa\'.*",
    		".*xp_cmdshell.*",
			".*xp_regenumvalues.*",
			".*xp_regwrite.*",
			".*xplog70.dll.*",
			".*sp_oacreate.*"
    };
    
    private String regexip = "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}";
    static String msregex = "([0-9]{4}-[0-9]{2}-[0-9]{2})\\s"
			+ "[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{2}\\s"
			+ "(?:(?:Server)|(?:������)|(?:����)|(?:��¼)|(?:spid[0-9s]{2,3}))\\s+"
			+ ".*";
    
    /*Map<java.sql.Date, Integer> MapDailyTotal = new HashMap<java.sql.Date, Integer>();
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");*/
	
	public AsyncMySqlMSLogEventSerializer() {  
		mstotal = 0;
		msinstotal = 0;
		total = 0;
		bmsflag = false;
		System.out.println("MysqlSink start...");
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
            preparedStatementOther = conn.prepareStatement("insert into " + TableOther +
                    " (risklevel) values (?)");
            preparedStatementDaily = conn.prepareStatement("insert into " + TableDailyInfo +
                    " (date,total) values (?,?)");
            preparedStatementContent = conn.prepareStatement("insert into " + tableName +
                    " (content,sorttime) values (?,?)");
            preparedStatementPrase = conn.prepareStatement("insert into " + TableNamePrase +
                    " (date,time,srcip,dstip,attacktype,srcloc,dstloc) values (?, ?, ?, ?, ?, ?, ?)");
            preparedStatementInfo = conn.prepareStatement("insert into " + TableNameMS +
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
        //preparedStatementOther
        if (preparedStatementOther != null) {
            try {
            	preparedStatementOther.close();
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
        
        if (preparedStatementPrase != null) {
            try {
            	preparedStatementPrase.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        
        if (preparedStatementInfo != null) {
            try {
            	preparedStatementInfo.close();
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
	
	private void processMS(String content,List<InfoParse> infops,List<Info> infos){
		Info info=new Info();
		if(content.length() < 10000){
			
			info.setContent(content);
			infos.add(info);
		}
		else{//������־��������������
			/*content = content.substring(0, 9999);
			info.setContent(content);
			infos.add(info);*/
			//����ע�����
			return;
		}
        
		//*******************�����ڶ��ű�*******************
       //���Դip
        String[] SplitRecord = content.split("\\s+");
        InfoParse infop = new InfoParse();
        infop.setSrcip("Unknown");
        infop.setDstip("Unknown");
        //���Ŀ��IPtmp

        //���date
        
        java.sql.Date date = GeneralFunc.strToDate(SplitRecord[0]);
        infop.setDate(date);
        //���time
        SplitRecord[1] = SplitRecord[1].substring(0, SplitRecord[1].length() - 3);
        infop.setTime(SplitRecord[1]);
        //���atype
        infop.setAType(3);
        //location
        infop.setSrcloc("Unknown");
        infop.setDstloc("Local");
        
        infops.add(infop);
	}
	
	
	@Override
	public Status process() throws EventDeliveryException {//ÿ���ϴ�һ����־�������￪ʼ��
		// TODO Auto-generated method stub
		
		Status result = Status.READY;
        Channel channel = getChannel();
        Transaction transaction = channel.getTransaction();
        Event event;
        String content;
        RecordDetect rd = new RecordDetect();
        List<Info> infos = Lists.newArrayList();
        List<InfoParse> infops = Lists.newArrayList();
        List<DailyInfo> dinfos = Lists.newArrayList();
        
        boolean bBlank = false;
        boolean bSubmit = false;
        
        Pattern patternip = Pattern.compile(regexip);
       /* IPLocation iploc = new IPLocation();
		iploc.load("//tool//mydata4vipday2.dat");*/
		String[] loc;
		String sloc = "0.0.0.0";
		int tmpmstotal = 0;//�ж��Ƿ�������4
		Pattern patternMS = Pattern.compile(msregex);
		
		Map<java.sql.Date, Integer> MapDailyTotal = new HashMap<java.sql.Date, Integer>();
	    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");
		
        transaction.begin();
        try {
            for (int i = 0; i < batchSize; i++) {
                event = channel.take();
                
                if (event != null) {//���¼����д���
                	RiskLevel.bmsstart = true;
                	bBlank = true;
                    content = new String(event.getBody());
                    
                    Matcher matcherMS = patternMS.matcher(content);
                    if(!matcherMS.find()){//�жϴ�����־�Ƿ������ݿ���־��
                    	continue;
                    }
                    total++;
                    java.sql.Date dailyinfo = GeneralFunc.strToDate(matcherMS.group(1));
                    //java.sql.Date dailyinfo = simpleDateFormat.parse(matcherMS.group(1))
                    if(!MapDailyTotal.containsKey(dailyinfo)){
                    	MapDailyTotal.put(dailyinfo, 1);
                    }else{
                    	Integer itotal = MapDailyTotal.get(dailyinfo) + 1;
                    	MapDailyTotal.put(dailyinfo, itotal);
                    }
                    
                    for(String r : MSAttack){
	                 	Pattern pattern = Pattern.compile(r);
	                 	Matcher matcher = pattern.matcher(content);
	                 	
	                 	if(matcher.find()){
	                 		//һЩͨ�õ��������������
	                 		//���ƥ��ɹ������޸���в�ȼ�
	                 		if(RiskLevel.GetRiskLevel() < 2){
	                    		RiskLevel.SetMidLevel();
	                    	}
	                 		mstotal++;
	                 		bmsflag = true;
	                 		tmpmstotal++;
	                 		abntotal++;
	                 		processMS(content, infops, infos);
	                 		
	                        break;
	        			}
	                 }
                    //һЩ�������жϲ���
                    if( (tmpmstotal == 4) && bmsflag){//����4��
             			instotal += 4;
             			msinstotal += 4;
             		}
             		else if( (tmpmstotal > 4) && bmsflag){//��������4��
             			msinstotal ++;
             			instotal ++;
             		}
             		if(!bmsflag){//���ѭ��һ��Sql�Ĺؼ��֣�û�з���ƥ�䣬˵���Ѿ���������
             			tmpmstotal = 0;
                    }
                    bmsflag = false;
                    
                } else {//if (event != null)
                	//transaction.commit();
                	bSubmit = true;
                	//ɨβ����
                	RiskLevel.bmsend = true;
                    result = Status.BACKOFF;
                    break;
                }
            }
            
            if(RiskLevel.GetRiskLevel() == 2){//����
          	  RiskLevel.mabnTotal +=  mstotal;
          	  RiskLevel.minsTotal += msinstotal;
          	  riskvalue = RiskLevel.GetRiskValue();
            }
            RiskLevel.bms = true;
            //����Map��ŵ���Ӧ�����ݽṹ��
            for (Map.Entry<java.sql.Date, Integer> entry : MapDailyTotal.entrySet()){
            	DailyInfo df = new DailyInfo();
            	df.SetDate(entry.getKey());
            	df.SetTotal(entry.getValue());
            	dinfos.add(df);
            }
            //LOG.debug("afterLoop........");
            
            if (infos.size() > 0) {
            	
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
            	for(DailyInfo dinfo : dinfos){
            		preparedStatementDaily.setDate(1, (java.sql.Date) dinfo.GetDate());
            		preparedStatementDaily.setInt(2, dinfo.GetTotal());
            		preparedStatementDaily.addBatch();
            	}
            	preparedStatementDaily.executeBatch();
                conn.commit();
            }
            
            if(bSubmit && bBlank){//ms��־�����ݣ��������һ��ѭ����ʱ��
            	preparedStatementInfo.clearBatch();
                preparedStatementInfo.setInt(1, abntotal - instotal);
                preparedStatementInfo.setInt(2, instotal);
                preparedStatementInfo.setFloat(3, 0);
                preparedStatementInfo.setInt(4, 0);
                preparedStatementInfo.setInt(5, abntotal);
                preparedStatementInfo.addBatch();
                preparedStatementInfo.executeBatch();
                //conn.commit();//���ﲻ��������commit������ڶ��������ϴ�
                
                
                
                if(!RiskLevel.biisstart){//û���м����־
                	preparedStatementOther.clearBatch();
                    preparedStatementOther.setInt(1, riskvalue);
                    preparedStatementOther.addBatch();
                    preparedStatementOther.executeBatch();
                }
                       
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
        TableNameMS = "mstotalinfo";
        TableDailyInfo = "dateinfo";
        TableOther = "other";
	}

}




/*@Override
public Status process() throws EventDeliveryException {
	// TODO Auto-generated method stub
	
	Status result = Status.READY;
    Channel channel = getChannel();
    Transaction transaction = channel.getTransaction();
    Event event;
    String content;
    RecordDetect rd = new RecordDetect();
    List<Info> infos = Lists.newArrayList();
    List<InfoParse> infops = Lists.newArrayList();
    List<DailyInfo> dinfos = Lists.newArrayList();
    
    Pattern patternip = Pattern.compile(regexip);
    IPLocation iploc = new IPLocation();
	iploc.load("//tool//mydata4vipday2.dat");
	String[] loc;
	String sloc = "0.0.0.0";
	int tmptotal = 0;//�ж��Ƿ�������4
	Pattern patternMS = Pattern.compile(msregex);
	
    transaction.begin();
    try {//���账��Ķ����м����־
        for (int i = 0; i < batchSize; i++) {
            event = channel.take();
            
            if (event != null) {//���¼����д���
            	
                content = new String(event.getBody());
                
                Matcher matcherMS = patternMS.matcher(content);
                if(!matcherMS.find()){
                	continue;
                }
                total++;
                java.sql.Date dailyinfo = GeneralFunc.strToDate(matcherMS.group(1));
                if(!MapDailyTotal.containsKey(dailyinfo)){
                	MapDailyTotal.put(dailyinfo, 1);
                }else{
                	Integer itotal = MapDailyTotal.get(dailyinfo) + 1;
                	MapDailyTotal.put(dailyinfo, itotal);
                }
                
                for(String r : MSAttack){
                	
                	if(RiskLevel.GetRiskLevel() < 2){
                		RiskLevel.SetMidLevel();
                	}
                	
                 	Pattern pattern = Pattern.compile(r);
                 	Matcher matcher = pattern.matcher(content);
                 	if(matcher.find()){
                 		tmptotal++;
                 		if(tmptotal == 4){
                 			instotal += 4;
                 		}
                 		else if(tmptotal > 4){
                 			instotal ++;
                 		}
                 		//*******************������һ�ű�*******************
                 		Info info=new Info();
        				//info.setContent(content);
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
                       //���Դip
                        String[] SplitRecord = content.split("\\s+");
                        InfoParse infop = new InfoParse();
                        infop.setSrcip("Unknown");
                        infop.setDstip("Unknown");
                        //���Ŀ��IPtmp

                        //���date
                        
                        java.sql.Date date = GeneralFunc.strToDate(SplitRecord[0]);
                        infop.setDate(date);
                        //���time
                        SplitRecord[1] = SplitRecord[1].substring(0, SplitRecord[1].length() - 3);
                        infop.setTime(SplitRecord[1]);
                        //���atype
                        infop.setAType(3);
                        //location
                        infop.setSrcloc("Unknown");
                        infop.setDstloc("Local");
                        
                        infops.add(infop);
                        
                        break;
        			}
                 	else{
                 		tmptotal = 0;
                 	}

                 }
            } else {//if (event != null)
            	//transaction.commit();
                result = Status.BACKOFF;
                break;
            }
        }
        
        if(RiskLevel.GetRiskLevel() == 2){//����
      	  RiskLevel.mabnTotal +=  total;
      	  RiskLevel.minsTotal += instotal;
      	  riskvalue = RiskLevel.GetRiskValue();
        }
        RiskLevel.bms = true;
        //����Map��ŵ���Ӧ�����ݽṹ��
        for (Map.Entry<java.sql.Date, Integer> entry : MapDailyTotal.entrySet()){
        	DailyInfo df = new DailyInfo();
        	df.SetDate(entry.getKey());
        	df.SetTotal(entry.getValue());
        	dinfos.add(df);
        }
        //LOG.debug("afterLoop........");
        
        
        if (infos.size() > 0) {
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
            preparedStatementInfo.setInt(1, total - instotal);
            preparedStatementInfo.setInt(2, instotal);
            preparedStatementInfo.setFloat(3, 0);
            preparedStatementInfo.setInt(4, 0);
            preparedStatementInfo.setInt(5, total);
            preparedStatementInfo.addBatch();
            preparedStatementInfo.executeBatch();
            
            preparedStatementOther.clearBatch();
            preparedStatementOther.setInt(1, riskvalue);
            preparedStatementOther.addBatch();
            preparedStatementOther.executeBatch();
            
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
*/