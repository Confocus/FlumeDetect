package AsyncHBaseLog;

import com.google.common.base.Preconditions;  
import com.google.common.base.Throwables;  
import com.google.common.collect.Lists;

import regexfilt.MidwareErr;
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
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;  

public class AsyncMySqlLogServerEventSerializer extends AbstractSink implements Configurable{

	private Logger LOG = LoggerFactory.getLogger(AsyncMySqlLogServerEventSerializer.class);
	private String hostname;
    private String port;
    private String databaseName;
    private String tableName;
    private String user;
    private String password;
    private PreparedStatement preparedStatementContent;
    private Connection conn;
    private int batchSize;
    
    
    private String tableNamePrase;
   
    private PreparedStatement preparedStatementPrase;

    //private Connection conn;
    
    private String TableNameInfo;
    private PreparedStatement preparedStatementInfo;
    
    private int mwtotal;
    private int mstotal;
    private int webtotal;
    private int servertotal;
    private int itemtotal;
    
    
    private int mwinstotal;
    private int msinstotal;
    private int webinstotal;
    private int serverinstotal;
     
    
    private String[] ServerAttack = {
    		
    };
    
    private String regexip = "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}";
    
	
	public AsyncMySqlLogServerEventSerializer() {  
		mwtotal = 0;
		mstotal = 0;
		webtotal = 0;
		itemtotal = 0;
        //LOG.info("MysqlSink start...");  
		System.out.println("MysqlSink start...");
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
            preparedStatementContent = conn.prepareStatement("insert into " + tableName +
                    " (content,sorttime) values (?,?)");
            preparedStatementPrase = conn.prepareStatement("insert into " + tableNamePrase +
                    " (date,time,srcip,dstip,attacktype,srcloc,dstloc) values (?, ?, ?, ?, ?, ?, ?)");
            preparedStatementInfo = conn.prepareStatement("insert into " + TableNameInfo +
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
        String content;
        RecordDetect rd = new RecordDetect();
        List<Info> infos = Lists.newArrayList();
        List<InfoParse> infops = Lists.newArrayList();
        
        Pattern patternip = Pattern.compile(regexip);
        IPLocation iploc = new IPLocation();
		iploc.load("//tool//mydata4vipday2.dat");
		String[] loc;
		String sloc = "0.0.0.0";
		int tmptotal = 0;//判断是否连续有4
        
		
        transaction.begin();
        try {//假设处理的都是中间件日志
            for (int i = 0; i < batchSize; i++) {
                event = channel.take();
                
                if (event != null) {//对事件进行处理
                	mwtotal++;//event 的 body 为   "exec tail$i , abel"
                    content = new String(event.getBody());
                    for(String r : ServerAttack){
	                 	Pattern pattern = Pattern.compile(r);
	                 	Matcher matcher = pattern.matcher(content);
	                 	if(matcher.find()){
	                 		tmptotal++;
	                 		if(tmptotal == 4){
	                 			mwinstotal += 4;
	                 		}
	                 		else if(tmptotal > 4){
	                 			mwinstotal ++;
	                 		}
	                 		//*******************操作第一张表*******************
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
	                        
	        				//*******************操作第二张表*******************
	                       //添加源ip
	                        String[] SplitRecord = content.split("\\s+");
	                        InfoParse infop = new InfoParse();
	                        infop.setSrcip(SplitRecord[2]);
	                        //添加目标IPtmp
	                        Matcher matcherip = patternip.matcher(SplitRecord[8]);
	                        if(matcherip.find()){
	                        	infop.setDstip(SplitRecord[8]);
	                        	sloc = SplitRecord[8];
	                        }
	                        else{
	                        	matcherip = patternip.matcher(SplitRecord[9]);
	                        	if(matcherip.find()){
	                        		infop.setDstip(SplitRecord[9]);
	                        		sloc = SplitRecord[9];
	                        	}else{
	                        		infop.setDstip("nothing");
	                        	}
	                        }
	                        
	                        //添加date
	                        java.sql.Date date = GeneralFunc.strToDate(SplitRecord[0]);
	                        infop.setDate(date);
	                        //添加time
	                        infop.setTime(SplitRecord[1]);
	                        //添加atype
	                        infop.setAType(2);
	                        //location
	                        if(!sloc.equals("0.0.0.0")){
	                        	loc = iploc.find(sloc);
	                        	infop.setSrcloc(loc[2]);
	                        }
	                        else{
	                        	infop.setSrcloc("1");
	                        }
	                        
	                        
	                        infop.setDstloc("loc");
	                        
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
           
                preparedStatementInfo.clearBatch();
                preparedStatementInfo.setInt(1, mwtotal - mwinstotal);
                preparedStatementInfo.setInt(2, mwinstotal);
                preparedStatementInfo.setFloat(3, 0);
                preparedStatementInfo.setInt(4, 0);
                preparedStatementInfo.setInt(5, mwtotal);
                preparedStatementInfo.addBatch();
                preparedStatementInfo.executeBatch();
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
        
        tableNamePrase = "ids_an_data";
        TableNameInfo = "servertotalinfo";
      
	}

}
