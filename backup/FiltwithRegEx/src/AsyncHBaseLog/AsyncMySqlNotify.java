package AsyncHBaseLog;

//import com.google.common.base.Preconditions;  
import com.google.common.base.Throwables;  
//import com.google.common.collect.Lists;

/*import regexfilt.MidwareErr;
import regexfilt.RecordDetect;
import regexfilt.RegexMatch;
import res.IPLocation;*/

import org.apache.flume.*;  
import org.apache.flume.conf.Configurable;  
import org.apache.flume.sink.AbstractSink;
/*import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.SimpleLayout;*/
import org.slf4j.Logger;  
import org.slf4j.LoggerFactory;  
   
/*import java.sql.Connection;  
import java.sql.DriverManager;  
import java.sql.PreparedStatement;  
import java.sql.SQLException;  
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;  */

public class AsyncMySqlNotify extends AbstractSink implements Configurable{

	private Logger LOG = LoggerFactory.getLogger(AsyncMySqlNotify.class);
	private String strDel=new String("deleteAllData");
    private int batchSize = 100;
    
	public AsyncMySqlNotify() {  
		
    }  
	
	
	
	public void start() {
        super.start();
    }
	
	public void stop() {
        super.stop();
       
    }
	
	@Override
	public Status process() throws EventDeliveryException {
		// TODO Auto-generated method stub
		
		Status result = Status.READY;
        Channel channel = getChannel();
        Transaction transaction = channel.getTransaction();
        Event event;
        String content;
        /*RecordDetect rd = new RecordDetect();
        List<Info> infos = Lists.newArrayList();
        List<InfoParse> infops = Lists.newArrayList();*/
        
        //Pattern patternip = Pattern.compile(regexip);
       
        
		
        transaction.begin();
        try {//假设处理的都是中间件日志
            for (int i = 0; i < batchSize; i++) {
                event = channel.take();
                
                if (event != null) {//对事件进行处理
                    content = new String(event.getBody());
                    if(content.equals(strDel)){
                    	AsyncMySqlMSLogEventSerializer.abntotal = 0;
                    	AsyncMySqlMSLogEventSerializer.instotal = 0;
                    	AsyncMySqlMSLogEventSerializer.riskvalue = 0;
                    	
                    	AsyncMySqlMidwareLogEventSerializer.abntotal = 0;
                    	AsyncMySqlMidwareLogEventSerializer.instotal = 0;
                    	AsyncMySqlMidwareLogEventSerializer.riskvalue = 0;
                    	
                    	System.out.println("Delete all data success.");
                    }
                    else{
                    	System.out.println("Delete all data fail.");
                    }
                } else {//if (event != null)
                	//transaction.commit();
                    result = Status.BACKOFF;
                    break;
                }
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
		
      
	}

}
