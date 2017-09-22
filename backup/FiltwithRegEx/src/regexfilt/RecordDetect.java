package regexfilt;

import java.util.List;
import java.util.regex.Pattern;

import org.apache.flume.Channel;
import org.apache.flume.Event;
import org.apache.flume.EventDeliveryException;
import org.apache.flume.Transaction;
import org.apache.flume.Sink.Status;

import com.google.common.base.Throwables;
import com.google.common.collect.Lists;

import AsyncHBaseLog.Info;

public class RecordDetect {
	private String[] SqlAttacks = {
			".*select.*", ".*%20or.%20*", ".*%20and%20.*",
			".*%20from%20.*", ".*%20where%20.*",
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
	
	public boolean detecte(String str){
		boolean flag = false;
		for(String r : SqlAttacks){
			//Pattern pattern = Pattern.compile(r);
			if(RegexMatch.match(r, str)){
				//System.out.println(str);
				flag = true;
				break;
			}
		}
		return flag;
	}
	
	
}
