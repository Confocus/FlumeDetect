package AsyncHBaseLog;
import java.util.ArrayList;
import java.util.List;

import org.apache.flume.Context;
import org.apache.flume.Event;
import org.apache.flume.conf.ComponentConfiguration;
import org.apache.flume.sink.hbase.AsyncHbaseEventSerializer;
//import org.apache.flume.sink.hbase.HbaseEventSerializer;
//import org.apache.hadoop.hbase.client.Increment;
//import org.apache.hadoop.hbase.client.Row;
//import org.apache.hadoop.hbase.client.Put;
//import org.apache.hadoop.hbase.util.Bytes;
import org.hbase.async.AtomicIncrementRequest;
import org.hbase.async.PutRequest;
import regexfilt.MidwareErr;

public class AsyncHbaseLogEventSerializer implements AsyncHbaseEventSerializer {
	private byte[] table;
    private byte[] colFam;
    Event currentEvent;
    private final List<PutRequest> puts = new ArrayList<PutRequest>();
    private final List<AtomicIncrementRequest> incs = new ArrayList<AtomicIncrementRequest>();
    private byte[] currentRowKey;
    private final byte[] eventCountCol = "eventCount".getBytes();
    
    @Override
    public void initialize(byte[] table, byte[] cf) {//这两个值是从配置文件中获得的
        this.table = table;
        this.colFam = cf;
    }

	@Override
	public void configure(Context arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void configure(ComponentConfiguration arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void cleanUp() {
		// TODO Auto-generated method stub
		  table = null;
          colFam = null;
          currentEvent = null;
	}

	@Override
	public List<PutRequest> getActions() {
		// TODO Auto-generated method stub
		MidwareErr me = new MidwareErr();
		//对currentEvent的内容进行过滤
		String eventStr = new String(currentEvent.getBody());
		//检测单个字段
		if(me.DetectRecord(eventStr)){
			Long currTime = System.currentTimeMillis();//利用当前时间构造key。否则，一旦有重复的key，新的数据就会覆盖旧的数据
			currentRowKey = (Long.toString(currTime)).getBytes();
			//this.currentRowKey = "test".getBytes();
			//表；键；列族；列名；添加的内容
			//以日志类型为表名中间件表；以时间为键；以错误类型为列族；列名暂未涉及；整行日志为内容
			PutRequest reqPathPutReq = new PutRequest(table, currentRowKey, colFam, "testMidware".getBytes(), "warning".getBytes());
	        puts.add(reqPathPutReq);     
	       // 
			return puts;
		}
		return null;
	}
	// 暂存一个测试副本：
	/*//对currentEvent的内容进行过滤
	String eventStr = new String(currentEvent.getBody());
	Long currTime = System.currentTimeMillis();//利用当前时间构造key。否则，一旦有重复的key，新的数据就会覆盖旧的数据
	currentRowKey = (Long.toString(currTime)).getBytes();
	//this.currentRowKey = "test".getBytes();
	//表；键；列族；列名；添加的内容
	PutRequest reqPathPutReq = new PutRequest(table, currentRowKey, colFam, "req_path".getBytes(), eventStr.getBytes());
    puts.add(reqPathPutReq);     
   // return null;
	return puts;*/

	@Override
	public List<AtomicIncrementRequest> getIncrements() {
		// TODO Auto-generated method stub
		incs.clear();
		//totalEvent是key
        incs.add(new AtomicIncrementRequest(table, "totalEvents".getBytes(), colFam, eventCountCol));
        return incs;
		//return null;
	}

	

	@Override
	public void setEvent(Event event) {
		// TODO Auto-generated method stub
		this.currentEvent = event;
	}
	
}

