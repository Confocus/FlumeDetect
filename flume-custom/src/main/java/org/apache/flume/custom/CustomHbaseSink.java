package org.apache.flume.custom;

import java.util.List;
import java.util.ArrayList;

import org.apache.flume.Context;  
import org.apache.flume.Event;  
import org.apache.flume.FlumeException;  
import org.hbase.async.AtomicIncrementRequest;  
import org.hbase.async.PutRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.flume.conf.ComponentConfiguration;  
import org.apache.flume.sink.hbase.SimpleHbaseEventSerializer.KeyType;  
import org.apache.flume.sink.hbase.AsyncHbaseEventSerializer;
  
import com.google.common.base.Charsets;  

public class CustomHbaseSink implements AsyncHbaseEventSerializer {
	
	private Logger logger = LoggerFactory.getLogger(CustomHbaseSink.class);  
	private byte[] table;
    private byte[] colFam;
    Event currentEvent;
    private final List<PutRequest> puts = new ArrayList<PutRequest>();
    private final List<AtomicIncrementRequest> incs = new ArrayList<AtomicIncrementRequest>();
    private byte[] currentRowKey;
    private final byte[] eventCountCol = "eventCount".getBytes();
    private long rowcount;
    
    public CustomHbaseSink(){
    	logger.info("HbaseSink start by Wang...");  
    }
    
	@Override
	public void configure(Context context) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void configure(ComponentConfiguration conf) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void initialize(byte[] table, byte[] cf) {
		// TODO Auto-generated method stub
		 this.table = table;
	     this.colFam = cf;
	     this.rowcount = 1;
	}

	@Override
	public void setEvent(Event event) {
		// TODO Auto-generated method stub
		this.currentEvent = event;
	}

	@Override
	public List<PutRequest> getActions() {
		// TODO Auto-generated method stub
		String eventStr = new String(currentEvent.getBody());
		this.currentRowKey = Long.toString(this.rowcount).getBytes();
		this.rowcount++;
		PutRequest reqPathPutReq = new PutRequest(table, currentRowKey, colFam, "id".getBytes(), eventStr.getBytes());
        puts.add(reqPathPutReq);     
       // return null;
		return puts;
	}

	@Override
	public List<AtomicIncrementRequest> getIncrements() {
		// TODO Auto-generated method stub
		List<AtomicIncrementRequest> incs = new ArrayList<AtomicIncrementRequest>();

		return incs;
	}

	@Override
	public void cleanUp() {
		// TODO Auto-generated method stub
		 table = null;
         colFam = null;
         currentEvent = null;
	}  
	
}