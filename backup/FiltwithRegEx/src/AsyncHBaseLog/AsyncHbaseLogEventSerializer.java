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
    public void initialize(byte[] table, byte[] cf) {//������ֵ�Ǵ������ļ��л�õ�
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
		//��currentEvent�����ݽ��й���
		String eventStr = new String(currentEvent.getBody());
		//��ⵥ���ֶ�
		if(me.DetectRecord(eventStr)){
			Long currTime = System.currentTimeMillis();//���õ�ǰʱ�乹��key������һ�����ظ���key���µ����ݾͻḲ�Ǿɵ�����
			currentRowKey = (Long.toString(currTime)).getBytes();
			//this.currentRowKey = "test".getBytes();
			//���������壻��������ӵ�����
			//����־����Ϊ�����м������ʱ��Ϊ�����Դ�������Ϊ���壻������δ�漰��������־Ϊ����
			PutRequest reqPathPutReq = new PutRequest(table, currentRowKey, colFam, "testMidware".getBytes(), "warning".getBytes());
	        puts.add(reqPathPutReq);     
	       // 
			return puts;
		}
		return null;
	}
	// �ݴ�һ�����Ը�����
	/*//��currentEvent�����ݽ��й���
	String eventStr = new String(currentEvent.getBody());
	Long currTime = System.currentTimeMillis();//���õ�ǰʱ�乹��key������һ�����ظ���key���µ����ݾͻḲ�Ǿɵ�����
	currentRowKey = (Long.toString(currTime)).getBytes();
	//this.currentRowKey = "test".getBytes();
	//���������壻��������ӵ�����
	PutRequest reqPathPutReq = new PutRequest(table, currentRowKey, colFam, "req_path".getBytes(), eventStr.getBytes());
    puts.add(reqPathPutReq);     
   // return null;
	return puts;*/

	@Override
	public List<AtomicIncrementRequest> getIncrements() {
		// TODO Auto-generated method stub
		incs.clear();
		//totalEvent��key
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

