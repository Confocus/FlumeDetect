package AsyncHBaseLog;

import java.text.SimpleDateFormat;

public class GeneralFunc {
	
	public static boolean bEmpty = false;//�û��Ƿ�����յĲ���
	
	public static java.sql.Date strToDate(String strDate) {  
        String str = strDate;  
        SimpleDateFormat format = new SimpleDateFormat("yyyy-mm-dd");  
        java.util.Date d = null;  
        try {  
            d = format.parse(str);  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
        java.sql.Date date = new java.sql.Date(d.getTime());  
        return date;  
    }  
}
