package regexfilt;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexMatch {
	//�������ֻ�����ж�������ʽ������Ƿ�ƥ��
		public static boolean match(String regEx, String str){//, StringBuilder sec
			// ����������ʽ
		    Pattern pattern = Pattern.compile(regEx);
		 // ���Դ�Сд��д��
		    // Pattern pat = Pattern.compile(regEx, Pattern.CASE_INSENSITIVE);
		    Matcher matcher = pattern.matcher(str);
		    boolean rs = matcher.matches();
		    //System.out.println(str);
		    /*StringBuilder sec = new StringBuilder();
		    sec.append(matcher.group(1));
	    	sec.append(matcher.group(2));
	    	sec.append(matcher.group(3));*/
		    return rs;
		}
}
