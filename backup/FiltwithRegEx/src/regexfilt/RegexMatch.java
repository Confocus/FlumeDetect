package regexfilt;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexMatch {
	//这个函数只用来判断正则表达式和语句是否匹配
		public static boolean match(String regEx, String str){//, StringBuilder sec
			// 编译正则表达式
		    Pattern pattern = Pattern.compile(regEx);
		 // 忽略大小写的写法
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
