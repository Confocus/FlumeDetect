package regexfilt;

/*import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;*/
import java.io.IOException;
/*import java.io.InputStreamReader;
import java.util.Date;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.regex.Pattern;*/



public class FiltwithRegEx {
	
	
	
	public static void RunCmdline(){
		try {
			Process pro = Runtime.getRuntime().exec("mv /tool/tmp.txt /tool/tmpq.txt");
			pro.waitFor();
			
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
	
	public static void main(String[] args){
		RunCmdline();
	}

}
