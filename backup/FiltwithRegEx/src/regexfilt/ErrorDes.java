package regexfilt;
import res.ResDetail;
//���ﲻʹ�ýӿڣ���ʹ�ó�����᲻�����

public interface ErrorDes {
	/*boolean DetectionRes = false;
	String regex = "";*/
	void ErrorDescription();
	int Detecte();
	int WarnLevel();
	ResDetail ReturnResult();
	void ParseRecord(String record);
	void StoreMySQL();
	//String GetRegexRule();
	/*void SetMember();
	void GetMember();*/
}
