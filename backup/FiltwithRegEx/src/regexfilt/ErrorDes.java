package regexfilt;
import res.ResDetail;
//这里不使用接口，而使用抽象类会不会更好

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
