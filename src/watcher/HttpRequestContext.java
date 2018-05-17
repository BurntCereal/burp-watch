package watcher;

//A context for the http requests so that the worker knows how to interpret the response

public class HttpRequestContext {

	String payloadType;
	int payloadNumber;
	String requestID;
	String originalRequest;
	
	public HttpRequestContext(String type, int payload, String requestID, String original)
	{
		payloadType = type;
		payloadNumber = payload;
		this.requestID = requestID;
		originalRequest = original;
	}
}
