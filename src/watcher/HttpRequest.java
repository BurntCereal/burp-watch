package watcher;

public class HttpRequest {

	String hostname;
	int port;
	boolean useHttps;
	byte[] payload;
	HttpRequestContext context;
	
	public HttpRequest(String host, int p, boolean use, byte[] req, HttpRequestContext context)
	{
		hostname = host;
		port = p;
		useHttps = use;
		payload = req;
		this.context = context;
	}
	
		
}
