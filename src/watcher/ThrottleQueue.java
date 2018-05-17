package watcher;

import java.util.LinkedList;
import java.util.List;

import burp.IBurpExtenderCallbacks;

//1) Attempt 1, we will have queue populated and each caller thread will wait til their request sent out then they will continue, blocking callback. Rate setable in window and text field displays 
//queue buffer size. Able to hold buffer without sending any as well. Actually that will cause us to run out of memory as we use new thread per request.
// Add a field for thread count as well.

//2) Attempt 2 - send them into queue with request and context, end thread and once receive response call an analyze method with the context . A lot safer. Textbox with queue pickup rate

public class ThrottleQueue {

	public int requestRate; 
	public int currentRequest;
	public int bufferCount;
	public LinkedList buffer; 
	IBurpExtenderCallbacks callbacks;
	
	//Need access to callbacks object to send out request
	public ThrottleQueue(IBurpExtenderCallbacks callbacks) {
		// TODO Auto-generated constructor stub
		this.callbacks = callbacks;
		
		//start the http worker
	
	}
	
	public ThrottleQueue() {
		
	}

	public void push(HttpRequest request)
	{
		buffer.add(request);
	}	
	
	public HttpRequest pop()
	{
		HttpRequest request = (HttpRequest) buffer.pop();
		return request;
	}
	
	
}
