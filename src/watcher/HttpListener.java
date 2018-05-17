package watcher;

import java.awt.Color;
import java.net.URL;
import java.util.List;

import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.JTextArea;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;

//The main processor, hooks onto http calls and creates custom vectors

public class HttpListener implements IHttpListener{

	
	//TODO 
	//Throttler, so half my requests arent being blocked
	//THROW in log statements debug into synchronized block. so they all execute in order without others
	//Search function for textpane
	//	- Search box done
	//CLear logs hotkey
	//Host Blacklist/Whitelist so we only testing what we want
	//Scroll lockable - toggle
	//Fix false positive redirects and buffer limit on textpane to save memory
	
	//Add options for number of payloads for XXE, log debugging etc. and providing them via settings rather than hard coded
	//Feed in CPanel logs into XXE checker and others for request ids
	// use SSH - http://www.jcraft.com/jsch/
	
	
	Tab khrono;
	
	IExtensionHelpers helper;
	
	IBurpExtenderCallbacks callbacks;
	
	ThrottleQueue queue;
	
	private static int requestNumber = 0; //Switched to request ID, unique key per request, since this implementation isnt thread safe, Need to add a text search function for your text pane then
	
	public HttpListener(){
		
		HttpWorker httpWorker = new HttpWorker(queue);
		httpWorker.start();
	}
	
	public static synchronized String createID()
	{
	    return String.valueOf(requestNumber++);
	}    
	
	
	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		
		if(messageIsRequest && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY){
			//Ignore Black List for requests only
			URL url = helper.analyzeRequest(messageInfo).getUrl();
			
			if(!isBlacklisted(url.getHost()))
			{
				//Lets send these to an http service
				if(khrono.xxeCheckBox.isSelected())
				{
					sendXXEPayloads(messageInfo, 2); //WIP
					sendXSSPayload(messageInfo);
					sendSQLPayload(messageInfo);
					sendEntropyPayload(messageInfo);
		
				}
				if(khrono.crlfBox.isSelected())
				{
					sendCRLFPayloads(messageInfo, 2); //WIP 
		
				}
				if(khrono.openRedirectBox.isSelected())
				{
					sendRedirectPayloads(messageInfo, 3);
				}
			}
		
		}
		
	}
	
	private void sendRedirectPayloads(IHttpRequestResponse message, int numberOfPayloads) {
		
		//1) Example.com//evil.com, reflected in location header response
		//2) evil.com in all query params
		//3) //evil.com in all query params
		
		byte[] payload;
		IRequestInfo httpRequest;
		IResponseInfo httpResponse;
		//String requestID = "";
		List<String> requestHeaders;
		List<String> responseHeaders;
		List<IParameter> params; 
		Boolean useHttps;
		
		String httpRequestText = new String(message.getRequest());
		httpRequest = helper.analyzeRequest(message);
		
		URL url = httpRequest.getUrl();

		if(url.getProtocol().equals("http"))
		{
			useHttps = false;
		}
		else
		{
			useHttps = true;
		}

		for(int i=1; i<=numberOfPayloads; i++)
		{
			String requestID = createID();
			
			switch(i)
			{
			
				case 1:
				{
					
					payload = message.getRequest();
					
					requestHeaders = httpRequest.getHeaders();
					String replaceHeader = httpRequest.getMethod() + " " + url.getPath() + PayloadGenerator.REDIRECT_PAYLOAD_1;
					requestHeaders.set(0, replaceHeader);
					
					payload = helper.buildHttpMessage(requestHeaders, httpRequestText.substring(httpRequest.getBodyOffset()).getBytes());
					
					queue.push(new HttpRequest(url.getHost(), url.getPort(), useHttps, payload, new HttpRequestContext("redirect", i, requestID, httpRequestText)));
					
					break;

				}
				case 2:
				{
					
					payload = message.getRequest();
					
					params = httpRequest.getParameters();

					for(IParameter param : params)
					{
						if(param.getType() == param.PARAM_URL)
						{
							param = helper.buildParameter(param.getName(), PayloadGenerator.REDIRECT_PAYLOAD_2, param.getType());
							payload = helper.updateParameter(payload, param);
						}
					}
					
					queue.push(new HttpRequest(url.getHost(), url.getPort(), useHttps, payload, new HttpRequestContext("redirect", i, requestID, httpRequestText)));
					
	
					break;
									
					
				}
				
				case 3:
				{
					
					payload = message.getRequest();
					
					params = httpRequest.getParameters();

					for(IParameter param : params)
					{
						if(param.getType() == param.PARAM_URL)
						{
							param = helper.buildParameter(param.getName(), PayloadGenerator.REDIRECT_PAYLOAD_3, param.getType());
							payload = helper.updateParameter(payload, param);
						}
					}
					
					queue.push(new HttpRequest(url.getHost(), url.getPort(), useHttps, payload, new HttpRequestContext("redirect", i, requestID, httpRequestText)));
									
					
					break;	
					
				}
			}
			

		
		}
		
	}

	private void sendEntropyPayload(IHttpRequestResponse messageInfo) {
		// TODO Auto-generated method stub
		
		//1. Add an X-Forwarded-For header and compare output with control, might have access to internal links
		
	}

	private void sendSQLPayload(IHttpRequestResponse messageInfo) {
		// TODO Auto-generated method stub
		
	}

	public void attachHelperParser(IExtensionHelpers helper)
	{
		this.helper = helper;
	}
	
	public void sendCRLFPayloads(IHttpRequestResponse message, int numberOfPayloads)
	{
		//1) CRLF payloads in query params
		//2) CRLF Payload as a page i.e. GET /support/%0d%0aPAYLOAD%0d%0a
		//3) CRLF payloads in message body
		
		byte[] payload;
		boolean useHttps = true;
		List<String> responseHeaders;
		String httpRequestText;
		List<IParameter> params;
		List<IParameter> newParams;
		List<String> requestHeaders;
		IRequestInfo httpRequest;

		
		httpRequestText = new String(message.getRequest());
		httpRequest = helper.analyzeRequest(message);
		payload = message.getRequest();
		
		params = httpRequest.getParameters();
		
		
		//Each loop uses a stronger XXE pattern
		for(int i = 1; i<=numberOfPayloads; i++)
		{
			//Generate unique ID
			String requestID = createID();
			
			//Payload 1, CRLF in params   //Breaking the payloads by if statements isnt clean we should put param initialization in Payload Generator then jus call function in switch statement
		    if(i == 1)
		    {
				for(IParameter param : params)
				{
					if(param.getType() == param.PARAM_URL)
					{
						param = helper.buildParameter(param.getName(), PayloadGenerator.CRLF_PAYLOAD_1, param.getType());
						payload = helper.updateParameter(payload, param);
					}
				}
		    }
		    //END OF PAYLOAD 1
		    
		    
				URL url = httpRequest.getUrl();
				if(url.getProtocol().equals("http"))
				{
					useHttps = false;
				}
				else
				{
					useHttps = true;
				}
			
				
				
				
				
			//Payload 2, CRLF appended to URL, get the first header and append payload
			if(i==2)
			{
				String urlString = url.getPath();
				if(urlString.endsWith("/"))
				{
					urlString = urlString + PayloadGenerator.CRLF_PAYLOAD_1;
				}
				else
				{
					urlString = urlString + "/" + PayloadGenerator.CRLF_PAYLOAD_1;
				}
				
				requestHeaders = httpRequest.getHeaders();
				requestHeaders.set(0, httpRequest.getMethod() + " " + urlString + " " + "HTTP/1.1");
				
				payload = helper.buildHttpMessage(requestHeaders, httpRequestText.substring(httpRequest.getBodyOffset()).getBytes());
			}
		    //END OF PAYLOAD 2
			
			queue.push(new HttpRequest(url.getHost(), url.getPort(), useHttps, payload, new HttpRequestContext("crlf", i, requestID, httpRequestText)));

		}

	}
	
	public void sendXSSPayload(IHttpRequestResponse message)
	{
		
		//1) A cheap weak <script>alert(1)<script> on all parameters --> actually we need some way to detect payload this will be tougher. Need to emulate a browser for this 
		
	}
	
	//Test to see if payloads work properly
	public void sendXXEPayloads(IHttpRequestResponse messageInfo, int numberOfPayloads)
	{
		//TODO Youre missing file lookup payloads etc which may give us attack vectors
		/*
		 * Payload #
		 * 1 - Original Path and Query Params, (GET/POST) with body host lookup payload, content type app xml
		 * 2 - Original Path and Query Params, (GET/POST) with body host lookup payload, content type text xml
		 * 3 - Same as (1) but without query params
		 * 4 - Same as (2) but without query params
		 * 5 - DNS lookup
		 * 6 - Timing based 
		 * 
		 */
		
		//PrePayload
				byte[] payload;
				boolean useHttps = true;
				List<String> headers;
				String httpRequestText;
				String body = "";
				IRequestInfo httpRequest;

								
				httpRequestText = new String(messageInfo.getRequest());
				httpRequest = helper.analyzeRequest(messageInfo);
				
				headers = httpRequest.getHeaders();

		//Add Payload
			
			//Each loop uses a stronger XXE pattern
			for(int i = 1; i<=numberOfPayloads; i++)
			{
				//Generate unique ID
				String requestID = createID();
				int index = 0;
				
				for(String header:headers)
				{
					
					if(header.toLowerCase().contains("Content-Type".toLowerCase()))
					{
						if(i == 1)
						{
							if(header.contains("Content-Type"))
							{
							headers.set(index, "Content-Type: application/xml");
							}
							else
							{
								headers.set(index, "Content-type: application/xml");

							}
						}
						else if(i == 2)
						{
							if(header.contains("Content-Type"))
							{
							headers.set(index, "Content-Type: text/xml");
							}
							else{
								headers.set(index, "Content-type: text/xml");

							}
						}
					}
					index++;
				}
				
				
				switch (i)
				{
				case 1:
					body = PayloadGenerator.getXXEBody_1(requestNumber);
					break;
				case 2:
					body = PayloadGenerator.getXXEBody_1(requestNumber);
					break;
				}
				
				//payload = helper.buildHttpMessage(headers, httpRequestText.substring(httpRequest.getBodyOffset()).getBytes());
				payload = helper.buildHttpMessage(headers, body.getBytes());
				
				//Send Payload
				URL url = httpRequest.getUrl();
				if(url.getProtocol().equals("http"))
				{
					useHttps = false;
				}
				else
				{
					useHttps = true;
				}
				
				
			}
		
		
	}

	public void attachCallbackInterface(IBurpExtenderCallbacks callbacks) {
		// TODO Auto-generated method stub
		this.callbacks = callbacks;
	}

	public void attachTab(Tab khrono) {
		// TODO Auto-generated method stub
		this.khrono = khrono;
	}
	
	public void attachQueue(ThrottleQueue queue) {
		// TODO Auto-generated method stub
		this.queue = queue;
	}
	
	public boolean isBlacklisted(String hostname)
	{
		for(String host:khrono.blackList)
		{
			if(hostname.toLowerCase().contains(host.toLowerCase()))
			{
				return true;
			}
		}
		return false;
		
	}
	
	
	public class HttpWorker extends Thread{

		public long requestBuffer = 1000; //Make modifiable from screen 
		ThrottleQueue queue;
		
		public HttpWorker(ThrottleQueue queue) {

			this.queue = queue;
		}


		@Override
		public void run() {
			
			HttpRequest request = queue.pop();
			
			if(request.context.payloadType.equals("redirect"))
			{
				RedirectParser(request);
			}
			else if(request.context.payloadType.equals("crlf"))
			{
				CRLFParser(request);
			}
			else if(request.context.payloadType.equals("xss"))
			{
				XXEParser(request);
			}
			
			try {
				Thread.sleep(requestBuffer);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		private void XXEParser(HttpRequest request) {
			
			
			//Payload designed based on payload number, dont need to switch case here

			byte[] response = callbacks.makeHttpRequest(url.getHost(), url.getPort(), useHttps, payload);
			

			if(!khrono.debugBox.isSelected())
			{

				
			//Log
				Logger.log("----XXE Request Number: " + requestID + " Host: " + url.getHost() + " Status: " + helper.analyzeResponse(response).getStatusCode(), Color.green);
			}
			else
			{
			//Debug 
				Logger.log("\n-----XXE Original request DEBUG-----" + "      RequestNo: " + requestID + "\n\n" + httpRequestText, Color.green);
				Logger.log("\n-----XXE Payload request DEBUG-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(payload), Color.green);
				Logger.log("\n-----XXE Payload response-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(response), Color.green);
			}
			
		}
		
		private void RedirectParser(HttpRequest request)
		{
			String requestID = request.context.requestID;
			IResponseInfo httpResponse;					
			List<String> responseHeaders;
			String httpRequestText = request.context.originalRequest;
			byte[] payload = request.payload;
			int i = request.context.payloadNumber;
			
			switch(request.context.payloadNumber)
			{
				case 1:
				{
					

					byte[] response = callbacks.makeHttpRequest(request.hostname, request.port, request.useHttps, request.payload);

					httpResponse = helper.analyzeResponse(response);
					
					responseHeaders = httpResponse.getHeaders();
					
					for(String header : responseHeaders)
					{
						if(header.toLowerCase().contains("evil.com") && !header.toLowerCase().contains(request.hostname) && header.toLowerCase().contains("location"))
						{
							Thread t = new Thread(new Runnable(){
						        public void run(){
									JOptionPane.showMessageDialog(khrono.mainPanel, "Possible OpenRedirect on request: " + requestID);
						        }
						    });
						  t.start();
							
								Logger.log("-----REDIRECT Original request DEBUG-----" + "      RequestNo: " + requestID + "\n\n" + request.context.originalRequest, Color.red);
								Logger.log("-----REDIRECT Payload request DEBUG-----" + "      RequestNo: " + requestID + " ------ Payload #: " + request.context.payloadNumber + "\n\n" + new String(request.payload), Color.red);
								Logger.log("-----REDIRECT Payload response-----" + "      RequestNo: " + requestID + " ------ Payload #: " + request.context.payloadNumber + "\n\n" + new String(response), Color.red);
						}
						
					}
					
					if(!khrono.debugBox.isSelected())
					{
					//Log
						Logger.log("----REDIRECT Request Number: " + requestID + " Host: " + request.hostname + " Status: " + helper.analyzeResponse(response).getStatusCode(), Color.DARK_GRAY);
					}
					else
					{
					//Debug 
						Logger.log("-----REDIRECT Original request DEBUG-----" + "      RequestNo: " + requestID + "\n\n" + request.context.originalRequest, Color.DARK_GRAY);
						Logger.log("-----REDIRECT Payload request DEBUG-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(request.payload), Color.DARK_GRAY);
						Logger.log("-----REDIRECT Payload response-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(response), Color.DARK_GRAY);
						
						
					}
					
					
					break;
				}
				case 2:
				{
					byte[] response = callbacks.makeHttpRequest(request.hostname, request.port, request.useHttps, request.payload);

					httpResponse = helper.analyzeResponse(response);
					
					responseHeaders = httpResponse.getHeaders();
					
					for(String header : responseHeaders)
					{
						if(header.toLowerCase().contains("evil.com") && !header.toLowerCase().contains(request.hostname) && header.toLowerCase().contains("location"))
						{
							Thread t = new Thread(new Runnable(){
						        public void run(){
									JOptionPane.showMessageDialog(khrono.mainPanel, "Possible OpenRedirect on request: " + requestID);
						        }
						    });
						  t.start();
							
								Logger.log("-----REDIRECT Original request DEBUG-----" + "      RequestNo: " + requestID + "\n\n" + httpRequestText, Color.red);
								Logger.log("-----REDIRECT Payload request DEBUG-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(payload), Color.red);
								Logger.log("-----REDIRECT Payload response-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(response), Color.red);
						}
						
					}
					
					if(!khrono.debugBox.isSelected())
					{
					//Log
						Logger.log("----REDIRECT Request Number: " + requestID + " Host: " + request.hostname + " Status: " + helper.analyzeResponse(response).getStatusCode(), Color.DARK_GRAY);
					}
					else
					{
					//Debug 
						Logger.log("-----REDIRECT Original request DEBUG-----" + "      RequestNo: " + requestID + "\n\n" + httpRequestText, Color.DARK_GRAY);
						Logger.log("-----REDIRECT Payload request DEBUG-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(payload), Color.DARK_GRAY);
						Logger.log("-----REDIRECT Payload response-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(response), Color.DARK_GRAY);
						
						
					}
					
					
					break;
				}
				
				case 3:
				{
					byte[] response = callbacks.makeHttpRequest(request.hostname, request.port, request.useHttps, request.payload);

					httpResponse = helper.analyzeResponse(response);
					
					responseHeaders = httpResponse.getHeaders();
					
					for(String header : responseHeaders)
					{
						if(header.toLowerCase().contains("evil.com") && !header.toLowerCase().contains(request.hostname) && header.toLowerCase().contains("location"))
						{
							Thread t = new Thread(new Runnable(){
						        public void run(){
									JOptionPane.showMessageDialog(khrono.mainPanel, "Possible OpenRedirect on requesdt: " + requestID);
						        }
						    });
						  t.start();
							
								Logger.log("-----REDIRECT Original request DEBUG-----" + "      RequestNo: " + requestID + "\n\n" + httpRequestText, Color.red);
								Logger.log("-----REDIRECT Payload request DEBUG-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(payload), Color.red);
								Logger.log("-----REDIRECT Payload response-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(response), Color.red);
						}
						
					}
					
					if(!khrono.debugBox.isSelected())
					{
					//Log
						Logger.log("----REDIRECT Request Number: " + requestID + " Host: " + request.hostname + " Status: " + helper.analyzeResponse(response).getStatusCode(), Color.DARK_GRAY);
					}
					else
					{
					//Debug 
						Logger.log("-----REDIRECT Original request DEBUG-----" + "      RequestNo: " + requestID + "\n\n" + httpRequestText, Color.DARK_GRAY);
						Logger.log("-----REDIRECT Payload request DEBUG-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(payload), Color.DARK_GRAY);
						Logger.log("-----REDIRECT Payload response-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(response), Color.DARK_GRAY);						
					}
					break;
				}
			}
			
		}
		
		private void CRLFParser(HttpRequest request)
		{
			List<String> responseHeaders;
			String requestID = request.context.requestID;
			String httpRequestText = request.context.originalRequest;
			byte[] payload = request.payload;
			int i = request.context.payloadNumber;

			
			//Payload designed based on payload number, dont need to switch case here
			
			byte[] response = callbacks.makeHttpRequest(request.hostname, request.port, request.useHttps, request.payload);
			responseHeaders = helper.analyzeResponse(response).getHeaders();
			
			//Scan if failed CRLF test
			for(String header : responseHeaders)
			{
				if(header.toLowerCase().startsWith("PAYLOAD".toLowerCase()))
				{
									 
					//Problem with this is its blocking, lets jus put it through its own thread
					Thread t = new Thread(new Runnable(){
				        public void run(){
							JOptionPane.showMessageDialog(khrono.mainPanel, "Possible CRLF on request: " + requestID);
				        }
				    });
				  t.start();
					
						Logger.log("-----CRLF Original request DEBUG-----" + "      RequestNo: " + requestID + "\n\n" + httpRequestText, Color.red);
						Logger.log("-----CRLF Payload request DEBUG-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(payload), Color.red);
						Logger.log("-----CRLF Payload response-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(response), Color.red);
					
				}
			}
	
	
			if(!khrono.debugBox.isSelected())
			{
			//Log
				Logger.log("----CRLF Request Number: " + requestID + " Host: " + request.hostname + " Status: " + helper.analyzeResponse(response).getStatusCode(), Color.MAGENTA);
			}
			else
			{
			//Debug 
				Logger.log("-----CRLF Original request DEBUG-----" + "      RequestNo: " + requestID + "\n\n" + httpRequestText, Color.MAGENTA);
				Logger.log("-----CRLF Payload request DEBUG-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(payload), Color.MAGENTA);
				Logger.log("-----CRLF Payload response-----" + "      RequestNo: " + requestID + " ------ Payload #: " + i + "\n\n" + new String(response), Color.MAGENTA);
				
				
			}
			
		}

	}


}
