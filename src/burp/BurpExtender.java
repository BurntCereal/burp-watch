package burp;

import javax.swing.SwingUtilities;

import watcher.HttpListener;
import watcher.Tab;
import watcher.ThrottleQueue;

public class BurpExtender implements IBurpExtender {
	
	 private IExtensionHelpers httpHelper;
	 
	 Tab khronoTab = new Tab();
	 
	 HttpListener listener = new HttpListener();
	 
	 ThrottleQueue queue;
	
	public BurpExtender()
	{
		
	}
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		// TODO Auto-generated method stub
		
		queue = new ThrottleQueue();
		
		//UI stuff
		callbacks.setExtensionName("TheWatcher");
		callbacks.addSuiteTab(khronoTab);
		//callbacks.customizeUiComponent(khronoTab.mainFrame);
		callbacks.customizeUiComponent(khronoTab.mainPanel);
	//	callbacks.customizeUiComponent(khronoTab.xxeCheckBox);
		callbacks.customizeUiComponent(khronoTab.sp);
	//	callbacks.customizeUiComponent(khronoTab.logArea);
		
		//Pass needed objects to main processor (http listener)
		httpHelper = callbacks.getHelpers();
		listener.attachHelperParser(callbacks.getHelpers());
		listener.attachTab(khronoTab);
		listener.attachCallbackInterface(callbacks);
		listener.attachQueue(queue);
		
		
		//Enable SSH for testing exfiltration
		//SSHManager sshManager = new SSHManager();
		
		
		
		callbacks.registerHttpListener(listener);

	}

	
	
	
	
	
}
