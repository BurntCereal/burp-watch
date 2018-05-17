package watcher;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Panel;
import java.awt.TextArea;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JLayeredPane;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRootPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

import burp.ITab;

//UI actions and layout

//Components using listeners will call 'this' objects listener methods
public class Tab implements ITab, FocusListener, KeyListener, ActionListener{

	String tabName = "The Watcher";
	//public JFrame mainFrame = new JFrame();

	GridBagLayout layout = new GridBagLayout();
	public JPanel mainPanel = new JPanel(layout);
	GridBagConstraints c = new GridBagConstraints();
	
	public JTextField searchField = new JTextField();
	
	public JScrollPane sp = new JScrollPane(Logger.styledLog);
	
	public JTextField blackListText = new JTextField();
	
	public JTextField queueRateText = new JTextField();
	public JLabel queueBufferSizeLabel = new JLabel();
	
	JCheckBox xxeCheckBox = new JCheckBox();
	JCheckBox crlfBox = new JCheckBox();
	JCheckBox debugBox = new JCheckBox();
	JCheckBox openRedirectBox = new JCheckBox();
	
	public static boolean scrollLock = false; 
	
	public String[] blackList = {};
	
	// Set of currently pressed keys
    private final Set<Integer> pressed = new HashSet<Integer>();
	
    //messy and unreadable initialization of components
	public Tab()
	{
		
		// fix so its not hard coded values
		//layout.minimumLayoutSize(mainFrame);
		
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 0;
		c.gridy = 0;
		c.weightx = 0.5;
		mainPanel.add(xxeCheckBox, c);
		
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 1;
		c.gridy = 0;
		c.weightx = 0.5;
		mainPanel.add(crlfBox, c);
		
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 2;
		c.gridy = 0;
		c.weightx = 0.5;
		mainPanel.add(openRedirectBox, c);
		
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 3;
		c.gridy = 0;
		c.weightx = 0.5;
		mainPanel.add(debugBox, c);
		
		c.fill = GridBagConstraints.HORIZONTAL;
		c.anchor = GridBagConstraints.PAGE_END;
		c.gridx = 0;
		c.gridy = 1;
		c.weightx = 0;
		c.gridwidth = 4;
		//c.ipady = mainFrame.getMaximumSize().height/2;
		c.ipady = 700;
		//sp.setPreferredSize(new Dimension(mainFrame.getMaximumSize().width,500));
		
		mainPanel.add(sp,c );
		
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 0;
		c.gridy = 2;
		c.gridwidth = 4;
		c.ipady = 0;

		mainPanel.add(searchField, c);
		
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 0;
		c.gridy = 3;
		c.gridwidth = 4;
		c.ipady = 0;

		mainPanel.add(blackListText, c);
		
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 1;
		c.gridy = 4;
		c.gridwidth = 1;
		c.ipady = 0;

		mainPanel.add(queueBufferSizeLabel, c);
		
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 2;
		c.gridy = 4;
		c.gridwidth = 1;
		c.ipady = 0;

		mainPanel.add(queueRateText, c);
		
		
		queueBufferSizeLabel.setText("0 http requests pending");
		
		//Search box stuff, CTRL+F to use
		searchField.setText("Enter Search Term...");
		blackListText.setText("Hostname Ignore List...");
		
		blackListText.addActionListener(this);
		mainPanel.setFocusable(true);
		sp.setFocusable(true);
		sp.addKeyListener(this);
		searchField.setFocusable(true);
		searchField.addFocusListener(this);
		searchField.addActionListener(this);
		searchField.addKeyListener(this);

		mainPanel.addKeyListener(this);
		Logger.styledLog.setFocusable(true);
		Logger.styledLog.addKeyListener(this);
		
		//mainFrame.getContentPane().add(mainPanel);
		//mainFrame.pack();
		
		
		debugBox.setText("Enable Debug Log");
		crlfBox.setText("Enable CRLF Detector");
		openRedirectBox.setText("Enable Open Redirect");

		xxeCheckBox.setText("Enable XXE Detector");
	
		Logger.log("------------------Extension Live----------------");
		//logArea.setText("----------Extension Live--------" + "\n");
		
		Logger.log("Listening for traffic");
		
	}
	
	
	@Override
	public String getTabCaption() {
		// TODO Auto-generated method stub
		return tabName;
	}

	@Override
	public Component getUiComponent() {
		// TODO Auto-generated method stub
	
	
		
		return mainPanel;
	}


	@Override
    public synchronized void keyPressed(KeyEvent e) {

        pressed.add(e.getKeyCode());
        if (pressed.size() > 1) {
        	

            // More than one key is currently pressed.
            // Iterate over pressed to get the keys.
        	if(pressed.contains(KeyEvent.VK_CONTROL) && pressed.contains(KeyEvent.VK_F))
        	{
        		searchField.grabFocus();
  			}
        	
        	//Clear logs
        	if(pressed.contains(KeyEvent.VK_CONTROL) && pressed.contains(KeyEvent.VK_O) && pressed.contains(KeyEvent.VK_P) )
        	{
        		Logger.styledLog.setText("");
  			}
        	
        	//Quick off and on
        	if(pressed.contains(KeyEvent.VK_CONTROL) && pressed.contains(KeyEvent.VK_A))
        	{
        		if(xxeCheckBox.isSelected() || crlfBox.isSelected() || openRedirectBox.isSelected())
        		{
        		 xxeCheckBox.setSelected(false);
        		 crlfBox.setSelected(false);
        		 openRedirectBox.setSelected(false);
        		}
        		else
        		{
        			xxeCheckBox.setSelected(true);
           		 crlfBox.setSelected(true);
           		 openRedirectBox.setSelected(true);
        		}
        		
        		
        		
        	}
        	
        	//Doesnt work properly
        	if(pressed.contains(KeyEvent.VK_CONTROL) && pressed.contains(KeyEvent.VK_S) )
        	{
        		scrollLock = true;
  			}
        }
    }

    @Override
    public synchronized void keyReleased(KeyEvent e) {
        pressed.clear();
    }

	@Override
	public void keyTyped(KeyEvent arg0) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void focusGained(FocusEvent arg0) {
		// TODO Auto-generated method stub
		searchField.setText("");
	}


	@Override
	public void focusLost(FocusEvent arg0) {
		// TODO Auto-generated method stub
		
	}


	@Override
	public void actionPerformed(ActionEvent arg0) {
		// TODO Auto-generated method stub
	    //String text = searchField.getText();
	   // Logger.search();
		
		//read in blacklist
		String hosts = blackListText.getText();
		blackList = hosts.split(",");
		Thread t = new Thread(new Runnable(){
	        public void run(){
				JOptionPane.showMessageDialog(mainPanel, "Blacklist Updated");
	        }
	    });
	  t.start();
		
	}
	
	
	
	
	
	

}
