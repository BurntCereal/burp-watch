package watcher;

import java.awt.Color;

import javax.swing.JOptionPane;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

public final class Logger {

	
	static JTextPane styledLog = new JTextPane();
    static StyledDocument doc = styledLog.getStyledDocument();
    private static int lineBuffer = 0; // When over certain number of lines clear first 1000 or so..
    

    public static void log(String logEntry)
	{
        Style style = styledLog.addStyle("Main", null);
        StyleConstants.setForeground(style, Color.BLACK);
        
        try { doc.insertString(doc.getLength(), logEntry + "\n",style); }
        catch (BadLocationException e){}
        
        lineBuffer++;
        
        
        /* TEST LATER FOR CREATING A LINE BUFFER
         * 
         * Element root = pane.getDocument().getDefaultRootElement();
			Element first = root.getElement(0);
		pane.getDocument().remove(first.getStartOffset(), first.getEndOffset());
			System.out.println(pane.getText());
         */
	}
    
]    public static void log(String logEntry, Color color)
	{
        Style style = styledLog.addStyle("Main", null);
        StyleConstants.setForeground(style, color);
        
        try { doc.insertString(doc.getLength(), logEntry + "\n",style); }
        catch (BadLocationException e){}
        
        //Force scroll to bottom when not scroll locked 
       // styledLog.setCaretPosition(styledLog.getDocument().getLength());

        lineBuffer++;
 
	}

	public static void search() {
		// TODO Auto-generated method stub
		
	}
    

    
    
}
