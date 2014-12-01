package org.zaproxy.zap.extension.domxss;

import java.util.ArrayList;

import org.apache.log4j.Logger;
import org.openqa.selenium.UnhandledAlertException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.ie.InternetExplorerDriver;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;

public abstract class AbstractDomAppPlugin extends AbstractAppPlugin {

	private static Logger log = Logger.getLogger(AbstractDomAppPlugin.class);
	
	private static final int LOCATION_HASH = 0;
    private static final int LOCATION = 1;
    private static final int LOCATION_SEARCH = 2;
    private static final int REFERRER = 3;
    
    private static final int [] sources = {LOCATION_HASH, LOCATION, LOCATION_SEARCH, REFERRER};
  
    public static String [] locationHashAttackStrings = {
		"#alert(1)",//if eval sink
		"#<script>alert(1)</script>",
		"#<img src=\"random.gif\" onerror=alert(1)>",
		"#abc#<script>alert(1)</script>", // If document.write is the sink
		"#abc#<img src='random.gif' onerror=alert(1)",
		"#javascript:alert(1)"
		};
    
    public static String [] locationAttackStrings = {
    	"#<script>alert(1)</script>",
    	"?name=abc#<img src=\"random.gif\" onerror=alert(1)>",
    	"#<img src=\"random.gif\" onerror=alert(1)>",
    };
    
    public static String [] locationSearchAttackStrings = {
    	"?name=<img src=\"random.gif\" onerror=alert(1)>"
    };
   
    public static String [] referrerAttackStrings = {
    	"?name=<img src=\"random.gif\" onerror=alert(1)>"
    };
    
    public static ArrayList<String[]> attackVectors;
	@Override
	public int getCategory() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public String[] getDependency() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getDescription() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getId() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getReference() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getSolution() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void init() {
		// TODO Auto-generated method stub

	}

	@Override
	public void scan() {
		// TODO Auto-generated method stub
		attackVectors = new ArrayList<String[]>();
		attackVectors.add(locationHashAttackStrings);
		attackVectors.add(locationAttackStrings);
		attackVectors.add(locationSearchAttackStrings);
		attackVectors.add(referrerAttackStrings);
		
		for(int source : sources)
		{
			try
			{
				scan(source);
			}
			catch(UnhandledAlertException uae)
			{
				break;
			}
		}
	}
	
	public void scan(int source) throws UnhandledAlertException
	{
		for(String attackVector : attackVectors.get(source))
		{
			ArrayList<WebDriver> drivers = new ArrayList<WebDriver>();
		/*	WebDriver firefoxDriver = new FirefoxDriver();
			drivers.add(firefoxDriver);
			try
			{
				WebDriver chromeDriver = new ChromeDriver();
				drivers.add(chromeDriver);
			}
			catch(IllegalStateException ise)
			{
				log.debug("Chrome Web Driver property is not set.", ise);
			}
			try
			{
				WebDriver ieDriver = new InternetExplorerDriver();
				drivers.add(ieDriver);
			}
			catch(IllegalStateException ise)
			{
				log.debug("Internet Explorer Web Driver property is not set.", ise);
			}*/
			try
			{
				scan(source, drivers, attackVector);
			}
			catch(UnhandledAlertException uae)
			{
				throw uae;
			}
		}
	}
	
	public void scan(int source, ArrayList<WebDriver> drivers, String attackVector) throws UnhandledAlertException
	{
/*		for(int i = 0; i < drivers.size(); i++)
		{
			WebDriver driver = drivers.get(i);
			try
			{
				scan(source, driver, attackVector);
			}
			catch(UnhandledAlertException uae)
			{
				throw uae;
				
			}
		}
	*/}
	/*
	public void scan(int source, WebDriver driver, String attackVector) throws UnhandledAlertException
	{
		
	}
	*/
}
