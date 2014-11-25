package org.zaproxy.zap.extension.domxss;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.ElementNotVisibleException;
import org.openqa.selenium.UnhandledAlertException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.ie.InternetExplorerDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

public class TestDomXSS extends AbstractDomAppPlugin 
{
	private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_8");
    private static Logger log = Logger.getLogger(TestDomXSS.class);
    private static final int LOCATION_HASH = 1;
    private static final int LOCATION = 2;
    private static final int LOCATION_SEARCH = 3;
    private static final int REFERRER = 4;
    
//    private static final int [] sources = {LOCATION_HASH, LOCATION, LOCATION_SEARCH, REFERRER};
    private static final int [] sources = {REFERRER};
  
    public static String [] locationHashAttackStrings = {
		"alert(1)",//if eval sink
		"<script>alert(1)</script>",
		"<img src=\"random.gif\" onerror=alert(1)>",
		"abc#<script>alert(1)</script>", // If document.write is the sink
		"abc#<img src='random.gif' onerror=alert(1)",
		"javascript:alert(1)"
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
    
    @Override
    public int getId() {
        return 10049;
    }

    @Override
    public String getName() {
    	 if (vuln != null) {
             return vuln.getAlert() + " (DOM Based)";
     }
     return "Cross Site Scripting (DOM Based)";
    }

    @Override
    public String[] getDependency() {
        return null;
    }

    @Override
    public String getDescription() {
    	if (vuln != null) {
    		return vuln.getDescription();
    	}
    	return "Failed to load vulnerability description from file";
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
    	if (vuln != null) {
    		return vuln.getSolution();
    	}
    	return "Failed to load vulnerability solution from file";
    }

    @Override
    public String getReference() {
    	if (vuln != null) {
    		StringBuilder sb = new StringBuilder();
    		for (String ref : vuln.getReferences()) {
    			if (sb.length() > 0) {
    				sb.append('\n');
    			}
    			sb.append(ref);
    		}
    		return sb.toString();
    	}
    	return "Failed to load vulnerability reference from file";
    }

    @Override
    public void init() {
    }
    
    @Override
	public void scan()
	{
    	System.setProperty("webdriver.chrome.driver", "C:\\Users\\IEUser\\Downloads\\ZAP\\workspace_zap\\workspace-zap\\zaproxy\\lib\\chromedriver.exe");
    	System.setProperty("webdriver.ie.driver", "C:\\Users\\IEUser\\Downloads\\ZAP\\workspace_zap\\workspace-zap\\zaproxy\\lib\\IEDriverServer.exe");
    	
    	HttpMessage msg = getBaseMsg();
    	String url = msg.getRequestHeader().getURI().toString();
    	String currURL = new String();
    	String attackVector = new String();
    	
    	WebDriver firefoxDriver = null;
    	WebDriver chromeDriver = null;
    	WebDriver ieDriver = null;
    	 	
    	for(int source : sources)
    	{
    		switch(source)
    		{
    			case LOCATION_HASH:
    				for(String attackStr : locationHashAttackStrings)
    				{
    					currURL = url + "#" + attackStr;
    					
    					firefoxDriver = new FirefoxDriver();
    					try
    					{
    						scanHelperLocationHash(firefoxDriver, attackStr, currURL);
    					}
    					catch(UnhandledAlertException uae)
    					{
    						bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in firefox", msg);
    						return;
    					}
    					finally
    					{
    						firefoxDriver.close();
    					}
    					
    					chromeDriver = new ChromeDriver();
    					try
    					{
    						scanHelperLocationHash(chromeDriver, attackStr, currURL);
    					}
    					catch(UnhandledAlertException uae)
    					{
    						bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in Chrome", msg);
    						return;
    					}
    					finally
    					{
    						chromeDriver.close();
    					}
    					
    					ieDriver = new InternetExplorerDriver();
    					try
    					{
    						scanHelperLocationHash(ieDriver, attackStr, currURL);
    					}
    					catch(UnhandledAlertException uae)
    					{
    						bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in Internet Explorer", msg);
    						return;
    					}
    					finally
    					{
    						ieDriver.close();
    					}
    				}
    				break;
    			case LOCATION_SEARCH:
    				for(String attackStr : locationSearchAttackStrings)
    				{
    					currURL = url + attackStr;
    					
    					firefoxDriver = new FirefoxDriver();
    					try
    					{
    						scanHelperLocationHash(firefoxDriver, attackStr, currURL);
    					}
    					catch(UnhandledAlertException uae)
    					{
    						bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in firefox", msg);
    						return;
    					}
    					finally
    					{
    						firefoxDriver.close();
    					}
    					
    					chromeDriver = new ChromeDriver();
    					try
    					{
    						scanHelperLocationHash(chromeDriver, attackStr, currURL);
    					}
    					catch(UnhandledAlertException uae)
    					{
    						bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in Chrome", msg);
    						return;
    					}
    					finally
    					{
    						chromeDriver.close();
    					}
    					
    					ieDriver = new InternetExplorerDriver();
    					try
    					{
    						scanHelperLocationHash(ieDriver, attackStr, currURL);
    					}
    					catch(UnhandledAlertException uae)
    					{
    						bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in Internet Explorer", msg);
    						return;
    					}
    					finally
    					{
    						ieDriver.close();
    					}
    				}
    				break;
    			case LOCATION:
    				for(String attackStr : locationAttackStrings)
    				{
    					currURL = url + attackStr;
    					
    					firefoxDriver = new FirefoxDriver();
    					try
    					{
    						scanHelperLocationHash(firefoxDriver, attackStr, currURL);
    					}
    					catch(UnhandledAlertException uae)
    					{
    						bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in firefox", msg);
    						return;
    					}
    					finally
    					{
    						firefoxDriver.close();
    					}
    					
    					chromeDriver = new ChromeDriver();
    					try
    					{
    						scanHelperLocationHash(chromeDriver, attackStr, currURL);
    					}
    					catch(UnhandledAlertException uae)
    					{
    						bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in Chrome", msg);
    						return;
    					}
    					finally
    					{
    						chromeDriver.close();
    					}
    					
    					ieDriver = new InternetExplorerDriver();
    					try
    					{
    						scanHelperLocationHash(ieDriver, attackStr, currURL);
    					}
    					catch(UnhandledAlertException uae)
    					{
    						bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in Internet Explorer", msg);
    						return;
    					}
    					finally
    					{
    						ieDriver.close();
    					}
    				}
    				break;
    			case REFERRER:
    				for(String attackStr : referrerAttackStrings)
    				{
    					currURL = url + attackStr;
    					
    					firefoxDriver = new FirefoxDriver();
    					try
    					{
    						scanHelperLocationHash(firefoxDriver, attackStr, currURL);
    					}
    					catch(UnhandledAlertException uae)
    					{
    						bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in firefox", msg);
    						//return;
    					}
    					finally
    					{
    						firefoxDriver.close();
    					}
    					
    					chromeDriver = new ChromeDriver();
    					try
    					{
    						scanHelperLocationHash(chromeDriver, attackStr, currURL);
    					}
    					catch(UnhandledAlertException uae)
    					{
    						bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in Chrome", msg);
    						//return;
    					}
    					finally
    					{
    						chromeDriver.close();
    					}
    					
    					ieDriver = new InternetExplorerDriver();
    					try
    					{
    						scanHelperLocationHash(ieDriver, attackStr, currURL);
    					}
    					catch(UnhandledAlertException uae)
    					{
    						bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in Internet Explorer", msg);
    						//return;
    					}
    					finally
    					{
    						ieDriver.close();
    					}
    				}
    				break;
    		}
    	}
	}
    
 //   private void scanHelperReferrer(WebDriver, String attackVector, String url) throws Un
    private void scanHelperLocationHash(WebDriver driver, String attackVector, String url) throws UnhandledAlertException
	{
		driver.get(url);
		List<WebElement> inputElements = driver.findElements(By.tagName("input"));
		for(WebElement element : inputElements)
		{
			driver.get(url);
			element.sendKeys(attackVector);
			element.click();
		}
		List<WebElement>allElements = driver.findElements(By.tagName("div"));
		System.out.println(allElements.size());
		for(WebElement element : allElements)
		{
			System.out.println("Now clicking on " + element.getTagName());
			try
			{
				driver.get(url);
				element.click();
			}
			catch(ElementNotVisibleException enve)
			{
				System.out.println("Element not visible exception encountered");
			}
		}
	}
	@Override
	public int getRisk() {
		return Alert.RISK_MEDIUM;
	}

	@Override
	public int getCweId() {
		return 0;
	}

	@Override
	public int getWascId() {
		return 0;
	}
}

