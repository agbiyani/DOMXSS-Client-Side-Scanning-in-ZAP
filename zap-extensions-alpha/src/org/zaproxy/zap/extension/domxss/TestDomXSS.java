package org.zaproxy.zap.extension.domxss;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.ElementNotVisibleException;
import org.openqa.selenium.UnhandledAlertException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.ie.InternetExplorerDriver;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

public class TestDomXSS extends AbstractDomAppPlugin 
{
	private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_8");
    private static Logger log = Logger.getLogger(TestDomXSS.class);
 
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
 /*   
    @Override
	public void scan()
	{  
    
	}
   */ 
    private void scanHelper(WebDriver driver, String attackVector, String url) throws UnhandledAlertException
	{
		driver.get(url);
		List<WebElement> inputElements = driver.findElements(By.tagName("input"));
		//for(WebElement element : inputElements)
		for(int i = 0; i < inputElements.size(); i++)
		{
			//driver.get(url);
			WebElement element = inputElements.get(i);
			try
			{
				element.sendKeys(attackVector);
				element.click();
			}
			catch(UnhandledAlertException uae)
			{
				throw uae;
			}
			catch(WebDriverException wde)
			{
				log.debug(wde);
			}
			driver.get(url);
			inputElements = driver.findElements(By.tagName("input"));
			
		}
		List<WebElement>allElements = driver.findElements(By.tagName("div"));
	//	for(WebElement element : allElements)
		for(int i = 0; i < allElements.size(); i++)
		{
			WebElement element = allElements.get(i);
			try
			{
				//driver.get(url);
				element.click();
				driver.get(url);
				allElements = driver.findElements(By.tagName("div"));
			}
			catch(UnhandledAlertException uae)
			{
				throw uae;
			}
			catch(ElementNotVisibleException enve)
			{
				log.debug(enve);
			}
			catch(WebDriverException wde)
			{
				log.debug(wde);
			}
		}
	}
	
    
    @Override
    public void scan(int source, ArrayList<WebDriver> drivers, String attackVector) throws UnhandledAlertException
    {
    	HttpMessage msg = getBaseMsg();
    	String url = msg.getRequestHeader().getURI().toString();
    	String currURL = url + attackVector;
    	WebDriver firefoxDriver = new FirefoxDriver();
    	try
		{
			scanHelper(firefoxDriver, attackVector, currURL);
		}
		catch(UnhandledAlertException uae)
		{
			bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in Firefox ", msg);
			//return;
			throw uae;
		}
		finally
		{
			//firefoxDriver.close();
			firefoxDriver.quit();
		}
    	if(System.getProperty("webdriver.chrome.driver") != null)
    	{
    		WebDriver chromeDriver = new ChromeDriver();
        	try
    		{
    			scanHelper(chromeDriver, attackVector, currURL);
    		}
    		catch(UnhandledAlertException uae)
    		{
    			bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in Chrome ", msg);
    			//return;
    			throw uae;
    		}
    		finally
    		{
    			//chromeDriver.close();
    			chromeDriver.quit();
    		}
    	}
    	if(System.getProperty("webdriver.ie.driver") != null)
    	{
    		WebDriver ieDriver = new InternetExplorerDriver();
        	try
    		{
    			scanHelper(ieDriver, attackVector, currURL);
    		}
    		catch(UnhandledAlertException uae)
    		{
    			bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + " in Internet Explorer ", msg);
    			//return;
    			throw uae;
    		}
    		finally
    		{
    			//ieDriver.close();
    			ieDriver.quit();
    		}
    	}
    }
 /*   public void scan(int source, WebDriver driver, String attackVector) throws UnhandledAlertException
    {
    	HttpMessage msg = getBaseMsg();
    	String url = msg.getRequestHeader().getURI().toString();
    	String currURL = url + attackVector;
    	try
		{
			scanHelper(driver, attackVector, currURL);
		}
		catch(UnhandledAlertException uae)
		{
			bingo(Alert.RISK_MEDIUM, Alert.RISK_MEDIUM, url, null, attackVector, "", currURL + driver.getClass().getCanonicalName(), msg);
			//return;
			throw uae;
		}
		finally
		{
			driver.close();
		}
    }
   */ 
    
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

