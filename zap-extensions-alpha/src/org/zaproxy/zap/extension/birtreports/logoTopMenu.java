

/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *  
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.birtreports;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ResourceBundle;

import javax.swing.JMenuItem;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

/*
 * An example ZAP extension which adds a top level menu item.
 *
 * This class is defines the extension.
 */
public class logoTopMenu extends ExtensionAdaptor {

    private JMenuItem menuExample = null;
    private ResourceBundle messages = null;

        /**
     *
     */
    public logoTopMenu() {
        super();
                initialize();
    }

    /**
     * @param name
     */
    public logoTopMenu(String name) {
        super(name);
    }

        /**
         * This method initializes this
         *
         */
        private void initialize() {
        this.setName("logoTopMenu");
        // Load extension specific language files - these are held in the extension jar
        messages = ResourceBundle.getBundle(
                        this.getClass().getPackage().getName() + ".resources.Messages", Constant.getLocale());
        }
       
        @Override
        public void hook(ExtensionHook extensionHook) {
            super.hook(extensionHook);
           
            if (getView() != null) {
                // Register our top menu item, as long as we're not running as a daemon
                // Use one of the other methods to add to a different menu list
                extensionHook.getHookMenu().addReportMenuItem(getMenuExample());
            }

        }

        private JMenuItem getMenuExample() {
        if (menuExample == null) {
                menuExample = new JMenuItem();
                menuExample.setText(getMessageString("menu.birtreport.logo.upload"));

                menuExample.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                        // This is where you do what you want to do.
                        // In this case we'll just show a popup message.
                	
                	
                	ReportLastScan reportgen = new ReportLastScan();
                	reportgen.uploadLogo(getView());
                    //View.getSingleton().showMessageDialog(getMessageString("menu.birtreport.pdf.generate.success"));
                	//View.getSingleton().showMessageDialog("TEST");
                	
                }
            });
        }
        return menuExample;
    }

        public String getMessageString (String key) {
                return messages.getString(key);
        }
        @Override
        public String getAuthor() {
                return Constant.ZAP_TEAM;
        }

        @Override
        public String getDescription() {
                return messages.getString("ext.topmenu.desc");
        }

        @Override
        public URL getURL() {
                try {
                        return new URL(Constant.ZAP_EXTENSIONS_PAGE);
                } catch (MalformedURLException e) {
                        return null;
                }
        }
}

