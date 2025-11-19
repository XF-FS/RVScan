/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit;

import APIKit.ContextMenu;
import APIKit.CookieManager;
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IExtensionStateListener;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import APIKit.PassiveScanner;
import APIKit.ScanConfig;
import APIKit.ui.ConfigPanel;
import APIKit.ui.ExtensionTab;
import APIKit.ui.TargetAPIScan;

import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;

public class BurpExtender
        implements IBurpExtender,
        IExtensionStateListener {
    public static String VERSION = "1.6.3";
    public static String NAME = "APIKit";
    public static String FULLNAME = NAME + "pro v" + VERSION;
    public static HashMap<String, String> TargetAPI = new HashMap();
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static ConfigPanel configPanel;
    private static CookieManager cookieManager;
    private static ExtensionTab extensionTab;
    private static PassiveScanner passiveScanner;

    public static void clearPassiveScannerCache() {
        passiveScanner.clearUrlScanedCache();
    }

    public static PrintWriter getStdout() {
        return stdout;
    }

    public static PrintWriter getStderr() {
        return stderr;
    }

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static IExtensionHelpers getHelpers() {
        return helpers;
    }

    public static ConfigPanel getConfigPanel() {
        return configPanel;
    }

    public static void setConfigPanel(ConfigPanel configPanel) {
        BurpExtender.configPanel = configPanel;
    }

    public static CookieManager getCookieManager() {
        return cookieManager;
    }

    public static ExtensionTab getExtensionTab() {
        return extensionTab;
    }

    public static PassiveScanner getPassiveScanner() {
        return passiveScanner;
    }

    public static void startNewScan(ScanConfig config) {
        TargetAPI.put("BasePathURL", config.getBasePathURL());
        TargetAPI.put("APIDocumentURL", config.getApiDocumentURL());
        TargetAPI.put("Header", String.join((CharSequence) "\n", config.getHeaders()));
        TargetAPI.put("APITypename", config.getApiTypeName());
        if (config.getHttpService() != null) {
            TargetAPI.put("CustomHost", config.getHttpService().getHost());
            TargetAPI.put("CustomPort", String.valueOf(config.getHttpService().getPort()));
            TargetAPI.put("CustomProtocol", config.getHttpService().getProtocol());
        } else {
            TargetAPI.remove("CustomHost");
            TargetAPI.remove("CustomPort");
            TargetAPI.remove("CustomProtocol");
        }
        TargetAPIScan targetAPIScan = new TargetAPIScan();
        targetAPIScan.start();
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        extensionTab = new ExtensionTab(NAME);
        cookieManager = new CookieManager();
        passiveScanner = new PassiveScanner();
        callbacks.registerScannerCheck(new IScannerCheck() {

            @Override
            public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
                if (!extensionTab.getConfigPanel().getScannerEnabled().booleanValue()) {
                    return null;
                }
                return passiveScanner.doPassiveScan(baseRequestResponse);
            }

            @Override
            public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
                return null;
            }

            @Override
            public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
                return 0;
            }
        });
        callbacks.registerHttpListener(cookieManager);
        callbacks.registerContextMenuFactory(new ContextMenu());
        System.setOut(new PrintStream(callbacks.getStdout()));
        System.setErr(new PrintStream(callbacks.getStderr()));
        callbacks.setExtensionName(FULLNAME);
        stdout.println("===================================");
        stdout.println(String.format("%s load success!", FULLNAME));
        stdout.println("Author: XF-FS");
        stdout.println("Project address: https://github.com/XF-FS/APIKit");
        stdout.println("Thank: https://github.com/API-Security/APIKit");
        stdout.println("===================================");
        callbacks.registerExtensionStateListener(this);
    }

    @Override
    public void extensionUnloaded() {
        if (passiveScanner != null) {
            passiveScanner.clearUrlScanedCache();
        }
        stdout = null;
        stderr = null;
        callbacks = null;
        helpers = null;
        configPanel = null;
        cookieManager = null;
        extensionTab = null;
        passiveScanner = null;
    }
}

