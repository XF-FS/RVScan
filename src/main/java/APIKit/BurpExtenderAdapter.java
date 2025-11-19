package APIKit;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IScanIssue;
import APIKit.ui.ConfigPanel;
import APIKit.PassiveScanner;

import java.io.PrintWriter;
import java.util.List;
import APIKit.BurpExtenderAdapter;

/**
 * BurpExtender适配器，提供静态方法供APIKit使用
 * 在RVScan中，这些方法会委托给实际的callbacks和helpers
 */
public class BurpExtenderAdapter {
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static PassiveScanner passiveScanner;
    private static ConfigPanel configPanel;
    private static java.util.HashMap<String, String> targetAPI = new java.util.HashMap<>();
    
    public static void initialize(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        BurpExtenderAdapter.callbacks = callbacks;
        BurpExtenderAdapter.helpers = helpers;
    }
    
    public static void setPassiveScanner(PassiveScanner scanner) {
        BurpExtenderAdapter.passiveScanner = scanner;
    }
    
    public static void setConfigPanel(ConfigPanel panel) {
        BurpExtenderAdapter.configPanel = panel;
    }
    
    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }
    
    public static IExtensionHelpers getHelpers() {
        return helpers;
    }
    
    public static PassiveScanner getPassiveScanner() {
        return passiveScanner;
    }
    
    public static ConfigPanel getConfigPanel() {
        return configPanel;
    }
    
    public static PrintWriter getStdout() {
        if (callbacks != null) {
            return new PrintWriter(callbacks.getStdout(), true);
        }
        return null;
    }
    
    public static PrintWriter getStderr() {
        if (callbacks != null) {
            return new PrintWriter(callbacks.getStderr(), true);
        }
        return null;
    }
    
    public static java.util.HashMap<String, String> getTargetAPI() {
        return targetAPI;
    }
    
    public static void setConfigPanel(ConfigPanel panel) {
        configPanel = panel;
    }
    
    public static void clearPassiveScannerCache() {
        if (passiveScanner != null) {
            passiveScanner.clearUrlScanedCache();
        }
    }
}

