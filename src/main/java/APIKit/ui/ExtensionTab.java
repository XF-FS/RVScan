/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.ui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.ITab;
import APIKit.ui.ConfigPanel;
import APIKit.ui.HttpRequestResponsePanel;
import APIKit.ui.apitable.ApiDetailTable;
import APIKit.ui.apitable.ApiDocumentEntity;
import APIKit.ui.apitable.ApiDocumentTable;

import java.awt.Component;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import APIKit.BurpExtenderAdapter;

public class ExtensionTab
        implements ITab {
    private final String tagName;
    private final ConfigPanel configPanel;
    private JSplitPane mainPanel;
    private ApiDocumentTable apiDocumentTable;

    public ExtensionTab(String name) {
        final IBurpExtenderCallbacks callbacks = BurpExtenderAdapter.getCallbacks();
        this.tagName = name;
        this.configPanel = new ConfigPanel();
        SwingUtilities.invokeLater(new Runnable() {

            @Override
            public void run() {
                ExtensionTab.this.mainPanel = new JSplitPane(0);
                HttpRequestResponsePanel httpRequestResponsePanel = new HttpRequestResponsePanel(callbacks);
                JSplitPane apiTableAndConfigPanel = new JSplitPane(0);
                apiTableAndConfigPanel.setEnabled(false);
                BurpExtender.setConfigPanel(ExtensionTab.this.configPanel);
                ApiDetailTable apiDetailTable = new ApiDetailTable(entity -> httpRequestResponsePanel.setHttpRequestResponse(entity.requestResponse));
                JSplitPane apiTablePanel = new JSplitPane(0);
                ExtensionTab.this.apiDocumentTable = new ApiDocumentTable(entity -> {
                    apiDetailTable.setApiDetail((ApiDocumentEntity) entity);
                    httpRequestResponsePanel.setHttpRequestResponse(entity.requestResponse);
                });
                ExtensionTab.this.configPanel.addClearHistoryCallback(() -> {
                    apiDetailTable.clear();
                    ExtensionTab.this.apiDocumentTable.clear();
                    httpRequestResponsePanel.clear();
                    BurpExtender.clearPassiveScannerCache();
                });
                apiTablePanel.add((Component) new JScrollPane(ExtensionTab.this.apiDocumentTable), "left");
                apiTablePanel.add((Component) new JScrollPane(apiDetailTable), "right");
                apiTablePanel.setResizeWeight(0.5);
                apiTableAndConfigPanel.add((Component) ExtensionTab.this.configPanel, "left");
                apiTableAndConfigPanel.add((Component) apiTablePanel, "right");
                ExtensionTab.this.mainPanel.add((Component) apiTableAndConfigPanel, "left");
                ExtensionTab.this.mainPanel.add((Component) httpRequestResponsePanel, "right");
                ExtensionTab.this.mainPanel.setResizeWeight(0.5);
                callbacks.customizeUiComponent(ExtensionTab.this.mainPanel);
                callbacks.addSuiteTab(ExtensionTab.this);
            }
        });
    }

    @Override
    public String getTabCaption() {
        return this.tagName;
    }

    @Override
    public Component getUiComponent() {
        return this.mainPanel;
    }

    public void addApiDocument(ApiDocumentEntity apiDocumentEntity) {
        this.apiDocumentTable.append(apiDocumentEntity);
    }

    public ConfigPanel getConfigPanel() {
        return this.configPanel;
    }
}

