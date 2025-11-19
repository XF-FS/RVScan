package APIKit.ui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import APIKit.ui.apitable.ApiDetailEntity;
import APIKit.ui.apitable.ApiDetailTable;
import APIKit.ui.apitable.ApiDocumentEntity;
import APIKit.ui.apitable.ApiDocumentTable;

import javax.swing.*;
import java.awt.*;

/**
 * APIKit面板组件，用于集成到RVScan的Tags中
 */
public class ApiKitPanel extends JSplitPane {
    private final ApiDocumentTable apiDocumentTable;
    private final ApiDetailTable apiDetailTable;
    private final HttpRequestResponsePanel httpRequestResponsePanel;
    private final ConfigPanel configPanel;

    public ApiKitPanel(IBurpExtenderCallbacks callbacks) {
        super(JSplitPane.HORIZONTAL_SPLIT);
        
        // 创建配置面板
        this.configPanel = new ConfigPanel();
        
        // 创建请求/响应面板
        this.httpRequestResponsePanel = new HttpRequestResponsePanel(callbacks);
        
        // 创建API详情表格
        this.apiDetailTable = new ApiDetailTable(entity -> {
            if (entity != null && entity.requestResponse != null) {
                httpRequestResponsePanel.setHttpRequestResponse(entity.requestResponse);
            }
        });
        
        // 创建API文档表格
        this.apiDocumentTable = new ApiDocumentTable(entity -> {
            if (entity != null) {
                apiDetailTable.setApiDetail(entity);
                if (entity.requestResponse != null) {
                    httpRequestResponsePanel.setHttpRequestResponse(entity.requestResponse);
                }
            }
        });
        
        // 设置清理历史回调
        this.configPanel.addClearHistoryCallback(() -> {
            apiDetailTable.clear();
            apiDocumentTable.clear();
            httpRequestResponsePanel.clear();
        });
        
        // 创建左侧面板：配置面板 + API表格
        JSplitPane leftPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        leftPanel.setEnabled(false);
        
        JSplitPane apiTablePanel = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        apiTablePanel.add(new JScrollPane(apiDocumentTable), "left");
        apiTablePanel.add(new JScrollPane(apiDetailTable), "right");
        apiTablePanel.setResizeWeight(0.5);
        
        leftPanel.add(configPanel, "top");
        leftPanel.add(apiTablePanel, "bottom");
        leftPanel.setResizeWeight(0.3);
        
        // 设置主面板
        this.add(leftPanel, "left");
        this.add(httpRequestResponsePanel, "right");
        this.setResizeWeight(0.6);
    }
    
    /**
     * 添加API文档到表格
     */
    public void addApiDocument(ApiDocumentEntity apiDocumentEntity) {
        if (apiDocumentTable != null) {
            apiDocumentTable.append(apiDocumentEntity);
        }
    }
    
    /**
     * 清空所有数据
     */
    public void clear() {
        if (apiDocumentTable != null) {
            apiDocumentTable.clear();
        }
        if (apiDetailTable != null) {
            apiDetailTable.clear();
        }
        if (httpRequestResponsePanel != null) {
            httpRequestResponsePanel.clear();
        }
    }
    
    /**
     * 获取配置面板
     */
    public ConfigPanel getConfigPanel() {
        return configPanel;
    }
}

