/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes;

import burp.IHttpRequestResponse;
import APIKit.application.apitypes.ApiEndpoint;
import APIKit.application.apitypes.ApiTypeInterface;
import APIKit.BurpExtenderAdapter;

import java.util.ArrayList;
import java.util.HashMap;

public abstract class ApiType
        implements ApiTypeInterface {
    private final HashMap<String, IHttpRequestResponse> ApiDocuments = new HashMap();
    protected Boolean isPassive;
    private String apiTypeName = "";

    @Override
    public String getApiTypeName() {
        return this.apiTypeName;
    }

    protected void setApiTypeName(String value) {
        this.apiTypeName = value;
    }

    public HashMap<String, IHttpRequestResponse> getApiDocuments() {
        return this.ApiDocuments;
    }

    public ArrayList<ApiEndpoint> parseApiDocument(IHttpRequestResponse apiDocument, IHttpRequestResponse basePathURL, boolean isTargetScan) {
        return null;
    }

    @Override
    public Boolean urlAddPath(String apiDocumentUrl) {
        return false;
    }

    @Override
    public Boolean isFingerprintMatch() {
        return false;
    }

    @Override
    public java.util.List<burp.IScanIssue> exportIssues() {
        // Default implementation
        return new java.util.ArrayList<>();
    }

    @Override
    public String exportConsole() {
        // Default implementation
        return "";
    }

    // 检查并处理路径过滤 - 只对API接口路径进行过滤，不对发现路径进行过滤
    protected boolean checkAndHandleFilterPath(String url) {
        // 如果是API发现路径（如swagger-resources, service, webservice等），不进行过滤
        if (isDiscoveryPath(url)) {
            return false;
        }
        
        try {
            APIKit.ui.ConfigPanel configPanel = BurpExtenderAdapter.getConfigPanel();
            if (configPanel != null && configPanel.shouldFilterPath(url)) {
                System.out.println("[" + getApiTypeName() + " Filter] Blocked path: " + url + " (contains filtered keywords: " + configPanel.getFilterPath() + ")");
                return true;
            }
        } catch (Exception e) {
            System.out.println("[" + getApiTypeName() + " Filter] Warning: Could not apply path filter - " + e.getMessage());
        }
        return false;
    }
    
    // 判断是否为API发现路径
    private boolean isDiscoveryPath(String url) {
        String[] discoveryPaths = {
            "/swagger", "/swagger-resources", "/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/service", "/services", "/webservice", "/webservices", 
            "/graphql", "/graphiql", "/actuator", "/mappings",
            ".json", ".yaml", ".yml", ".wsdl", ".wadl"
        };
        
        String lowerUrl = url.toLowerCase();
        for (String path : discoveryPaths) {
            if (lowerUrl.contains(path)) {
                return true;
            }
        }
        return false;
    }
}

