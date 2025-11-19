/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import APIKit.application.ApiScanner;
import APIKit.application.apitypes.ApiEndpoint;
import APIKit.application.apitypes.ApiType;
import APIKit.application.apitypes.actuator.ApiTypeActuator;
import APIKit.application.apitypes.graphql.ApiTypeGraphQL;
import APIKit.application.apitypes.rest.ApiTypeRest;
import APIKit.application.apitypes.soap.ApiTypeSoap;
import APIKit.application.apitypes.swagger.ApiTypeSwagger;
import APIKit.ui.ApiKitPanel;
import APIKit.ui.apitable.ApiDetailEntity;
import APIKit.ui.apitable.ApiDocumentEntity;
import APIKit.utils.CommonUtils;
import APIKit.utils.HttpRequestResponse;
import APIKit.utils.UrlScanCount;

import java.net.URL;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import APIKit.BurpExtenderAdapter;

public class PassiveScanner
        implements IScannerCheck {
    private final UrlScanCount scanedUrl = new UrlScanCount();
    private final ApiScanner apiScanner;
    private final Object lock = new Object();
    private int scannedCount = 1;
    
    // 用于跟踪过滤器配置变化的变量
    private String lastFilterHost = "";
    private String lastFilterPath = "";

    public PassiveScanner() {
        this.apiScanner = new ApiScanner();
    }

    public void clearUrlScanedCache() {
        this.scannedCount = 1;
        this.scanedUrl.clear();
        ApiTypeRest.scannedUrl.clear();
        ApiTypeActuator.scannedUrl.clear();
        ApiTypeGraphQL.scannedUrl.clear();
        ApiTypeSoap.scannedUrl.clear();
        ApiTypeSwagger.scannedUrl.clear();
        this.apiScanner.clearScanState();
    }

    public ApiScanner getApiScanner() {
        return this.apiScanner;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse httpRequestResponse) {
        URL httpRequestURL = BurpExtenderAdapter.getHelpers().analyzeRequest(httpRequestResponse).getUrl();
        String requestUrl = CommonUtils.getUrlWithoutFilename(httpRequestURL);
        
        if (this.scanedUrl.get(requestUrl) > 0) {
            return null;
        }
        this.scanedUrl.add(requestUrl);
        
        System.out.println("Scanning\t" + requestUrl);
        ArrayList<ApiType> apiTypes = this.apiScanner.detect(httpRequestResponse, true);
        
        // 只有检测到 API 类型时才解析文档
        if (!apiTypes.isEmpty()) {
            return this.parseApiDocument(apiTypes, null);
        }
        
        return null;
    }

    public List<IScanIssue> parseApiDocument(final ArrayList<ApiType> apiTypes, final IHttpRequestResponse basePath) {
        ArrayList<IScanIssue> issues = new ArrayList<IScanIssue>();
        // 注意：在RVScan中，我们使用ApiKitPassiveScanner，它直接使用ApiKitPanel
        // 这个方法保留用于兼容性，但实际不会被调用
        final ApiKitPanel apiKitPanel = null; // 需要通过构造函数或setter传入
        for (final ApiType apiType : apiTypes) {
            Map apiDocuments = apiType.getApiDocuments();
            for (Object obj : apiDocuments.entrySet()) {
                @SuppressWarnings("unchecked")
                Map.Entry<String, IHttpRequestResponse> entry = (Map.Entry<String, IHttpRequestResponse>) obj;
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        int num;
                        Object lockObj = PassiveScanner.this.lock;
                        boolean isTargetScan = false;
                        if (apiTypes.size() == 1) {
                            isTargetScan = true;
                        }

                        List<ApiEndpoint> apiEndpoints = apiType.parseApiDocument(entry.getValue(), basePath, isTargetScan);
                        apiEndpoints.sort(Comparator.comparing(ApiEndpoint::getUrl));
                        ArrayList<ApiDetailEntity> apiDetails = new ArrayList<>();

                        for (ApiEndpoint endpoint : apiEndpoints) {
                            IHttpRequestResponse apiParseRequestResponse = endpoint.getHttpRequestResponse();
                            ApiDetailEntity currentDetail = createApiDetailEntity(endpoint, apiParseRequestResponse, apiType);
                            if (apiParseRequestResponse instanceof HttpRequestResponse) {
                                ((HttpRequestResponse) apiParseRequestResponse).setUpdateAcceptor(currentDetail);
                            }
                            apiDetails.add(currentDetail);
                        }

                        synchronized (lockObj) {
                            num = PassiveScanner.this.scannedCount++;
                        }
                        
                        // 计算API文档的内容长度
                        int documentContentLength = 0;
                        int documentStatusCode = 0;
                        IHttpRequestResponse documentResponse = (IHttpRequestResponse) entry.getValue();
                        
                        if (documentResponse != null && documentResponse.getResponse() != null && documentResponse.getResponse().length > 0) {
                            documentStatusCode = BurpExtenderAdapter.getHelpers().analyzeResponse(documentResponse.getResponse()).getStatusCode();
                            documentContentLength = Integer.parseInt(CommonUtils.getContentLength(documentResponse));
                        }
                        
                        ApiDocumentEntity apiDocument = new ApiDocumentEntity(num, (String) entry.getKey(), documentStatusCode, apiType.getApiTypeName(), "true", documentResponse, CommonUtils.getCurrentDateTime(), documentContentLength, apiDetails);
                        if (apiKitPanel != null) {
                            apiKitPanel.addApiDocument(apiDocument);
                        }
                    }
                }).start();
            }
            issues.addAll(apiType.exportIssues());
            BurpExtenderAdapter.getStdout().print(apiType.exportConsole());
        }
        return issues;
    }

    private ApiDetailEntity createApiDetailEntity(ApiEndpoint endpoint, IHttpRequestResponse response, ApiType apiType) {
        String method = "GET"; // 默认方法
        if (response != null && response.getRequest() != null && response.getRequest().length > 0) {
            // 从请求中提取HTTP方法
            String requestStr = new String(response.getRequest());
            String[] lines = requestStr.split("\r?\n");
            if (lines.length > 0) {
                String[] parts = lines[0].split(" ");
                if (parts.length > 0) {
                    method = parts[0];
                }
            }
        }
        
        if (response != null && response.getResponse() != null && response.getResponse().length > 0) {
            int statusCode = BurpExtenderAdapter.getHelpers().analyzeResponse(response.getResponse()).getStatusCode();
            String unAuth = String.valueOf(CommonUtils.isUnAuthResponse(response));
            int contentLength = Integer.parseInt(CommonUtils.getContentLength(response));
            return new ApiDetailEntity(endpoint.getUrl(), statusCode, apiType.getApiTypeName(), method, unAuth, response, CommonUtils.getCurrentDateTime(), contentLength);
        }
        return new ApiDetailEntity(endpoint.getUrl(), 0, apiType.getApiTypeName(), method, "false", response, CommonUtils.getCurrentDateTime(), 0);
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse httpRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        }
        return 0;
    }
}

