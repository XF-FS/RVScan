package APIKit;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import APIKit.BurpExtenderAdapter;
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
import java.util.List;
import java.util.Map;

/**
 * APIKit被动扫描器，适配RVScan架构
 */
public class ApiKitPassiveScanner {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final UrlScanCount scanedUrl = new UrlScanCount();
    private final ApiScanner apiScanner;
    private final Object lock = new Object();
    private int scannedCount = 1;
    private ApiKitPanel apiKitPanel;

    public ApiKitPassiveScanner(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.apiScanner = new ApiScanner();
        
        // 初始化BurpExtenderAdapter
        BurpExtenderAdapter.initialize(callbacks, helpers);
        BurpExtenderAdapter.setPassiveScanner(null); // 不使用原来的PassiveScanner
    }

    public void setApiKitPanel(ApiKitPanel panel) {
        this.apiKitPanel = panel;
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

    /**
     * 执行被动扫描
     */
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse httpRequestResponse) {
        URL httpRequestURL = helpers.analyzeRequest(httpRequestResponse).getUrl();
        String requestUrl = CommonUtils.getUrlWithoutFilename(httpRequestURL);
        
        if (this.scanedUrl.get(requestUrl) > 0) {
            return null;
        }
        this.scanedUrl.add(requestUrl);
        
        callbacks.printOutput("[APIKit] Scanning: " + requestUrl);
        ArrayList<ApiType> apiTypes = this.apiScanner.detect(httpRequestResponse, true);
        
        // 只有检测到 API 类型时才解析文档
        if (!apiTypes.isEmpty()) {
            return this.parseApiDocument(apiTypes, null);
        }
        
        return null;
    }

    /**
     * 解析API文档
     */
    public List<IScanIssue> parseApiDocument(final ArrayList<ApiType> apiTypes, final IHttpRequestResponse basePath) {
        ArrayList<IScanIssue> issues = new ArrayList<IScanIssue>();
        
        if (apiKitPanel == null) {
            callbacks.printError("[APIKit] ApiKitPanel not initialized!");
            return issues;
        }
        
        for (final ApiType apiType : apiTypes) {
            Map apiDocuments = apiType.getApiDocuments();
            for (Object obj : apiDocuments.entrySet()) {
                @SuppressWarnings("unchecked")
                Map.Entry<String, IHttpRequestResponse> entry = (Map.Entry<String, IHttpRequestResponse>) obj;
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        int num;
                        Object lockObj = ApiKitPassiveScanner.this.lock;
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
                            num = ApiKitPassiveScanner.this.scannedCount++;
                        }
                        
                        // 计算API文档的内容长度
                        int documentContentLength = 0;
                        int documentStatusCode = 0;
                        IHttpRequestResponse documentResponse = (IHttpRequestResponse) entry.getValue();
                        
                        if (documentResponse != null && documentResponse.getResponse() != null && documentResponse.getResponse().length > 0) {
                            documentStatusCode = helpers.analyzeResponse(documentResponse.getResponse()).getStatusCode();
                            documentContentLength = Integer.parseInt(CommonUtils.getContentLength(documentResponse));
                        }
                        
                        ApiDocumentEntity apiDocument = new ApiDocumentEntity(
                            num, 
                            (String) entry.getKey(), 
                            documentStatusCode, 
                            apiType.getApiTypeName(), 
                            "true", 
                            documentResponse, 
                            CommonUtils.getCurrentDateTime(), 
                            documentContentLength, 
                            apiDetails
                        );
                        
                        // 添加到UI面板
                        apiKitPanel.addApiDocument(apiDocument);
                    }
                }).start();
            }
            issues.addAll(apiType.exportIssues());
        }
        return issues;
    }

    /**
     * 创建API详情实体
     */
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
            int statusCode = helpers.analyzeResponse(response.getResponse()).getStatusCode();
            String unAuth = String.valueOf(CommonUtils.isUnAuthResponse(response));
            int contentLength = Integer.parseInt(CommonUtils.getContentLength(response));
            return new ApiDetailEntity(endpoint.getUrl(), statusCode, apiType.getApiTypeName(), method, unAuth, response, CommonUtils.getCurrentDateTime(), contentLength);
        }
        return new ApiDetailEntity(endpoint.getUrl(), 0, apiType.getApiTypeName(), method, "false", response, CommonUtils.getCurrentDateTime(), 0);
    }
}

