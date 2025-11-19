/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.rest;

import burp.BurpExtender;
import APIKit.CookieManager;
import APIKit.CustomScanIssue;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import APIKit.application.apitypes.ApiEndpoint;
import APIKit.application.apitypes.ApiType;
import APIKit.application.apitypes.rest.WadlParser;
import APIKit.exceptions.ApiKitRuntimeException;
import APIKit.utils.CommonUtils;
import APIKit.utils.HttpRequestFormator;
import APIKit.utils.HttpRequestResponse;
import APIKit.utils.RedirectUtils;
import APIKit.utils.UrlScanCount;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import APIKit.BurpExtenderAdapter;

public class ApiTypeRest
        extends ApiType {
    public static final UrlScanCount scannedUrl = new UrlScanCount();
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final IHttpRequestResponse baseRequestResponse;

    public ApiTypeRest(IHttpRequestResponse baseRequestResponse, Boolean isPassive) {
        this.setApiTypeName("REST-WADL");
        this.callbacks = BurpExtenderAdapter.getCallbacks();
        this.helpers = BurpExtenderAdapter.getHelpers();
        this.baseRequestResponse = baseRequestResponse;
        this.isPassive = isPassive;
    }

    public static ApiType newInstance(IHttpRequestResponse requestResponse, Boolean isPassive) {
        return new ApiTypeRest(requestResponse, isPassive);
    }

    @Override
    public Boolean isFingerprintMatch() {
        URL url = this.helpers.analyzeRequest(this.baseRequestResponse).getUrl();
        ArrayList<String> urlList = new ArrayList<String>();
        Set<String> UrlPathList = CommonUtils.getUrlPathList(url);
        Iterator<String> iterator = UrlPathList.iterator();
        while (iterator.hasNext()) {
            String tmpurl = iterator.next().toString();
            if (scannedUrl.get(tmpurl) > 0 && this.isPassive.booleanValue()) continue;
            urlList.add(tmpurl);
            if (!this.isPassive.booleanValue()) continue;
            scannedUrl.add(tmpurl);
        }
        this.urlAddPath(url.toString());
        for (Object e : urlList) {
            if (this.urlAddPath(e + "/service").booleanValue()) continue;
            this.urlAddPath(e + "/services");
            this.urlAddPath(e + "/webservices");
            this.urlAddPath(e + "/webservice");
        }
        return ((HashMap) this.getApiDocuments()).size() != 0;
    }

    @Override
    public Boolean urlAddPath(String apiDocumentUrl) {
        IHttpService httpService = this.baseRequestResponse.getHttpService();
        byte[] newRequest = null;
        try {
            // 检查路径过滤
            if (checkAndHandleFilterPath(apiDocumentUrl)) {
                return false;
            }
            
            newRequest = this.helpers.buildHttpRequest(new URL(apiDocumentUrl));
        } catch (MalformedURLException exception) {
            throw new ApiKitRuntimeException(exception);
        }
        IHttpRequestResponse newHttpRequestResponse = CookieManager.makeHttpRequest(this.baseRequestResponse, newRequest);
        String urlPath = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString();
        if (this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode() == 200) {
            if (this.isPassive.booleanValue()) {
                if (scannedUrl.get(this.helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString()) <= 0) {
                    scannedUrl.add(this.helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString());
                } else {
                    return false;
                }
            }
            ((HashMap) this.getApiDocuments()).put(apiDocumentUrl, newHttpRequestResponse);
            return true;
        }
        return false;
    }

    @Override
    public ArrayList<ApiEndpoint> parseApiDocument(IHttpRequestResponse apiDocument, IHttpRequestResponse basePath, boolean isTargetScan) {
        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);
        ArrayList<ApiEndpoint> results = new ArrayList<ApiEndpoint>();
        List<String> headers = this.helpers.analyzeRequest(apiDocument.getRequest()).getHeaders();
        for (int i2 = 0; i2 < headers.size(); ++i2) {
            String header = headers.get(i2).toLowerCase(Locale.ROOT);
            if (!header.startsWith("content-type") && !header.startsWith("content-length")) continue;
            headers.remove(i2);
        }
        HashMap<List<String>, byte[]> apiRequests = new WadlParser(headers).parseWadl(apiDocument, basePath);
        byte[] newRequest = null;
        for (Map.Entry<List<String>, byte[]> apiReq : apiRequests.entrySet()) {
            String uri = Arrays.asList(apiReq.getKey().get(0).split(" ")).get(1);
            headers = apiReq.getKey();
            if (isTargetScan && !this.isPassive) {
                String bypassSuffix = BurpExtender.TargetAPI.get("BypassSuffix");
                if (bypassSuffix != null && !bypassSuffix.isEmpty()) {
                    HttpRequestFormator.TrimDupHeader(headers);
                }
            }
            newRequest = this.helpers.buildHttpMessage(headers, apiReq.getValue());
            HttpRequestResponse tempRequestResponse = new HttpRequestResponse();
            if (basePath == null) {
                tempRequestResponse.setHttpService(apiDocument.getHttpService());
            } else {
                tempRequestResponse.setHttpService(basePath.getHttpService());
            }
            tempRequestResponse.setRequest(newRequest);
            tempRequestResponse.sendRequest();
            try {
                results.add(new ApiEndpoint(uri, tempRequestResponse));
            } catch (Exception e) {
                stdout.println(e.getMessage());
            }
        }
        return results;
    }

    @SuppressWarnings("unchecked")
    @Override
    public ArrayList<IScanIssue> exportIssues() {
        ArrayList<IScanIssue> issues = new ArrayList<IScanIssue>();
        Map<String, IHttpRequestResponse> documents = (Map<String, IHttpRequestResponse>) this.getApiDocuments();
        for (Map.Entry<String, IHttpRequestResponse> entry : documents.entrySet()) {
            IHttpRequestResponse newHttpRequestResponse = (IHttpRequestResponse) entry.getValue();
            URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();
            String detail = "<br/>============ ApiDetection ============<br/>";
            detail = detail + String.format("API Technology Type: %s <br/>", this.getApiTypeName());
            detail = detail + "=====================================<br/>";
            issues.add(new CustomScanIssue(newHttpRequestResponse.getHttpService(), newHttpRequestUrl, new IHttpRequestResponse[]{newHttpRequestResponse}, "API Technology", detail, "Information"));
        }
        return issues;
    }


    @Override
    public String exportConsole() {
        String stringBuilder = "\n============== API \u6307\u7eb9\u8be6\u60c5 ============\nxxxx\n\u8be6\u60c5\u8bf7\u67e5\u770b - Burp Scanner \u6a21\u5757 - Issue activity \u754c\u9762\n===================================";
        return stringBuilder;
    }
}

