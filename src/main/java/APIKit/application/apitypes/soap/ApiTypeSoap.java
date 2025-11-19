/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.soap;

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
import APIKit.application.apitypes.soap.WsdlParser;
import APIKit.exceptions.ApiKitRuntimeException;
import APIKit.utils.CommonUtils;
import APIKit.utils.RedirectUtils;
import APIKit.utils.UrlScanCount;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import APIKit.BurpExtenderAdapter;

public class ApiTypeSoap
        extends ApiType {
    public static final UrlScanCount scannedUrl = new UrlScanCount();
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final IHttpRequestResponse baseRequestResponse;

    public ApiTypeSoap(IHttpRequestResponse baseRequestResponse, Boolean isPassive) {
        this.setApiTypeName("SOAP-WSDL");
        this.callbacks = BurpExtenderAdapter.getCallbacks();
        this.helpers = BurpExtenderAdapter.getHelpers();
        this.baseRequestResponse = baseRequestResponse;
        this.isPassive = isPassive;
    }

    public static ApiType newInstance(IHttpRequestResponse requestResponse, Boolean isPassive) {
        return new ApiTypeSoap(requestResponse, isPassive);
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
        for (String urlPath : urlList) {
            if (this.urlAddPath(urlPath + "/service").booleanValue()) continue;
            this.urlAddPath(urlPath + "/services");
            this.urlAddPath(urlPath + "/webservices");
            this.urlAddPath(urlPath + "/webservice");
        }
        return ((HashMap) this.getApiDocuments()).size() != 0;
    }

    @Override
    public Boolean urlAddPath(String apiDocumentUrl) {
        String apidocument;
        String resp;
        IHttpRequestResponse newHttpRequestResponse;
        IHttpService httpService = this.baseRequestResponse.getHttpService();
        byte[] newRequest = null;
        String urlorgin = this.helpers.analyzeRequest(this.baseRequestResponse).getUrl().toString();
        if (apiDocumentUrl.equals(urlorgin)) {
            newHttpRequestResponse = this.baseRequestResponse;
        } else {
            try {
                newRequest = this.helpers.buildHttpRequest(new URL(apiDocumentUrl));
            } catch (MalformedURLException exception) {
                throw new ApiKitRuntimeException(exception);
            }
            newHttpRequestResponse = CookieManager.makeHttpRequest(this.baseRequestResponse, newRequest);
        }
        String currentUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString();
        if (RedirectUtils.isRedirectedResponse(newHttpRequestResponse)) {
            newHttpRequestResponse = RedirectUtils.getRedirectedResponse(newHttpRequestResponse);
        }
        if ((this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode() == 500 || this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode() == 200 || this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode() == 404) && ((resp = new String(CommonUtils.getHttpResponseBody(newHttpRequestResponse.getResponse()))).contains("soap:Server") || resp.contains("xmlns:soap"))) {
            apidocument = currentUrl + (currentUrl.endsWith("/") ? "" : "/") + "?wsdl";
            try {
                if (!((HashMap) this.getApiDocuments()).containsKey(apidocument)) {
                    newRequest = this.helpers.buildHttpRequest(new URL(apidocument));
                    newHttpRequestResponse = CookieManager.makeHttpRequest(this.baseRequestResponse, newRequest);
                    ((HashMap) this.getApiDocuments()).put(apidocument, newHttpRequestResponse);
                    return true;
                }
            } catch (MalformedURLException exception) {
                throw new ApiKitRuntimeException(exception);
            }
        }
        if (this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode() == 200) {
            if (this.isPassive.booleanValue()) {
                if (scannedUrl.get(this.helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString()) <= 0) {
                    scannedUrl.add(this.helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString());
                } else {
                    return false;
                }
            }
            resp = new String(CommonUtils.getHttpResponseBody(newHttpRequestResponse.getResponse()));
            Pattern pattern = Pattern.compile("href=\"([^\"]*)\\?wsdl\">");
            Matcher matcher = pattern.matcher(resp);
            while (matcher.find()) {
                try {
                    apidocument = matcher.group(1);
                    String string = apidocument.startsWith("http") ? apidocument + "?wsdl" : (apidocument = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString() + (this.helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString().endsWith("/") ? "" : "/") + apidocument + "?wsdl");
                    if (((HashMap) this.getApiDocuments()).containsKey(apidocument)) continue;
                    newRequest = this.helpers.buildHttpRequest(new URL(apidocument));
                    IHttpRequestResponse tempRequestResponse = CookieManager.makeHttpRequest(this.baseRequestResponse, newRequest);
                    ((HashMap) this.getApiDocuments()).put(apidocument, tempRequestResponse);
                } catch (Exception exception) {
                }
            }
        }
        return ((HashMap) this.getApiDocuments()).size() != 0;
    }

    @Override
    public ArrayList<ApiEndpoint> parseApiDocument(IHttpRequestResponse apiDocument, IHttpRequestResponse basePath, boolean isTargetScan) {
        return WsdlParser.parseWsdl(apiDocument, basePath, isTargetScan);
    }

    public ArrayList<IScanIssue> exportIssues() {
        Iterator iterator = ((HashMap) this.getApiDocuments()).entrySet().iterator();
        ArrayList<IScanIssue> issues = new ArrayList<IScanIssue>();
        while (iterator.hasNext()) {
            Map.Entry<String, IHttpRequestResponse> entry = (Map.Entry<String, IHttpRequestResponse>) iterator.next();
            IHttpRequestResponse newHttpRequestResponse = entry.getValue();
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

