/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes.swagger;

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
import APIKit.application.apitypes.swagger.SwaggerObject;
import APIKit.exceptions.ApiKitRuntimeException;
import APIKit.utils.CommonUtils;
import APIKit.utils.HttpRequestFormator;
import APIKit.utils.HttpRequestResponse;
import APIKit.utils.RedirectUtils;
import APIKit.utils.UrlScanCount;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import APIKit.BurpExtenderAdapter;

public class ApiTypeSwagger
        extends ApiType {
    public static final UrlScanCount scannedUrl = new UrlScanCount();
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final IHttpRequestResponse baseRequestResponse;

    public ApiTypeSwagger(IHttpRequestResponse baseRequestResponse, Boolean isPassive) {
        this.setApiTypeName("OpenAPI-Swagger");
        this.callbacks = BurpExtenderAdapter.getCallbacks();
        this.helpers = BurpExtenderAdapter.getHelpers();
        this.baseRequestResponse = baseRequestResponse;
        this.isPassive = isPassive;
    }

    public static ApiType newInstance(IHttpRequestResponse requestResponse, Boolean isPassive) {
        return new ApiTypeSwagger(requestResponse, isPassive);
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
            Boolean result = this.urlAddPath(urlPath + "/swagger-resources");
            if (result == null || result.booleanValue()) continue;
            this.urlAddPath(urlPath + "/swagger/");
            this.urlAddPath(urlPath + "/swagger/index.html");
            this.urlAddPath(urlPath + "/api/");
            this.urlAddPath(urlPath + "/api/index.html");
            this.urlAddPath(urlPath + "/docs/");
            this.urlAddPath(urlPath + "/docs/index.html");
            this.urlAddPath(urlPath + "/apidocs/");
            this.urlAddPath(urlPath + "/apidocs/index.html");
            this.urlAddPath(urlPath + "/api-docs/");
            this.urlAddPath(urlPath + "/api-docs/index.html");
            this.urlAddPath(urlPath + "/");
        }
        return ((HashMap) this.getApiDocuments()).size() != 0;
    }

    @Override
    public Boolean urlAddPath(String apiDocumentUrl) {
        block28:
        {
            String resp;
            block29:
            {
                JsonArray apisarray;
                JsonObject link;
                IHttpRequestResponse newHttpRequestResponse;
                boolean isapiobject;
                block31:
                {
                    Object element;
                    block30:
                    {
                        IHttpService httpService = this.baseRequestResponse.getHttpService();
                        byte[] newRequest = null;
                        isapiobject = false;
                        if (apiDocumentUrl.equals(this.helpers.analyzeRequest(this.baseRequestResponse).getUrl().toString())) {
                            newHttpRequestResponse = this.baseRequestResponse;
                        } else {
                            try {
                                newRequest = this.helpers.buildHttpRequest(new URL(apiDocumentUrl));
                            } catch (MalformedURLException exception) {
                                throw new ApiKitRuntimeException(exception);
                            }
                            newHttpRequestResponse = CookieManager.makeHttpRequest(this.baseRequestResponse, newRequest);
                        }
                        String urlPath = CommonUtils.getUrlRootPath(this.helpers.analyzeRequest(newHttpRequestResponse).getUrl());
                        String urlBasePath = "";
                        String urlPathWithoutFilename = CommonUtils.getUrlWithoutFilename(this.helpers.analyzeRequest(newHttpRequestResponse).getUrl());
                        if (urlPathWithoutFilename.endsWith("/")) {
                            urlBasePath = urlPathWithoutFilename.substring(0, urlPathWithoutFilename.length() - 1);
                        }
                        if (RedirectUtils.isRedirectedResponse(newHttpRequestResponse)) {
                            newHttpRequestResponse = RedirectUtils.getRedirectedResponse(newHttpRequestResponse);
                        }
                        if (this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode() != 200)
                            break block28;
                        if (this.isPassive.booleanValue()) {
                            if (scannedUrl.get(this.helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString()) <= 0) {
                                scannedUrl.add(this.helpers.analyzeRequest(newHttpRequestResponse).getUrl().toString());
                            } else {
                                return false;
                            }
                        }
                        resp = new String(CommonUtils.getHttpResponseBody(newHttpRequestResponse.getResponse()));
                        element = null;
                        try {
                            element = JsonParser.parseString(resp);
                        } catch (Exception exception) {
                            // empty catch block
                        }
                        try {
                            Yaml yaml = new Yaml(new SafeConstructor());
                            Object result = yaml.load(resp);
                            Gson gson = new GsonBuilder().create();
                            element = gson.toJsonTree(result);
                        } catch (Exception yaml) {
                            // empty catch block
                        }
                        if (element == null) break block29;
                        if (!((JsonElement) element).isJsonArray()) break block30;
                        JsonArray ja = ((JsonElement) element).getAsJsonArray();
                        if (null == ja) break block28;
                        for (JsonElement ae : ja) {
                            JsonObject link2;
                            if (!ae.isJsonObject() || (link2 = ae.getAsJsonObject()).get("location") == null) continue;
                            try {
                                String tmpurl = URLEncoder.encode(link2.get("location").getAsString(), "utf-8");
                                tmpurl = tmpurl.replace("%2F", "/").replace("%3D", "=").replace("%3F", "?").replace("%40", "@").replace("%3A", ":");
                                this.urlAddPath(urlPath + tmpurl);
                                this.urlAddPath(urlBasePath + tmpurl);
                            } catch (UnsupportedEncodingException e) {
                                BurpExtenderAdapter.getStderr().println(CommonUtils.exceptionToString(e));
                            }
                        }
                        break block28;
                    }
                    if (!((JsonElement) element).isJsonObject()) break block28;
                    link = ((JsonElement) element).getAsJsonObject();
                    if (link.get("paths") == null) break block31;
                    if (link.get("paths").isJsonObject() && !((HashMap) this.getApiDocuments()).containsKey(apiDocumentUrl)) {
                        ((HashMap) this.getApiDocuments()).put(apiDocumentUrl, newHttpRequestResponse);
                        return true;
                    }
                    break block28;
                }
                if (link.get("apis") == null) break block28;
                if (link.get("basePath") != null) {
                    isapiobject = true;
                }
                if (!link.get("apis").isJsonArray() || null == (apisarray = link.get("apis").getAsJsonArray()))
                    break block28;
                for (JsonElement ae : apisarray) {
                    JsonObject paths;
                    if (!ae.isJsonObject() || (paths = ae.getAsJsonObject()).get("path") == null) continue;
                    if (isapiobject) {
                        if (((HashMap) this.getApiDocuments()).containsKey(apiDocumentUrl)) continue;
                        ((HashMap) this.getApiDocuments()).put(apiDocumentUrl, newHttpRequestResponse);
                        return true;
                    }
                    this.urlAddPath(CommonUtils.combineURLs(apiDocumentUrl, paths.get("path").getAsString()));
                }
                break block28;
            }
            Pattern pattern = Pattern.compile("url:(\\s*)\"(.*?)\"");
            Pattern pattern2 = Pattern.compile("discoveryPaths:(\\s*)arrayFrom\\('(.*?)'\\)");
            Pattern pattern3 = Pattern.compile("\"url\":(\\s*)\"(.*?)\"");
            Matcher matcher = pattern.matcher(resp);
            Matcher matcher2 = pattern2.matcher(resp);
            Matcher matcher3 = pattern3.matcher(resp);
            String documentjsonyaml = "";
            block16:
            while (matcher.find() || matcher2.find() || matcher3.find()) {
                for (int count = 1; count > 0; ++count) {
                    try {
                        documentjsonyaml = matcher.group(count);
                        continue;
                    } catch (Exception e) {
                        try {
                            documentjsonyaml = matcher2.group(count);
                            continue;
                        } catch (Exception ee) {
                            try {
                                documentjsonyaml = matcher3.group(count);
                                continue;
                            } catch (Exception eee) {
                                continue block16;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    @Override
    public ArrayList<ApiEndpoint> parseApiDocument(IHttpRequestResponse apiDocument, IHttpRequestResponse basePath, boolean isTargetScan) {
        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);
        ArrayList<ApiEndpoint> results = new ArrayList<ApiEndpoint>();
        List<String> headers = this.helpers.analyzeRequest(apiDocument.getRequest()).getHeaders();
        String body = new String(CommonUtils.getHttpResponseBody(apiDocument.getResponse()));
        byte[] newRequest = null;
        JsonElement jsonobject = null;
        try {
            jsonobject = JsonParser.parseString(body);
        } catch (Exception e) {
            stdout.println(e.getMessage());
        }
        try {
            Yaml yaml = new Yaml(new SafeConstructor());
            Object result = yaml.load(body);
            Gson gson = new GsonBuilder().create();
            jsonobject = gson.toJsonTree(result);
        } catch (Exception e) {
            stdout.println(e.getMessage());
        }
        if (jsonobject != null && jsonobject.isJsonObject()) {
            try {
                SwaggerObject swaggerObject = new SwaggerObject(headers);
                String _basePath = "";
                if (basePath != null) {
                    _basePath = this.helpers.analyzeRequest(basePath).getUrl().getPath();
                }
                swaggerObject.SwaggerParseObject(jsonobject.getAsJsonObject(), _basePath);
                HashMap<List<String>, byte[]> apiRequest = swaggerObject.apiRequestResponse;
                for (Map.Entry<List<String>, byte[]> apiReq : apiRequest.entrySet()) {
                    String uri = Arrays.asList(apiReq.getKey().get(0).split(" ")).get(1);
                    headers = apiReq.getKey();
                    
                    // 检查是否是被过滤的响应
                    String responseContent = new String(apiReq.getValue(), StandardCharsets.UTF_8);
                    if (responseContent.equals("FILTERED_PATH_MARKER")) {
                        // 这是一个被过滤的请求，创建一个模拟的HttpRequestResponse
                        HttpRequestResponse tempRequestResponse = new HttpRequestResponse();
                        if (basePath == null) {
                            tempRequestResponse.setHttpService(apiDocument.getHttpService());
                        } else {
                            tempRequestResponse.setHttpService(basePath.getHttpService());
                        }
                        
                        // 构建请求（使用空的请求体）
                        newRequest = this.helpers.buildHttpMessage(headers, new byte[0]);
                        tempRequestResponse.setRequest(newRequest);
                        
                        // 构建过滤响应
                        String filteredResponseBody = "Filter Path list Dont sed to Reques";
                        String filteredResponse = "HTTP/1.1 403 Forbidden\r\n" +
                                                  "Content-Type: text/plain\r\n" +
                                                  "Content-Length: " + filteredResponseBody.length() + "\r\n" +
                                                  "\r\n" +
                                                  filteredResponseBody;
                        tempRequestResponse.setResponse(filteredResponse.getBytes(StandardCharsets.UTF_8));
                        
                        try {
                            // 使用正确的URI，并添加[FILTERED]标记
                            results.add(new ApiEndpoint(uri + " [FILTERED]", tempRequestResponse));
                            System.out.println("[ApiTypeSwagger] Added filtered endpoint: " + uri + " [FILTERED]");
                        } catch (Exception e) {
                            stdout.println(e.getMessage());
                        }
                        continue;
                    }
                    
                    if (isTargetScan && !this.isPassive) {
                        String bypassSuffix = BurpExtender.TargetAPI.get("BypassSuffix");
                        if (bypassSuffix != null && !bypassSuffix.isEmpty()) {
                            int queryIndex = uri.indexOf('?');
                            if (queryIndex != -1) {
                                uri = uri.substring(0, queryIndex) + bypassSuffix + uri.substring(queryIndex);
                            } else {
                                uri = uri + bypassSuffix;
                            }
                            
                            // 更新请求头中的URI
                            for (int i = 0; i < headers.size(); i++) {
                                String header = headers.get(i);
                                if (header.startsWith("GET ") || header.startsWith("POST ") || 
                                    header.startsWith("PUT ") || header.startsWith("DELETE ")) {
                                    String[] parts = header.split(" ");
                                    parts[1] = uri;
                                    headers.set(i, String.join(" ", parts));
                                    break;
                                }
                            }
                        }
                    }

                    if (isTargetScan) {
                        HttpRequestFormator.TrimDupHeader(headers);
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
            } catch (MalformedURLException e) {
                BurpExtenderAdapter.getStderr().println(CommonUtils.exceptionToString(e));
            }
        }
        return results;
    }

    public ArrayList<IScanIssue> exportIssues() {
        ArrayList<IScanIssue> issues = new ArrayList<IScanIssue>();
        for (Map.Entry<String, IHttpRequestResponse> entry : ((HashMap<String, IHttpRequestResponse>) this.getApiDocuments()).entrySet()) {
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
    public void clearScanState() {
        scannedUrl.clear();
    }
}
