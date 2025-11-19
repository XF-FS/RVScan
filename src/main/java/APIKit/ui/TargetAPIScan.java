/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.ui;

import APIKit.BurpExtenderAdapter;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import APIKit.PassiveScanner;
import APIKit.application.apitypes.ApiType;
import APIKit.utils.Constants;
import APIKit.utils.HttpRequestFormator;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.function.BiFunction;
import APIKit.BurpExtenderAdapter;

public class TargetAPIScan
        extends Thread {
    @Override
    public void run() {
        try {
            java.util.HashMap<String, String> targetAPI = BurpExtenderAdapter.getTargetAPI();
            String basepathurl = targetAPI.get("BasePathURL");
            if (basepathurl == null || basepathurl.isEmpty()) {
                return;
            }
            if (!basepathurl.endsWith("/")) {
                basepathurl = basepathurl + "/";
            }
            String apidocumenturl = targetAPI.get("APIDocumentURL");
            String headers = targetAPI.get("Header");
            String apiTypename = targetAPI.get("APITypename");
            IHttpRequestResponse apiHttpRequestResponse = this.makeHTTPRequest(apidocumenturl, headers, apiTypename);
            IHttpRequestResponse baseHttpRequestResponse = this.makeHTTPRequest(basepathurl, headers, apiTypename);
            BiFunction<IHttpRequestResponse, Boolean, ApiType> apiTypeConstructor = Constants.APITypeMaps.get(apiTypename);
            ApiType apiType = apiTypeConstructor.apply(apiHttpRequestResponse, false);
            ((HashMap) apiType.getApiDocuments()).put(apidocumenturl, apiHttpRequestResponse);
            ArrayList<ApiType> apiTypes = new ArrayList<ApiType>();
            apiTypes.add(apiType);
            PassiveScanner passiveScanner = BurpExtenderAdapter.getPassiveScanner();
            passiveScanner.parseApiDocument(apiTypes, baseHttpRequestResponse);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public IHttpRequestResponse makeHTTPRequest(String url, String headers, String apitype) {
        String[] splitHeader;
        String basepath;
        URL path;
        String method = "GET";
        LinkedList<String> Headers2 = new LinkedList<String>();
        byte[] apiRequest = null;
        try {
            path = new URL(url);
            basepath = path.getFile();
        } catch (MalformedURLException ex) {
            System.out.println(ex.getMessage());
            return null;
        }
        if (apitype.equals("GraphQLIntrospection")) {
            JsonObject jsonBody = new JsonObject();
            jsonBody.add("query", new JsonPrimitive(new String(BurpExtenderAdapter.getHelpers().base64Decode("cXVlcnkgUXVlcnkgewogICAgX19zY2hlbWEgewogICAgICBxdWVyeVR5cGUgeyBuYW1lIH0KICAgICAgbXV0YXRpb25UeXBlIHsgbmFtZSB9CiAgICAgIHN1YnNjcmlwdGlvblR5cGUgeyBuYW1lIH0KICAgICAgdHlwZXMgewogICAgICAgIC4uLkZ1bGxUeXBlCiAgICAgIH0KICAgICAgZGlyZWN0aXZlcyB7CiAgICAgICAgbmFtZQogICAgICAgIGRlc2NyaXB0aW9uCiAgICAgICAgbG9jYXRpb25zCiAgICAgICAgYXJncyB7CiAgICAgICAgICAuLi5JbnB1dFZhbHVlCiAgICAgICAgfQogICAgICB9CiAgICB9CiAgfQoKICBmcmFnbWVudCBGdWxsVHlwZSBvbiBfX1R5cGUgewogICAga2luZAogICAgbmFtZQogICAgZGVzY3JpcHRpb24KICAgIGZpZWxkcyhpbmNsdWRlRGVwcmVjYXRlZDogdHJ1ZSkgewogICAgICBuYW1lCiAgICAgIGRlc2NyaXB0aW9uCiAgICAgIGFyZ3MgewogICAgICAgIC4uLklucHV0VmFsdWUKICAgICAgfQogICAgICB0eXBlIHsKICAgICAgICAuLi5UeXBlUmVmCiAgICAgIH0KICAgICAgaXNEZXByZWNhdGVkCiAgICAgIGRlcHJlY2F0aW9uUmVhc29uCiAgICB9CiAgICBpbnB1dEZpZWxkcyB7CiAgICAgIC4uLklucHV0VmFsdWUKICAgIH0KICAgIGludGVyZmFjZXMgewogICAgICAuLi5UeXBlUmVmCiAgICB9CiAgICBlbnVtVmFsdWVzKGluY2x1ZGVEZXByZWNhdGVkOiB0cnVlKSB7CiAgICAgIG5hbWUKICAgICAgZGVzY3JpcHRpb24KICAgICAgaXNEZXByZWNhdGVkCiAgICAgIGRlcHJlY2F0aW9uUmVhc29uCiAgICB9CiAgICBwb3NzaWJsZVR5cGVzIHsKICAgICAgLi4uVHlwZVJlZgogICAgfQogIH0KCiAgZnJhZ21lbnQgSW5wdXRWYWx1ZSBvbiBfX0lucHV0VmFsdWUgewogICAgbmFtZQogICAgZGVzY3JpcHRpb24KICAgIHR5cGUgeyAuLi5UeXBlUmVmIH0KICAgIGRlZmF1bHRWYWx1ZQogIH0KCiAgZnJhZ21lbnQgVHlwZVJlZiBvbiBfX1R5cGUgewogICAga2luZAogICAgbmFtZQogICAgb2ZUeXBlIHsKICAgICAga2luZAogICAgICBuYW1lCiAgICAgIG9mVHlwZSB7CiAgICAgICAga2luZAogICAgICAgIG5hbWUKICAgICAgICBvZlR5cGUgewogICAgICAgICAga2luZAogICAgICAgICAgbmFtZQogICAgICAgICAgb2ZUeXBlIHsKICAgICAgICAgICAga2luZAogICAgICAgICAgICBuYW1lCiAgICAgICAgICAgIG9mVHlwZSB7CiAgICAgICAgICAgICAga2luZAogICAgICAgICAgICAgIG5hbWUKICAgICAgICAgICAgICBvZlR5cGUgewogICAgICAgICAgICAgICAga2luZAogICAgICAgICAgICAgICAgbmFtZQogICAgICAgICAgICAgICAgb2ZUeXBlIHsKICAgICAgICAgICAgICAgICAga2luZAogICAgICAgICAgICAgICAgICBuYW1lCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICB9CiAgICAgICAgfQogICAgICB9CiAgICB9CiAgfQ=="))));
            apiRequest = new Gson().toJson(jsonBody).getBytes();
            method = "POST";
            if (!basepath.equals("/") && basepath.endsWith("/")) {
                basepath = basepath.substring(0, basepath.length() - 1);
            }
        }
        Headers2.add(method + " " + basepath + " HTTP/1.1");
        String port = path.getPort() == -1 ? (path.getProtocol().equalsIgnoreCase("https") ? "443" : "80") : Integer.toString(path.getPort());
        Headers2.add("Host: " + path.getHost() + ":" + port);
        Headers2.add("User-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36");
        for (String header : splitHeader = headers.split("\r\n")) {
            if (splitHeader.equals("")) continue;
            Headers2.add(header);
        }
        Headers2.add("Content-Type: application/json");
        Headers2.add("Accept: */*");
        Headers2.add("Connection: close");
        HttpRequestFormator.TrimDupHeader(Headers2);
        byte[] newRequest = BurpExtenderAdapter.getHelpers().buildHttpMessage(Headers2, apiRequest);
        IHttpService httpService = BurpExtenderAdapter.getHelpers().buildHttpService(path.getHost(), (int) Integer.valueOf(port), path.getProtocol());
        IHttpRequestResponse ihttprequestresponse = BurpExtenderAdapter.getCallbacks().makeHttpRequest(httpService, newRequest);
        return ihttprequestresponse;
    }
}

