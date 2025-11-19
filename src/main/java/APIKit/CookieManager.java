/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import APIKit.BurpExtenderAdapter;

public class CookieManager
        implements IHttpListener {
    private final HashMap<String, HashMap<String, String>> cookies = new HashMap();

    public static byte[] getRequest(IHttpRequestResponse baseRequestResponse, byte[] newRequest) {
        IExtensionHelpers helpers = BurpExtenderAdapter.getHelpers();
        IRequestInfo newRequestInfo = helpers.analyzeRequest(newRequest);
        IRequestInfo baseRequestInfo = helpers.analyzeRequest(baseRequestResponse.getRequest());
        List<String> baseHeaders = baseRequestInfo.getHeaders();
        baseHeaders.set(0, newRequestInfo.getHeaders().get(0));
        byte[] request = helpers.buildHttpMessage(baseHeaders, Arrays.copyOfRange(newRequest, newRequestInfo.getBodyOffset(), newRequest.length));
        return request;
    }

    public static IHttpRequestResponse makeHttpRequest(IHttpRequestResponse baseRequestResponse, byte[] request) {
        byte[] newRequest = CookieManager.getRequest(baseRequestResponse, request);
        return BurpExtenderAdapter.getCallbacks().makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
    }

    private String urlToOrigin(URL url) {
        int port = url.getPort();
        if (port == -1) {
            port = "http".equals(url.getProtocol()) ? 80 : 443;
        }
        return url.getProtocol() + "://" + url.getHost() + ":" + port;
    }

    private HashMap<String, String> parseCookie(String cookie) {
        String[] keyValuePairs;
        HashMap<String, String> result = new HashMap<String, String>();
        for (String keyValuePair : keyValuePairs = cookie.split(";")) {
            String[] keyValue = (keyValuePair = keyValuePair.trim()).split("=", 2);
            if ("".equals(keyValue[0])) continue;
            if (keyValue.length == 2) {
                result.put(keyValue[0], keyValue[1]);
                continue;
            }
            result.put(keyValue[0], "");
        }
        return result;
    }

    private String joinCookieKeyValue(HashMap<String, String> cookie) {
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : cookie.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            builder.append(key);
            builder.append("=");
            builder.append((Object) value);
            builder.append("; ");
        }
        return builder.toString();
    }

    private String getCookieValue(Object obj) {
        if (obj == null) {
            return null;
        }
        return String.valueOf(obj);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            IRequestInfo requestInfo = BurpExtenderAdapter.getHelpers().analyzeRequest(messageInfo);
            String origin = this.urlToOrigin(requestInfo.getUrl());
            List<String> headers = requestInfo.getHeaders();
            List<String> cookies = headers.subList(1, headers.size()).stream()
                    .filter(header -> "cookie".equalsIgnoreCase(header.split(":", 2)[0]))
                    .collect(Collectors.toList());

            for (String cookieHeader : cookies) {
                String[] temp = cookieHeader.split(":", 2);
                if (temp.length != 2) continue;
                HashMap<String, String> cookie = this.parseCookie(temp[1]);
                if (this.cookies.get(origin) == null) {
                    this.cookies.put(origin, cookie);
                    continue;
                }
                this.cookies.get(origin).putAll(cookie);
            }
        }
    }

    public String getCookieHeader(URL url) {
        String origin = this.urlToOrigin(url);
        HashMap<String, String> cookie = this.cookies.get(origin);
        if (cookie != null) {
            return "Cookie: " + this.joinCookieKeyValue(cookie);
        }
        return null;
    }
}

