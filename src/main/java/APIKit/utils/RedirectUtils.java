/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.utils;

import burp.BurpExtender;
import APIKit.CookieManager;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import APIKit.exceptions.ApiKitRuntimeException;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import APIKit.BurpExtenderAdapter;

public class RedirectUtils {
    static final int maxRedirectCount = 16;
    private IHttpService currentHttpService;
    private IHttpRequestResponse currHttpRequestResponse;
    private String currUrl;
    private int redirectCount = 0;

    public RedirectUtils(IHttpRequestResponse httpRequestResponse) {
        this.currHttpRequestResponse = httpRequestResponse;
        this.currentHttpService = httpRequestResponse.getHttpService();
        this.currUrl = BurpExtenderAdapter.getHelpers().analyzeRequest(httpRequestResponse).getUrl().toString();
    }

    public static String handleRelativeRedirectedUrl(String currentUrl, String locationUrl) {
        String result = null;
        try {
            URL currentUrlObject = new URL(currentUrl);
            int port = currentUrlObject.getPort();
            if (port == -1) {
                int n = port = "https".equals(currentUrlObject.getProtocol()) ? 443 : 80;
            }
            if (locationUrl.startsWith("/")) {
                result = currentUrlObject.getProtocol() + "://" + currentUrlObject.getHost() + ":" + port + locationUrl;
            } else {
                String currentPath = currentUrlObject.getPath();
                if (!currentPath.endsWith("/")) {
                    currentPath = Paths.get(currentPath, new String[0]).getParent().toString();
                }
                String newPath = locationUrl.equals("./") ? currentPath + "/" : Paths.get(currentPath, locationUrl).toString();
                result = currentUrlObject.getProtocol() + "://" + currentUrlObject.getHost() + ":" + port + newPath;
            }
        } catch (MalformedURLException ignored) {
            throw new ApiKitRuntimeException("URL parse error");
        }
        return result;
    }

    public static IHttpService handleAbsoluteRedirectedUrl(String locationUrl) {
        IHttpService httpService = null;
        try {
            URL tempUrl = new URL(locationUrl);
            int port = tempUrl.getPort();
            if (port == -1) {
                port = "https".equals(tempUrl.getProtocol()) ? 443 : 80;
            }
            httpService = BurpExtenderAdapter.getHelpers().buildHttpService(tempUrl.getHost(), port, tempUrl.getProtocol());
        } catch (MalformedURLException ignored) {
            throw new ApiKitRuntimeException("URL parse error");
        }
        return httpService;
    }

    public static boolean isRedirectedResponse(IHttpRequestResponse httpRequestResponse) {
        if (httpRequestResponse.getResponse().length != 0 && httpRequestResponse.getResponse() != null) {
            return String.valueOf(BurpExtenderAdapter.getCallbacks().getHelpers().analyzeResponse(httpRequestResponse.getResponse()).getStatusCode()).startsWith("30");
        }
        return false;
    }

    public static IHttpRequestResponse getRedirectedResponse(IHttpRequestResponse httpRequestResponse) {
        RedirectUtils redirectUtils = new RedirectUtils(httpRequestResponse);
        return redirectUtils.getFinalHttpRequestResponse();
    }

    public IHttpRequestResponse getFinalHttpRequestResponse() {
        IExtensionHelpers helpers = BurpExtenderAdapter.getHelpers();
        try {
            while (String.valueOf(helpers.analyzeResponse(this.currHttpRequestResponse.getResponse()).getStatusCode()).startsWith("30")) {
                ++this.redirectCount;
                if (this.redirectCount > 16) {
                    return null;
                }
                List<String> headers = helpers.analyzeResponse(this.currHttpRequestResponse.getResponse()).getHeaders();
                List locationHeader = headers.stream().filter(header -> header.toLowerCase().startsWith("location:")).collect(Collectors.toList());
                if (locationHeader.size() > 0) {
                    String newLocation = (String) locationHeader.get(0);
                    if ((newLocation = newLocation.substring("location:".length()).trim()).startsWith("http://") || newLocation.startsWith("https://")) {
                        this.currentHttpService = RedirectUtils.handleAbsoluteRedirectedUrl(newLocation);
                    } else {
                        newLocation = RedirectUtils.handleRelativeRedirectedUrl(this.currUrl, newLocation);
                    }
                    this.currUrl = newLocation;
                    this.currHttpRequestResponse = CookieManager.makeHttpRequest(this.currHttpRequestResponse, helpers.buildHttpRequest(new URL(newLocation)));
                    continue;
                }
                return null;
            }
            return this.currHttpRequestResponse;
        } catch (Exception e) {
            return null;
        }
    }
}

