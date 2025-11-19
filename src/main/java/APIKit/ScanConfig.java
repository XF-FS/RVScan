/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit;

import burp.IHttpService;

import java.util.List;

public class ScanConfig {
    private String basePathURL;
    private String apiDocumentURL;
    private List<String> headers;
    private IHttpService httpService;
    private String apiTypeName;

    public String getBasePathURL() {
        return this.basePathURL;
    }

    public void setBasePathURL(String basePathURL) {
        this.basePathURL = basePathURL;
    }

    public String getApiDocumentURL() {
        return this.apiDocumentURL;
    }

    public void setApiDocumentURL(String apiDocumentURL) {
        this.apiDocumentURL = apiDocumentURL;
    }

    public List<String> getHeaders() {
        return this.headers;
    }

    public void setHeaders(List<String> headers) {
        this.headers = headers;
    }

    public String getApiTypeName() {
        return this.apiTypeName;
    }

    public void setApiTypeName(String apiTypeName) {
        this.apiTypeName = apiTypeName;
    }

    public IHttpService getHttpService() {
        return this.httpService;
    }

    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
    }
}

