/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.application.apitypes;

import burp.IHttpRequestResponse;

public class ApiEndpoint {
    private String url;
    private IHttpRequestResponse httpRequestResponse;

    public ApiEndpoint(String url, IHttpRequestResponse httpRequestResponse) {
        this.url = url;
        this.httpRequestResponse = httpRequestResponse;
    }

    public String getUrl() {
        return this.url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public IHttpRequestResponse getHttpRequestResponse() {
        return this.httpRequestResponse;
    }

    public void setHttpRequestResponse(IHttpRequestResponse httpRequestResponse) {
        this.httpRequestResponse = httpRequestResponse;
    }
}

