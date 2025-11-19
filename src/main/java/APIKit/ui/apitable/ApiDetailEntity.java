/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.ui.apitable;

import burp.IHttpRequestResponse;
import APIKit.ui.apitable.ResponseDynamicUpdatable;

public class ApiDetailEntity
        implements ResponseDynamicUpdatable {
    public final String name;
    public final String apiType;
    public final String method;
    public final IHttpRequestResponse requestResponse;
    public String unAuth;
    public int statusCode;
    public int contentLength;
    public String scanTime;

    public ApiDetailEntity(String name, int statusCode, String apiType, String method, String unAuth, IHttpRequestResponse requestResponse, String scanTime, int contentLength) {
        this.name = name;
        this.apiType = apiType;
        this.method = method;
        this.requestResponse = requestResponse;
        this.scanTime = scanTime;
        this.unAuth = unAuth;
        this.statusCode = statusCode;
        this.contentLength = contentLength;
    }

    @Override
    public void setUnAuth(String unAuth) {
        this.unAuth = unAuth;
    }

    @Override
    public void setContentLength(int contentLength) {
        this.contentLength = contentLength;
    }

    @Override
    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    @Override
    public void setScanTime(String scanTime) {
        this.scanTime = scanTime;
    }
}

