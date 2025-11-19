/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.ui.apitable;

import burp.IHttpRequestResponse;
import APIKit.ui.apitable.ApiDetailEntity;
import APIKit.ui.apitable.ResponseDynamicUpdatable;

import java.util.List;

public class ApiDocumentEntity
        implements ResponseDynamicUpdatable {
    public final int id;
    public final String url;
    public final String apiType;
    public final IHttpRequestResponse requestResponse;
    public String unAuth;
    public int statusCode;
    public int contentLength;
    public String scanTime;
    public List<ApiDetailEntity> details;

    public ApiDocumentEntity(int id, String url, int statusCode, String apiType, String unAuth, IHttpRequestResponse requestResponse, String scanTime, int contentLength, List<ApiDetailEntity> details) {
        this.id = id;
        this.url = url;
        this.statusCode = statusCode;
        this.apiType = apiType;
        this.unAuth = unAuth;
        this.requestResponse = requestResponse;
        this.scanTime = scanTime;
        this.contentLength = contentLength;
        this.details = details;
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

