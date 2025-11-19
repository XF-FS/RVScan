/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.utils;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import APIKit.ui.apitable.ResponseDynamicUpdatable;
import APIKit.utils.CommonUtils;
import APIKit.utils.Executor;

import java.util.concurrent.CompletableFuture;
import APIKit.BurpExtenderAdapter;

public class HttpRequestResponse
        implements IHttpRequestResponse {
    byte[] request;
    byte[] response;
    String comment;
    IHttpService httpService;
    ResponseDynamicUpdatable updateAcceptor;

    public HttpRequestResponse() {
    }

    public HttpRequestResponse(ResponseDynamicUpdatable updateAcceptor) {
        this.updateAcceptor = updateAcceptor;
    }

    public void setUpdateAcceptor(ResponseDynamicUpdatable updateAcceptor) {
        this.updateAcceptor = updateAcceptor;
    }

    @Override
    public byte[] getRequest() {
        return this.request;
    }

    @Override
    public void setRequest(byte[] request) {
        this.request = request;
    }

    public void sendRequest() {
        if (BurpExtenderAdapter.getConfigPanel().getAutoSendRequest().booleanValue()) {
            this.setRequest(this.request);
            this.setResponse("Loading...".getBytes());
            CompletableFuture.supplyAsync(() -> {
                try {
                    IHttpRequestResponse newHttpRequestResponse = BurpExtenderAdapter.getCallbacks().makeHttpRequest(this.httpService, this.request);
                    this.setResponse(newHttpRequestResponse.getResponse());
                    if (this.updateAcceptor != null) {
                        if (newHttpRequestResponse.getResponse() == null) {
                            this.updateAcceptor.setStatusCode(0);
                            this.updateAcceptor.setUnAuth("false");
                            this.updateAcceptor.setContentLength(0);
                            this.updateAcceptor.setScanTime(CommonUtils.getCurrentDateTime());
                        } else {
                            this.updateAcceptor.setStatusCode(BurpExtenderAdapter.getHelpers().analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode());
                            this.updateAcceptor.setUnAuth(String.valueOf(CommonUtils.isUnAuthResponse(newHttpRequestResponse)));
                            this.updateAcceptor.setContentLength(Integer.parseInt(CommonUtils.getContentLength(newHttpRequestResponse)));
                            this.updateAcceptor.setScanTime(CommonUtils.getCurrentDateTime());
                        }
                    }
                } catch (Exception e) {
                    BurpExtenderAdapter.getStderr().println(CommonUtils.exceptionToString(e));
                    this.setResponse(CommonUtils.exceptionToString(e).getBytes());
                }
                return null;
            }, Executor.getExecutor());
        } else {
            this.setResponse("Auto request sending disabled".getBytes());
        }
    }

    @Override
    public byte[] getResponse() {
        return this.response;
    }

    @Override
    public void setResponse(byte[] response) {
        this.response = response;
    }

    @Override
    public String getComment() {
        return this.comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String getHighlight() {
        return "";
    }

    @Override
    public void setHighlight(String s) {
    }

    @Override
    public IHttpService getHttpService() {
        return this.httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
    }
}

