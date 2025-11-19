/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.ui.apitable;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import APIKit.utils.CommonUtils;
import APIKit.BurpExtenderAdapter;

public interface ResponseDynamicUpdatable {
    public void setUnAuth(String var1);

    public void setContentLength(int var1);

    public void setStatusCode(int var1);

    public void setScanTime(String var1);

    default public void updateResponse(IHttpRequestResponse response) {
        if (response.getResponse() == null) {
            this.setStatusCode(0);
            this.setUnAuth("false");
            this.setContentLength(0);
            this.setScanTime(CommonUtils.getCurrentDateTime());
        } else {
            this.setStatusCode(BurpExtenderAdapter.getHelpers().analyzeResponse(response.getResponse()).getStatusCode());
            this.setUnAuth(String.valueOf(CommonUtils.isUnAuthResponse(response)));
            this.setContentLength(Integer.parseInt(CommonUtils.getContentLength(response)));
            this.setScanTime(CommonUtils.getCurrentDateTime());
        }
    }
}

