/*
 * Decompiled with CFR 0.153-SNAPSHOT (d6f6758-dirty).
 */
package APIKit.ui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;

import java.awt.Component;
import java.nio.charset.StandardCharsets;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;

public class HttpRequestResponsePanel
        extends JSplitPane
        implements IMessageEditorController {
    private final IMessageEditor requestTextEditor;
    private final IMessageEditor responseTextEditor;
    private IHttpRequestResponse currentRequestResponse;

    public HttpRequestResponsePanel(IBurpExtenderCallbacks callbacks) {
        super(1);
        this.setResizeWeight(0.5);
        JTabbedPane requestPanel = new JTabbedPane();
        this.requestTextEditor = callbacks.createMessageEditor(this, false);
        requestPanel.addTab("Request", this.requestTextEditor.getComponent());
        JTabbedPane responsePanel = new JTabbedPane();
        this.responseTextEditor = callbacks.createMessageEditor(this, false);
        responsePanel.addTab("Response", this.responseTextEditor.getComponent());
        this.add((Component) requestPanel, "left");
        this.add((Component) responsePanel, "right");
    }

    public void clear() {
        this.currentRequestResponse = null;
        this.requestTextEditor.setMessage("".getBytes(StandardCharsets.UTF_8), true);
        this.responseTextEditor.setMessage("".getBytes(StandardCharsets.UTF_8), false);
    }

    public void setHttpRequestResponse(IHttpRequestResponse httpRequestResponse) {
        this.currentRequestResponse = httpRequestResponse;
        this.requestTextEditor.setMessage(httpRequestResponse.getRequest(), true);
        this.responseTextEditor.setMessage(httpRequestResponse.getResponse(), false);
    }

    @Override
    public IHttpService getHttpService() {
        return this.currentRequestResponse.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return this.currentRequestResponse.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return this.currentRequestResponse.getResponse();
    }
}

