package burp;

import func.ForceScan;
import utils.BurpAnalyzedRequest;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * 强制扫描监听器
 * 实现不进行去重的路径扫描功能
 */
public class Force_Scan_Monitor implements ActionListener {
    private IContextMenuInvocation invocation;
    private BurpExtender burp;

    public Force_Scan_Monitor(IContextMenuInvocation invocation, BurpExtender burp) {
        this.invocation = invocation;
        this.burp = burp;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        // 初始化线程池
        final int threadCount = (Integer) burp.Config_l.spinner1.getValue();
        burp.threadPoolManager.createThreadPool(threadCount, threadCount * 2, 60L, 200);
        
        // 获取选中的请求
        final IHttpRequestResponse[] requestResponses = invocation.getSelectedMessages();
        
        // 使用SwingWorker在后台线程中执行扫描，避免阻塞UI线程
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                for (IHttpRequestResponse requestResponse : requestResponses) {
                    try {
                        // 获取请求信息
                        IHttpService httpService = requestResponse.getHttpService();
                        IRequestInfo requestInfo = burp.help.analyzeRequest(httpService, requestResponse.getRequest());
                        URL url = requestInfo.getUrl();
                        
                        // 创建请求对象
                        BurpAnalyzedRequest rootRequest = new BurpAnalyzedRequest(burp.call, requestResponse);
                        
                        // 提取路径
                        String path = url.getPath();
                        burp.call.printOutput("[Force Scan] Starting forced scan for: " + url.toString());
                        
                        // 执行强制扫描
                        new ForceScan(burp, rootRequest, path);
                        
                    } catch (Exception exception) {
                        burp.call.printError("[Force Scan] Error: " + exception.getMessage());
                        exception.printStackTrace();
                    }
                }
                return null;
            }
            
            @Override
            protected void done() {
                burp.call.printOutput("[Force Scan] All scans have been queued in background.");
            }
        };
        
        // 启动后台任务
        worker.execute();
        
        // 立即返回，不阻塞UI线程
        burp.call.printOutput("[Force Scan] Scan tasks have been started in background. UI will remain responsive.");
    }
}