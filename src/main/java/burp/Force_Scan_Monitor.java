package burp;

import func.ForceScan;
import utils.BurpAnalyzedRequest;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.util.*;

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
                // 第一阶段：收集所有路径到队列管理器
                Set<String> processedHosts = new HashSet<>();
                
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
                        burp.call.printOutput("[Force Scan Queue] Adding path to queue: " + url.toString());
                        
                        // 将路径添加到队列管理器
                        burp.pathQueueManager.addPath(httpService, path, rootRequest);
                        
                        // 记录需要处理的host
                        String hostKey = httpService.getProtocol() + "://" + 
                                        httpService.getHost() + ":" + 
                                        httpService.getPort();
                        processedHosts.add(hostKey);
                        
                    } catch (Exception exception) {
                        burp.call.printError("[Force Scan Queue] Error adding path to queue: " + exception.getMessage());
                        exception.printStackTrace();
                    }
                }
                
                // 第二阶段：处理每个host的路径队列
                burp.call.printOutput("[Force Scan Queue] Starting to process " + processedHosts.size() + " host queues");
                
                // 创建host到httpService的映射，避免重复处理
                Map<String, IHttpService> hostServiceMap = new HashMap<>();
                for (IHttpRequestResponse requestResponse : requestResponses) {
                    IHttpService httpService = requestResponse.getHttpService();
                    String hostKey = httpService.getProtocol() + "://" + 
                                    httpService.getHost() + ":" + 
                                    httpService.getPort();
                    if (processedHosts.contains(hostKey)) {
                        hostServiceMap.put(hostKey, httpService);
                    }
                }
                
                // 只处理每个唯一的host一次
                for (Map.Entry<String, IHttpService> entry : hostServiceMap.entrySet()) {
                    try {
                        String hostKey = entry.getKey();
                        IHttpService httpService = entry.getValue();
                        
                        burp.call.printOutput("[Force Scan Queue] Processing queue for host: " + hostKey);
                        burp.pathQueueManager.processHostQueue(httpService);
                        
                    } catch (Exception exception) {
                        burp.call.printError("[Force Scan Queue] Error processing host queue: " + exception.getMessage());
                        exception.printStackTrace();
                    }
                }
                
                return null;
            }
            
            @Override
            protected void done() {
                burp.call.printOutput("[Force Scan Queue] All host queues have been processed.");
            }
        };
        
        // 启动后台任务
        worker.execute();
        
        // 立即返回，不阻塞UI线程
        burp.call.printOutput("[Force Scan Queue] Queue processing has been started in background. UI will remain responsive.");
    }
}