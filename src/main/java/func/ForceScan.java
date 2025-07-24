package func;

import burp.*;
import utils.BurpAnalyzedRequest;
import yaml.YamlUtil;

import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * 强制扫描类
 * 实现不进行去重的路径扫描功能
 */
public class ForceScan {
    private IBurpExtenderCallbacks call;
    private BurpAnalyzedRequest rootRequest;
    private IExtensionHelpers help;
    private BurpExtender burp;
    private IHttpService httpService;
    private String originalPath;

    /**
     * 构造函数
     * @param burp BurpExtender实例
     * @param rootRequest 请求对象
     * @param path 原始路径
     */
    public ForceScan(BurpExtender burp, BurpAnalyzedRequest rootRequest, String path) {
        this.burp = burp;
        this.call = burp.call;
        this.help = burp.help;
        this.rootRequest = rootRequest;
        this.originalPath = path;
        this.httpService = rootRequest.requestResponse().getHttpService();
        
        // 获取请求
        byte[] request = rootRequest.requestResponse().getRequest();
        
        // 处理请求
        if (this.help.analyzeRequest(request).getMethod().equals("POST")) {
            request = this.help.toggleRequestMethod(request);
        }
        
        // 移除参数
        IRequestInfo requestInfo = this.help.analyzeRequest(request);
        List<IParameter> parameters = requestInfo.getParameters();
        if (!parameters.isEmpty()) {
            for (IParameter parameter : parameters) {
                request = this.help.removeParameter(request, parameter);
            }
        }
        
        // 获取请求头
        IHttpRequestResponse newHttpRequestResponse = rootRequest.requestResponse();
        IRequestInfo analyzeRequest = this.help.analyzeRequest(newHttpRequestResponse);
        List<String> headers = analyzeRequest.getHeaders();
        
        // 加载YAML配置
        Map<String, Object> yamlMap = YamlUtil.readYaml(burp.Config_l.yaml_path);
        List<Map<String, Object>> ruleList = (List<Map<String, Object>>) yamlMap.get("Load_List");
        List<String> bypassList = (List<String>) yamlMap.get("Bypass_List");
        List<String> bypassFirstList = (List<String>) yamlMap.get("Bypass_First_List");
        List<String> bypassEndList = (List<String>) yamlMap.get("Bypass_End_List");
        
        // 分割路径并扫描每一级
        scanAllPaths(path, ruleList, newHttpRequestResponse, headers, bypassList, bypassFirstList, bypassEndList);
    }
    
    /**
     * 扫描所有路径级别
     */
    private void scanAllPaths(String fullPath, List<Map<String, Object>> ruleList, 
                             IHttpRequestResponse requestResponse, List<String> headers,
                             List<String> bypassList, List<String> bypassFirstList, List<String> bypassEndList) {
        
        // 移除开头的斜杠
        if (fullPath.startsWith("/")) {
            fullPath = fullPath.substring(1);
        }
        
        // 分割路径
        String[] pathSegments = fullPath.split("/");
        
        // 存储构建的路径
        List<String> pathsToScan = new ArrayList<>();
        
        // 添加根路径
        pathsToScan.add("/");
        
        // 构建每一级路径
        StringBuilder currentPath = new StringBuilder();
        for (String segment : pathSegments) {
            if (segment.isEmpty()) continue;
            
            currentPath.append("/").append(segment);
            pathsToScan.add(currentPath.toString());
        }
        
        // 打印要扫描的路径
        burp.call.printOutput("[Force Scan] Will scan these paths:");
        for (String path : pathsToScan) {
            burp.call.printOutput("[Force Scan] - " + path);
        }
        
        // 扫描每个路径
        for (String path : pathsToScan) {
            String url = requestResponse.getHttpService().getProtocol() + "://" + 
                         requestResponse.getHttpService().getHost() + ":" + 
                         requestResponse.getHttpService().getPort() + path;
            
            burp.call.printOutput("[Force Scan] Scanning: " + url);
            
            // 对每个规则执行扫描
            for (Map<String, Object> rule : ruleList) {
                if ((boolean) rule.get("loaded")) {
                    // 提交扫描任务
                    burp.threadPoolManager.submitTask(new ForceScanThread(
                        rule, this, requestResponse, headers, bypassList, 
                        bypassFirstList, bypassEndList, path
                    ));
                }
            }
            
            // 等待当前路径的所有任务完成
            waitForCompletion();
        }
        
        burp.call.printOutput("[Force Scan] All paths scan completed!");
    }
    
    /**
     * 等待扫描任务完成
     */
    private void waitForCompletion() {
        int attempts = 0;
        while (true) {
            if (attempts >= 10) {
                // 超时处理
                burp.threadPoolManager.shutdownNow();
                int threadCount = (Integer) burp.Config_l.spinner1.getValue();
                burp.threadPoolManager.createThreadPool(threadCount, threadCount * 2);
                burp.call.printError("[Force Scan] Timeout waiting for tasks to complete");
                break;
            }
            
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            
            // 检查是否所有任务都已完成
            if (burp.threadPoolManager.getActiveScans() == 0) {
                break;
            }
            
            attempts++;
        }
    }
    
    /**
     * 获取HTTP服务
     */
    public IHttpService getHttpService() {
        return httpService;
    }
    
    /**
     * 获取BurpExtender实例
     */
    public BurpExtender getBurp() {
        return burp;
    }
    
    /**
     * 获取帮助器
     */
    public IExtensionHelpers getHelp() {
        return help;
    }
    
    /**
     * 获取回调
     */
    public IBurpExtenderCallbacks getCall() {
        return call;
    }
}