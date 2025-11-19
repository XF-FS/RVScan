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
     * 构造函数 - 支持路径列表（用于PathQueueManager）
     * @param burp BurpExtender实例
     * @param rootRequest 请求对象
     * @param pathList 路径列表（已经按层级排序）
     */
    public ForceScan(BurpExtender burp, Object rootRequest, List<String> pathList) {
        this.burp = burp;
        this.call = burp.call;
        this.help = burp.help;
        
        // 类型转换处理
        if (rootRequest instanceof BurpAnalyzedRequest) {
            this.rootRequest = (BurpAnalyzedRequest) rootRequest;
        } else {
            burp.call.printError("[ForceScan] Invalid rootRequest type: " + rootRequest.getClass().getName());
            return;
        }
        
        this.httpService = this.rootRequest.requestResponse().getHttpService();
        this.originalPath = pathList.isEmpty() ? "/" : pathList.get(pathList.size() - 1);
        
        // 获取请求
        byte[] request = this.rootRequest.requestResponse().getRequest();
        
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
        IHttpRequestResponse newHttpRequestResponse = this.rootRequest.requestResponse();
        IRequestInfo analyzeRequest = this.help.analyzeRequest(newHttpRequestResponse);
        List<String> headers = analyzeRequest.getHeaders();
        
        // 加载YAML配置
        Map<String, Object> yamlMap = YamlUtil.readYaml(burp.Config_l.yaml_path);
        List<Map<String, Object>> ruleList = (List<Map<String, Object>>) yamlMap.get("Load_List");
        List<String> bypassList = (List<String>) yamlMap.get("Bypass_List");
        List<String> bypassFirstList = (List<String>) yamlMap.get("Bypass_First_List");
        List<String> bypassEndList = (List<String>) yamlMap.get("Bypass_End_List");
        
        // 使用预先排序的路径列表进行扫描
        scanPathList(pathList, ruleList, newHttpRequestResponse, headers, bypassList, bypassFirstList, bypassEndList);
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
            
            // 分批处理规则执行扫描 - 添加URL去重逻辑
            List<Map<String, Object>> enabledRules = new ArrayList<>();
            Set<String> seenUrls = new HashSet<>();
            
            for (Map<String, Object> rule : ruleList) {
                if ((boolean) rule.get("loaded")) {
                    String ruleUrl = (String) rule.get("url");
                    String fullUrl = path + ruleUrl;
                    
                    // 去重：如果这个URL已经被处理过，跳过
                    if (!seenUrls.contains(fullUrl)) {
                        seenUrls.add(fullUrl);
                        enabledRules.add(rule);
                    } else {
                        burp.call.printOutput("[Force Scan Dedup] Skipping duplicate URL: " + fullUrl + 
                                             " for rule: " + rule.get("name"));
                    }
                }
            }
            
            // 动态批次大小计算
            int threadCount = (Integer) burp.Config_l.spinner1.getValue();
            int bypassMultiplier = calculateBypassMultiplier(bypassList, bypassFirstList, bypassEndList);
            int dynamicBatchSize = calculateDynamicBatchSize(threadCount, bypassMultiplier);
            int totalRules = enabledRules.size();
            
            burp.call.printOutput("[Force Scan Dynamic Batch] Path: " + path + 
                                 ", Total enabled rules: " + totalRules + 
                                 ", Thread count: " + threadCount +
                                 ", Bypass multiplier: " + bypassMultiplier +
                                 ", Dynamic batch size: " + dynamicBatchSize);
            
                         for (int i = 0; i < totalRules; i += dynamicBatchSize) {
                 int endIndex = Math.min(i + dynamicBatchSize, totalRules);
                 List<Map<String, Object>> batch = enabledRules.subList(i, endIndex);
                 
                 burp.call.printOutput("[Force Scan Dynamic Batch] Processing batch " + (i/dynamicBatchSize + 1) + 
                                      ": rules " + (i + 1) + "-" + endIndex);
                
                // 提交当前批次的任务
                for (Map<String, Object> rule : batch) {
                    burp.threadPoolManager.submitTask(new ForceScanThread(
                        rule, this, requestResponse, headers, bypassList, 
                        bypassFirstList, bypassEndList, path
                    ));
                }
                
                // 等待当前批次完成
                waitForCompletion();
                
                // Force Scan智能批次间延迟
                if (endIndex < totalRules) {
                    try {
                        int delay = calculateForceScanBatchDelay(bypassMultiplier, dynamicBatchSize);
                        if (delay > 0) {
                            Thread.sleep(delay);
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
            
            // 等待当前路径的所有任务完成
            waitForCompletion();
        }
        
        burp.call.printOutput("[Force Scan] All paths scan completed!");
    }
    
    /**
     * 扫描预先排序的路径列表（用于PathQueueManager）
     */
    private void scanPathList(List<String> pathList, List<Map<String, Object>> ruleList, 
                             IHttpRequestResponse requestResponse, List<String> headers,
                             List<String> bypassList, List<String> bypassFirstList, List<String> bypassEndList) {
        
        // 打印要扫描的路径
        burp.call.printOutput("[Force Scan PathList] Will scan these paths in order:");
        for (int i = 0; i < pathList.size(); i++) {
            burp.call.printOutput("[Force Scan PathList] " + (i + 1) + ". " + pathList.get(i));
        }
        
        // 扫描每个路径
        for (String path : pathList) {
            String url = requestResponse.getHttpService().getProtocol() + "://" + 
                         requestResponse.getHttpService().getHost() + ":" + 
                         requestResponse.getHttpService().getPort() + path;
            
            burp.call.printOutput("[Force Scan PathList] Scanning: " + url);
            
            // 分批处理规则执行扫描 - 添加URL去重逻辑
            List<Map<String, Object>> enabledRules = new ArrayList<>();
            Set<String> seenUrls = new HashSet<>();
            
            for (Map<String, Object> rule : ruleList) {
                if ((boolean) rule.get("loaded")) {
                    String ruleUrl = (String) rule.get("url");
                    String fullUrl = path + ruleUrl;
                    
                    // 去重：如果这个URL已经被处理过，跳过
                    if (!seenUrls.contains(fullUrl)) {
                        seenUrls.add(fullUrl);
                        enabledRules.add(rule);
                    } else {
                        burp.call.printOutput("[Force Scan PathList Dedup] Skipping duplicate URL: " + fullUrl + 
                                             " for rule: " + rule.get("name"));
                    }
                }
            }
            
            // 动态批次大小计算
            int threadCount = (Integer) burp.Config_l.spinner1.getValue();
            int bypassMultiplier = calculateBypassMultiplier(bypassList, bypassFirstList, bypassEndList);
            int dynamicBatchSize = calculateDynamicBatchSize(threadCount, bypassMultiplier);
            int totalRules = enabledRules.size();
            
            burp.call.printOutput("[Force Scan PathList Dynamic Batch] Path: " + path + 
                                 ", Total enabled rules: " + totalRules + 
                                 ", Thread count: " + threadCount +
                                 ", Bypass multiplier: " + bypassMultiplier +
                                 ", Dynamic batch size: " + dynamicBatchSize);
            
            for (int i = 0; i < totalRules; i += dynamicBatchSize) {
                int endIndex = Math.min(i + dynamicBatchSize, totalRules);
                List<Map<String, Object>> batch = enabledRules.subList(i, endIndex);
                
                burp.call.printOutput("[Force Scan PathList Dynamic Batch] Processing batch " + (i/dynamicBatchSize + 1) + 
                                     ": rules " + (i + 1) + "-" + endIndex);
               
                // 提交当前批次的任务
                for (Map<String, Object> rule : batch) {
                    burp.threadPoolManager.submitTask(new ForceScanThread(
                        rule, this, requestResponse, headers, bypassList, 
                        bypassFirstList, bypassEndList, path
                    ));
                }
                
                // 等待当前批次完成
                waitForCompletion();
                
                // Force Scan智能批次间延迟
                if (endIndex < totalRules) {
                    try {
                        int delay = calculateForceScanBatchDelay(bypassMultiplier, dynamicBatchSize);
                        if (delay > 0) {
                            Thread.sleep(delay);
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
            
            // 等待当前路径的所有任务完成
            waitForCompletion();
        }
        
        burp.call.printOutput("[Force Scan PathList] All paths scan completed!");
    }
    
    /**
     * 计算bypass功能的请求倍增系数
     */
    private int calculateBypassMultiplier(List<String> bypassList, List<String> bypassFirstList, List<String> bypassEndList) {
        int multiplier = 1; // 基础请求
        
        // 检查各种bypass功能是否启用，并累加请求数
        if (burp.BypassFirst && bypassFirstList != null) {
            multiplier += bypassFirstList.size(); // 前缀绕过
        }
        if (burp.Bypass && bypassList != null) {
            multiplier += bypassList.size(); // 路径绕过
        }
        if (burp.BypassEnd && bypassEndList != null) {
            multiplier += bypassEndList.size(); // 后缀绕过
        }
        
        return multiplier;
    }
    
    /**
     * 根据线程数和bypass倍增系数计算动态批次大小（Force Scan速度优化版本）
     */
    private int calculateDynamicBatchSize(int threadCount, int bypassMultiplier) {
        // Force Scan速度优化：相对保守但不过度限制
        int baseBatchSize = Math.max(threadCount, 4); // 最小4个规则
        
        // 优化的bypass倍增系数调整策略
        int adjustedBatchSize;
        if (bypassMultiplier <= 3) {
            // 轻度bypass功能
            adjustedBatchSize = baseBatchSize;
        } else if (bypassMultiplier <= 6) {
            // 中度bypass功能，适度减少
            adjustedBatchSize = Math.max((int)(baseBatchSize * 0.6), 3); // 减少40%，最小3个
        } else if (bypassMultiplier <= 9) {
            // 重度bypass功能
            adjustedBatchSize = Math.max(baseBatchSize / 2, 2); // 最小2个
        } else {
            // 极重度bypass功能，使用最小批次
            adjustedBatchSize = Math.max(baseBatchSize / 3, 1); // 最小1个
        }
        
        burp.call.printOutput("[Force Scan Dynamic Batch] Speed-Optimized Calculation: threadCount=" + threadCount + 
                             ", bypassMultiplier=" + bypassMultiplier + 
                             ", baseBatchSize=" + baseBatchSize + 
                             ", adjustedBatchSize=" + adjustedBatchSize);
        
        return adjustedBatchSize;
    }
    
    /**
     * 计算Force Scan智能批次间延迟（比vulscan更保守）
     */
    private int calculateForceScanBatchDelay(int bypassMultiplier, int batchSize) {
        // Force Scan的延迟策略：比普通扫描稍微保守一些
        int baseDelay;
        
        if (bypassMultiplier <= 3) {
            // 轻度bypass，最小延迟
            baseDelay = 100; // 100ms
        } else if (bypassMultiplier <= 6) {
            // 中度bypass，短延迟
            baseDelay = 200; // 200ms
        } else if (bypassMultiplier <= 9) {
            // 重度bypass，中等延迟
            baseDelay = 300; // 300ms
        } else {
            // 极重度bypass，较长延迟
            baseDelay = 450; // 450ms
        }
        
        // 根据批次大小调整延迟：批次越大，延迟越短
        int adjustedDelay = Math.max(baseDelay - (batchSize - 1) * 25, 50); // 最小50ms
        
        burp.call.printOutput("[Force Scan Dynamic Batch] Delay calculation: bypassMultiplier=" + bypassMultiplier + 
                             ", batchSize=" + batchSize + 
                             ", baseDelay=" + baseDelay + "ms" +
                             ", adjustedDelay=" + adjustedDelay + "ms");
        
        return adjustedDelay;
    }
    
    /**
     * 等待扫描任务完成，带改进的超时和卡住检测
     */
    private void waitForCompletion() {
        int maxWaitTime = 20; // Force Scan最大等待20秒
        int waitCount = 0;
        int lastActiveCount = -1;
        int stuckCount = 0; // 连续卡住的检查次数
        
        while (burp.threadPoolManager.getActiveScans() > 0 && waitCount < maxWaitTime) {
            try {
                Thread.sleep(1000);
                waitCount++;
                
                int currentActiveCount = burp.threadPoolManager.getActiveScans();
                
                // 检查是否有任务卡住（活跃任务数连续8秒不变）
                if (currentActiveCount == lastActiveCount && currentActiveCount > 0) {
                    stuckCount++;
                    if (stuckCount >= 8) { // Force Scan对卡住更敏感
                        burp.call.printError("[Force Scan] Tasks stuck for 8+ seconds. Force restarting thread pool...");
                        forceRestartThreadPool();
                        break;
                    }
                } else {
                    stuckCount = 0; // 重置卡住计数
                }
                lastActiveCount = currentActiveCount;
                
                // 每3秒输出一次状态（Force Scan更频繁）
                if (waitCount % 3 == 0) {
                    burp.call.printOutput("[Force Scan] Waiting for completion... Active scans: " + 
                                         currentActiveCount + " (waited " + waitCount + "s)");
                }
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                burp.call.printError("[Force Scan] Waiting interrupted");
                break;
            }
        }
        
        if (waitCount >= maxWaitTime) {
            burp.call.printError("[Force Scan] Timeout after " + maxWaitTime + " seconds. Force restarting thread pool...");
            forceRestartThreadPool();
        } else if (burp.threadPoolManager.getActiveScans() == 0) {
            burp.call.printOutput("[Force Scan] Batch completed successfully");
        }
    }
    
    /**
     * 强制重启线程池，清理卡住的任务
     */
    private void forceRestartThreadPool() {
        try {
            // 记录重启前的状态
            int activeScans = burp.threadPoolManager.getActiveScans();
            burp.call.printOutput("[Force Scan ThreadPool] Restarting thread pool. Active scans before restart: " + activeScans);
            
            // 强制关闭线程池
            burp.threadPoolManager.shutdownNow();
            
            // 等待一小段时间确保线程池完全关闭
            Thread.sleep(800);
            
            // 重新创建线程池
            int threadCount = (Integer) burp.Config_l.spinner1.getValue();
            burp.threadPoolManager.createThreadPool(threadCount, threadCount * 2);
            
            burp.call.printOutput("[Force Scan ThreadPool] Thread pool restarted successfully with " + threadCount + " core threads");
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            burp.call.printError("[Force Scan ThreadPool] Thread pool restart interrupted");
        } catch (Exception e) {
            burp.call.printError("[Force Scan ThreadPool] Error restarting thread pool: " + e.getMessage());
            e.printStackTrace();
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