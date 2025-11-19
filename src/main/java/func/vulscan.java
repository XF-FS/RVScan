package func;

import UI.Tags;
import burp.*;
import utils.BurpAnalyzedRequest;
import yaml.YamlUtil;
import java.net.URL;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class vulscan {

    private IBurpExtenderCallbacks call;

    private BurpAnalyzedRequest Root_Request;

    private IExtensionHelpers help;
    public String Path_record;
    public BurpExtender burp;
    public IHttpService httpService;


    public vulscan(BurpExtender burp, BurpAnalyzedRequest Root_Request,byte[] request) {
        this.burp = burp;
        this.call = burp.call;
        this.help = burp.help;
        this.Root_Request = Root_Request;
        // 获取httpService对象
        if (request == null){
            request = this.Root_Request.requestResponse().getRequest();
        }
//        IRequestInfo iRequestInfo = help.analyzeRequest(request);
//        httpService = help.buildHttpService(iRequestInfo.getUrl().getHost(), iRequestInfo.getUrl().getPort(), iRequestInfo.getUrl().getProtocol());
        httpService = this.Root_Request.requestResponse().getHttpService();
        IRequestInfo analyze_Request = help.analyzeRequest(httpService, request);
        List<String> heads = analyze_Request.getHeaders();


        // 判断请求方法为POST
        if (this.help.analyzeRequest(request).getMethod() == "POST")
            //将POST切换为GET请求
            request = this.help.toggleRequestMethod(request);
        // 获取所有参数
        IRequestInfo iRequestInfo = this.help.analyzeRequest(request);
        List<IParameter> Parameters = iRequestInfo.getParameters();
        // 判断参数列表不为空
        if (!Parameters.isEmpty())
            for (IParameter parameter : Parameters)
                // 删除所有参数
                request = this.help.removeParameter(request, parameter);

        // 创建新的请求类
//        IHttpRequestResponse newHttpRequestResponse = this.call.makeHttpRequest(httpService, request);
        IHttpRequestResponse newHttpRequestResponse = Root_Request.requestResponse();
        // 使用/分割路径
        IRequestInfo analyzeRequest = this.help.analyzeRequest(newHttpRequestResponse);
        List<String> headers = analyzeRequest.getHeaders();
        HashMap<String, String> headMap = vulscan.AnalysisHeaders(headers);
        String[] domainNames = vulscan.AnalysisHost(headMap.get("Host"));


        String[] paths = analyzeRequest.getUrl().getPath().split("\\?",2)[0].split("/");

        Map<String, Object> Yaml_Map = YamlUtil.readYaml(burp.Config_l.yaml_path);
        List<Map<String, Object>> Listx = (List<Map<String, Object>>) Yaml_Map.get("Load_List");
        if (paths.length == 0) {
            paths = new String[]{""};
        }
        List<String> Bypass_List = (List<String>) Yaml_Map.get("Bypass_List");
        List<String> Bypass_First_List = (List<String>)Yaml_Map.get("Bypass_First_List");
        List<String> Bypass_End_List = (List<String>)Yaml_Map.get("Bypass_End_List");
        
        // 域名扫描
        if (burp.DomainScan) {
            LaunchPath(true, domainNames, Listx, newHttpRequestResponse, heads, Bypass_List, Bypass_First_List, Bypass_End_List);
        }
        
        // 1. 首先始终对根目录进行扫描
        String[] rootPath = {""};
                    this.burp.call.printOutput("[Debug] Starting root directory scan");
        LaunchPath(false, rootPath, Listx, newHttpRequestResponse, heads, Bypass_List, Bypass_First_List, Bypass_End_List);
        
        // 2. 然后对当前访问路径的各级目录进行扫描
                    this.burp.call.printOutput("[Debug] Starting path-level scan, original path: " + analyzeRequest.getUrl().getPath());
        LaunchPath(false, paths, Listx, newHttpRequestResponse, heads, Bypass_List, Bypass_First_List, Bypass_End_List);



    }

    private void LaunchPath(Boolean ClearPath_record, String[] paths, List<Map<String, Object>> Listx, IHttpRequestResponse newHttpRequestResponse, List<String> heads, List<String> Bypass_List, List<String> Bypass_First_List, List<String> Bypass_End_List) {
        this.Path_record = "";
        
        // 存储所有需要扫描的路径
        List<String> pathsToScan = new ArrayList<>();
        StringBuilder currentPath = new StringBuilder();
        
        // 检查是否为根目录访问（空路径或只有空字符串）
        boolean isRootAccess = paths.length == 0 || 
                               (paths.length == 1 && paths[0].isEmpty()) ||
                               (paths.length == 1 && paths[0].equals(""));
        
        if (isRootAccess) {
            // 根目录访问，添加根路径到扫描列表
            pathsToScan.add("");
            this.burp.call.printOutput("[Debug] Root directory access detected, adding root path to scan");
        } else {
            // 构建每一级路径（不包含根路径）
            for (String path : paths) {
                if (path.isEmpty()) continue;
                currentPath.append("/").append(path);
                pathsToScan.add(currentPath.toString());
            }
        }
        
        // 打印要扫描的路径
        this.burp.call.printOutput("[Debug] Paths to scan: " + pathsToScan);
        
        // 对每个路径进行扫描
        for (String path : pathsToScan) {
            if (ClearPath_record) {
                this.Path_record = "";
            } else {
                this.Path_record = path;
            }

            String url = this.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getProtocol() + "://" + 
                        this.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getHost() + ":" + 
                        this.burp.help.analyzeRequest(newHttpRequestResponse).getUrl().getPort() + 
                        this.Path_record;

            this.burp.call.printOutput("[Debug] Scanning path: " + this.Path_record + " with URL: " + url);

            // 使用并发集合，不需要手动同步
            boolean is_InList = !this.burp.history_url.contains(url);

            if (is_InList) {
                this.burp.history_url.add(url);
                
                // 动态批次处理规则，根据线程数和bypass功能调整批次大小
                int threadCount = (Integer) this.burp.Config_l.spinner1.getValue();
                int bypassMultiplier = calculateBypassMultiplier(Bypass_List, Bypass_First_List, Bypass_End_List);
                int dynamicBatchSize = calculateDynamicBatchSize(threadCount, bypassMultiplier);
                int totalRules = Listx.size();
                
                this.burp.call.printOutput("[Dynamic Batch] Total rules: " + totalRules + 
                                          ", Thread count: " + threadCount + 
                                          ", Bypass multiplier: " + bypassMultiplier + 
                                          ", Dynamic batch size: " + dynamicBatchSize);
                
                for (int i = 0; i < totalRules; i += dynamicBatchSize) {
                    int endIndex = Math.min(i + dynamicBatchSize, totalRules);
                    List<Map<String, Object>> batch = Listx.subList(i, endIndex);
                    
                    this.burp.call.printOutput("[Dynamic Batch] Processing batch " + (i/dynamicBatchSize + 1) + 
                                              ": rules " + (i + 1) + "-" + endIndex);
                    
                    // 提交当前批次的任务
                    for (Map<String, Object> zidian : batch) {
                        this.burp.threadPoolManager.submitTask(new threads(zidian, this, newHttpRequestResponse, heads, Bypass_List, Bypass_First_List, Bypass_End_List));
                    }
                    
                    // 等待当前批次完成，再提交下一批次
                    waitForBatchCompletion();
                    
                    // 智能批次间延迟，根据bypass倍增系数调整
                    if (endIndex < totalRules) {
                        try {
                            int delay = calculateBatchDelay(bypassMultiplier, dynamicBatchSize);
                            if (delay > 0) {
                                Thread.sleep(delay);
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                }

                // 最终等待所有任务完成
                this.burp.call.printOutput("[Batch] All batches submitted, waiting for final completion...");
                waitForBatchCompletion();
            } else {
                this.burp.call.printError("Skip: " + url + "/*");
            }
        }
    }


    public static void ir_add(Tags tag, String title, String method, String url, String StatusCode, String notes, String Size, IHttpRequestResponse newHttpRequestResponse) {
        tag.add(title, method, url, StatusCode, notes, Size, newHttpRequestResponse);
    }
    
    /**
     * 带结果过滤功能的ir_add方法
     */
    public static void ir_add_with_filter(burp.BurpExtender burpInstance, Tags tag, String title, String method, String url, String StatusCode, String notes, String Size, IHttpRequestResponse newHttpRequestResponse) {
        // 检查是否需要过滤结果
        if (newHttpRequestResponse != null && newHttpRequestResponse.getResponse() != null && burpInstance != null && burpInstance.resultFilter != null) {
            try {
                // 获取响应信息
                burp.IResponseInfo responseInfo = burpInstance.help.analyzeResponse(newHttpRequestResponse.getResponse());
                
                // 使用新的过滤方法，传入原始字节数据和响应信息
                if (burpInstance.resultFilter.shouldFilter(newHttpRequestResponse.getResponse(), responseInfo)) {
                    // 过滤掉这个结果，不添加到显示列表
                    return;
                }
            } catch (Exception e) {
                // 如果过滤过程出错，继续正常添加结果
                if (burpInstance != null && burpInstance.call != null) {
                    burpInstance.call.printError("[ResultFilter] Error during filtering: " + e.getMessage());
                }
            }
        }
        
        // 如果没有被过滤，正常添加结果
        tag.add(title, method, url, StatusCode, notes, Size, newHttpRequestResponse);
    }

    public static HashMap<String, String> AnalysisHeaders(List<String> headers){
        headers.remove(0);
        HashMap<String, String> headMap = new HashMap<String, String>();
        for (String i : headers){
            int indexLocation = i.indexOf(":");
            String key = i.substring(0,indexLocation).trim();
            String value = i.substring(indexLocation + 1).trim();
            headMap.put(key,value);
        }
        return headMap;

    }

    public static String[] AnalysisHost(String host){
        ArrayList<String> ExceptSubdomain = new ArrayList<String>(Collections.singletonList("www"));
        Pattern zhengze = Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
        Matcher pipei = zhengze.matcher(host);
        if (!pipei.find()){
            List<String> hostArray = new ArrayList<>(Arrays.asList(host.split("\\.")));
            if (ExceptSubdomain.contains(hostArray.get(0))){
                hostArray.remove(0);
            }
            if (hostArray.get(hostArray.size() - 1).equals("cn") && hostArray.get(hostArray.size() - 2).equals("com")){
                hostArray.remove(hostArray.size() - 1);
                hostArray.remove(hostArray.size() - 1);
//                hostArray.remove(hostArray.size() - 2);
            }else {
                hostArray.remove(hostArray.size() - 1);
            }
            return hostArray.toArray(new String[0]);
        }
        return new String[]{};
    }
    
    /**
     * 计算bypass功能的请求倍增系数
     */
    private int calculateBypassMultiplier(List<String> bypassList, List<String> bypassFirstList, List<String> bypassEndList) {
        int multiplier = 1; // 基础请求
        
        // 检查各种bypass功能是否启用，并累加请求数
        if (this.burp.BypassFirst && bypassFirstList != null) {
            multiplier += bypassFirstList.size(); // 前缀绕过
        }
        if (this.burp.Bypass && bypassList != null) {
            multiplier += bypassList.size(); // 路径绕过
        }
        if (this.burp.BypassEnd && bypassEndList != null) {
            multiplier += bypassEndList.size(); // 后缀绕过
        }
        
        return multiplier;
    }
    
    /**
     * 根据线程数和bypass倍增系数计算动态批次大小（优化速度版本）
     */
    private int calculateDynamicBatchSize(int threadCount, int bypassMultiplier) {
        // 基础批次大小，更激进的策略
        int baseBatchSize = Math.max(threadCount * 2, 6); // 最小6个规则，基础为线程数的2倍
        
        // 优化的bypass倍增系数调整策略
        int adjustedBatchSize;
        if (bypassMultiplier <= 3) {
            // 轻度bypass功能，使用较大批次
            adjustedBatchSize = baseBatchSize;
        } else if (bypassMultiplier <= 6) {
            // 中度bypass功能，适度减少（原来过于保守）
            adjustedBatchSize = Math.max((int)(baseBatchSize * 0.7), 4); // 减少30%，最小4个
        } else if (bypassMultiplier <= 9) {
            // 重度bypass功能，减少一半
            adjustedBatchSize = Math.max(baseBatchSize / 2, 3); // 最小3个
        } else {
            // 极重度bypass功能，使用最小批次
            adjustedBatchSize = Math.max(baseBatchSize / 3, 2); // 最小2个
        }
        
        this.burp.call.printOutput("[Dynamic Batch] Speed-Optimized Calculation: threadCount=" + threadCount + 
                                  ", bypassMultiplier=" + bypassMultiplier + 
                                  ", baseBatchSize=" + baseBatchSize + 
                                  ", adjustedBatchSize=" + adjustedBatchSize);
        
        return adjustedBatchSize;
    }
    
    /**
     * 计算智能批次间延迟
     */
    private int calculateBatchDelay(int bypassMultiplier, int batchSize) {
        // 基础延迟策略：bypass倍增系数越高，延迟越长，但批次越大，延迟越短
        int baseDelay;
        
        if (bypassMultiplier <= 3) {
            // 轻度bypass，几乎无延迟
            baseDelay = 50; // 50ms
        } else if (bypassMultiplier <= 6) {
            // 中度bypass，短延迟
            baseDelay = 150; // 150ms
        } else if (bypassMultiplier <= 9) {
            // 重度bypass，中等延迟
            baseDelay = 250; // 250ms
        } else {
            // 极重度bypass，较长延迟
            baseDelay = 400; // 400ms
        }
        
        // 根据批次大小调整延迟：批次越大，可以适当减少延迟
        int adjustedDelay = Math.max(baseDelay - (batchSize - 2) * 20, 0);
        
        this.burp.call.printOutput("[Dynamic Batch] Delay calculation: bypassMultiplier=" + bypassMultiplier + 
                                  ", batchSize=" + batchSize + 
                                  ", baseDelay=" + baseDelay + "ms" +
                                  ", adjustedDelay=" + adjustedDelay + "ms");
        
        return adjustedDelay;
    }
    
    /**
     * 等待当前批次的任务完成，带超时和强制清理
     */
    private void waitForBatchCompletion() {
        int maxWaitTime = 30; // 最大等待30秒
        int waitCount = 0;
        int lastActiveCount = -1;
        int stuckCount = 0; // 连续卡住的检查次数
        
        while (this.burp.threadPoolManager.getActiveScans() > 0 && waitCount < maxWaitTime) {
            try {
                Thread.sleep(1000); // 每秒检查一次
                waitCount++;
                
                int currentActiveCount = this.burp.threadPoolManager.getActiveScans();
                
                // 检查是否有任务卡住（活跃任务数连续10秒不变）
                if (currentActiveCount == lastActiveCount && currentActiveCount > 0) {
                    stuckCount++;
                    if (stuckCount >= 10) { // 连续10秒任务数不变，认为卡住
                        this.burp.call.printError("[Batch] Tasks appear to be stuck for 10+ seconds. Force restarting thread pool...");
                        forceRestartThreadPool();
                        break;
                    }
                } else {
                    stuckCount = 0; // 重置卡住计数
                }
                lastActiveCount = currentActiveCount;
                
                if (waitCount % 5 == 0) { // 每5秒输出一次状态
                    this.burp.call.printOutput("[Batch] Waiting for batch completion... Active scans: " + 
                                              currentActiveCount + " (waited " + waitCount + "s)");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                this.burp.call.printError("[Batch] Batch waiting interrupted");
                break;
            }
        }
        
        if (waitCount >= maxWaitTime) {
            this.burp.call.printError("[Batch] Batch completion timeout after " + maxWaitTime + " seconds. Force restarting thread pool...");
            forceRestartThreadPool();
        } else if (this.burp.threadPoolManager.getActiveScans() == 0) {
            this.burp.call.printOutput("[Batch] Batch completed successfully");
        }
    }
    
    /**
     * 强制重启线程池，清理卡住的任务
     */
    private void forceRestartThreadPool() {
        try {
            // 记录重启前的状态
            int activeScans = this.burp.threadPoolManager.getActiveScans();
            this.burp.call.printOutput("[ThreadPool] Restarting thread pool. Active scans before restart: " + activeScans);
            
            // 强制关闭线程池
            this.burp.threadPoolManager.shutdownNow();
            
            // 等待一小段时间确保线程池完全关闭
            Thread.sleep(1000);
            
            // 重新创建线程池
            int threadCount = (Integer) this.burp.Config_l.spinner1.getValue();
            this.burp.threadPoolManager.createThreadPool(threadCount, threadCount * 2);
            
            this.burp.call.printOutput("[ThreadPool] Thread pool restarted successfully with " + threadCount + " core threads");
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            this.burp.call.printError("[ThreadPool] Thread pool restart interrupted");
        } catch (Exception e) {
            this.burp.call.printError("[ThreadPool] Error restarting thread pool: " + e.getMessage());
            e.printStackTrace();
        }
    }


}

