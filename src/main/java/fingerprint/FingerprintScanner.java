package fingerprint;

import burp.*;
import UI.Tags;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.io.IOException;
import java.util.ArrayList;

/**
 * 指纹扫描器
 * 集成到RVScan Pro的指纹识别功能
 */
public class FingerprintScanner {
    private BurpExtender burp;
    private FingerprintMatcher matcher;
    private FingerprintLoader loader;
    private boolean enabled;
    private ConcurrentMap<String, List<String>> fingerprintCache;
    
    public FingerprintScanner(BurpExtender burp) {
        this.burp = burp;
        this.matcher = new FingerprintMatcher(burp);
        this.loader = new FingerprintLoader(burp);
        this.enabled = true;
        this.fingerprintCache = new ConcurrentHashMap<>();
        
        // 初始化默认指纹库
        initializeDefaultFingerprints();
    }
    
    /**
     * 初始化默认指纹库
     */
    private void initializeDefaultFingerprints() {
        try {
            List<FingerPrint> fingerprints = loader.loadFingerprints();
            matcher.loadFingerprints(fingerprints);
            burp.call.printOutput("[Fingerprint] Loaded " + fingerprints.size() + " fingerprints");
        } catch (Exception e) {
            burp.call.printError("[Fingerprint] Failed to load fingerprints: " + e.getMessage());
        }
    }
    
    /**
     * 从在线源更新指纹库
     */
    public void updateFingerprintsFromOnline() {
        try {
            burp.call.printOutput("[Fingerprint] Updating fingerprint library from online source...");
            List<FingerPrint> onlineFingerprints = loader.loadFromUrl(null);
            matcher.loadFingerprints(onlineFingerprints);
                            burp.call.printOutput("[Fingerprint] Successfully updated fingerprint library with " + onlineFingerprints.size() + " fingerprints");
        } catch (Exception e) {
            burp.call.printError("[Fingerprint] Failed to update fingerprint library online: " + e.getMessage());
            burp.call.printError("[Fingerprint] Continue using current fingerprint library");
        }
    }
    
    /**
     * 从本地文件加载指纹库
     */
    public void loadFingerprintsFromFile(String filePath) {
        try {
            List<FingerPrint> fingerprints;
            if (filePath.toLowerCase().endsWith(".json")) {
                fingerprints = loader.loadFromJsonFile(filePath);
            } else if (filePath.toLowerCase().endsWith(".yaml") || filePath.toLowerCase().endsWith(".yml")) {
                fingerprints = loader.loadFromYamlFile(filePath);
            } else {
                throw new IllegalArgumentException("不支持的文件格式，请使用JSON或YAML文件");
            }
            
            matcher.loadFingerprints(fingerprints);
            burp.call.printOutput("[Fingerprint] Loaded " + fingerprints.size() + " fingerprints from file: " + filePath);
        } catch (Exception e) {
            burp.call.printError("[Fingerprint] Failed to load fingerprints from file: " + e.getMessage());
        }
    }
    
    /**
     * 执行指纹识别
     */
    public void performFingerprintScan(IHttpRequestResponse requestResponse) {
        if (!enabled || requestResponse == null) {
            return;
        }
        
        try {
            // 获取主机信息
            IHttpService httpService = requestResponse.getHttpService();
            String host = httpService.getHost();
            int port = httpService.getPort();
            String protocol = httpService.getProtocol();
            String baseUrl = protocol + "://" + host + ":" + port;
            
            // 获取请求路径
            String path = burp.help.analyzeRequest(requestResponse).getUrl().getPath();
            String fullUrl = baseUrl + path;
            // burp.call.printOutput("[Debug] 指纹识别检查路径: " + path + " 完整URL: " + fullUrl);
            
            // 检查缓存 - 使用完整URL作为缓存键
            if (fingerprintCache.containsKey(fullUrl)) {
                // burp.call.printOutput("[Debug] URL " + fullUrl + " 已在缓存中，跳过指纹识别");
                return; // 已经扫描过该URL
            }
            
            // 执行指纹识别（获取详细匹配信息）
            List<FingerprintMatcher.MatchResult> matchResults = matcher.identifyFingerprintWithDetails(requestResponse);
            
            // 提取CMS名称用于缓存
            List<String> identifiedCMS = new ArrayList<>();
            for (FingerprintMatcher.MatchResult result : matchResults) {
                identifiedCMS.add(result.getCms());
            }
            
            // 标记该URL已被扫描（无论是否识别到指纹）
            fingerprintCache.put(fullUrl, identifiedCMS.isEmpty() ? java.util.Arrays.asList("未识别") : identifiedCMS);
            
            if (!matchResults.isEmpty()) {
                // 记录识别结果（带匹配详情）
                List<String> detailInfo = new ArrayList<>();
                for (FingerprintMatcher.MatchResult result : matchResults) {
                    detailInfo.add(result.toString()); // 显示【匹配类型】CMS名称
                }
                String cmsInfo = String.join(", ", detailInfo);
                burp.call.printOutput("[Fingerprint] " + fullUrl + " identified: " + cmsInfo);
                
                // 添加到扫描结果中
                addFingerprintResultWithDetails(requestResponse, matchResults, fullUrl);
            } else {
                // burp.call.printOutput("[Debug] " + fullUrl + " 未识别到指纹");
            }
            
        } catch (Exception e) {
            burp.call.printError("[Fingerprint] Error occurred during fingerprint recognition: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 检查URL是否已经被扫描过
     */
    public boolean isHostAlreadyScanned(String fullUrl) {
        return fingerprintCache.containsKey(fullUrl);
    }
    
    /**
     * 标记URL为已扫描
     */
    public void markHostAsScanned(String fullUrl) {
        if (!fingerprintCache.containsKey(fullUrl)) {
            fingerprintCache.put(fullUrl, java.util.Arrays.asList("未识别"));
        }
    }
    
    /**
     * 添加指纹识别结果到扫描结果中（带详细匹配信息）
     */
    private void addFingerprintResultWithDetails(IHttpRequestResponse requestResponse, List<FingerprintMatcher.MatchResult> matchResults, String fullUrl) {
        try {
            // 构建详细的指纹信息
            List<String> detailInfoList = new ArrayList<>();
            List<String> cmsNames = new ArrayList<>();
            
            for (FingerprintMatcher.MatchResult result : matchResults) {
                detailInfoList.add(result.toString()); // 【匹配类型】CMS名称
                cmsNames.add(result.getCms());
            }
            
            String cmsInfo = String.join(", ", detailInfoList);
            String method = burp.help.analyzeRequest(requestResponse).getMethod();
            String url = fullUrl;
            String statusCode = String.valueOf(burp.help.analyzeResponse(requestResponse.getResponse()).getStatusCode());
            
            // 提取更多信息
            IResponseInfo responseInfo = burp.help.analyzeResponse(requestResponse.getResponse());
            List<String> headers = responseInfo.getHeaders();
            String server = "";
            for (String header : headers) {
                if (header.toLowerCase().startsWith("server:")) {
                    server = header.substring(7).trim();
                    break;
                }
            }
            
            // 构建详细的备注信息
            StringBuilder notesBuilder = new StringBuilder();
            notesBuilder.append("识别到的CMS/框架: ").append(String.join(", ", cmsNames));
            
            // 添加匹配详情
            notesBuilder.append("\n\n匹配详情:");
            for (FingerprintMatcher.MatchResult result : matchResults) {
                notesBuilder.append("\n- ").append(result.toString())
                          .append(": ").append(result.getMatchDetail());
            }
            
            if (!server.isEmpty()) {
                notesBuilder.append("\nServer: ").append(server);
            }
            String path = burp.help.analyzeRequest(requestResponse).getUrl().getPath();
            notesBuilder.append("\n识别位置: ").append(path.isEmpty() ? "根目录" : path);
            
            String details = notesBuilder.toString();
            String size = String.valueOf(requestResponse.getResponse().length);
            
            // 添加到指纹识别专用标签页
            if (burp.tags != null) {
                burp.tags.addFingerprintResult(
                    cmsInfo,        // 指纹名称（带匹配类型）
                    method,         // 请求方法
                    url,            // URL
                    statusCode,     // 状态码
                    details,        // 详细信息
                    size,           // 响应大小
                    requestResponse // HTTP请求响应对
                );
            }
        } catch (Exception e) {
            if (burp != null && burp.call != null) {
                burp.call.printError("Failed to add fingerprint recognition result: " + e.getMessage());
            }
        }
    }
    
    /**
     * 添加指纹识别结果到扫描结果中（兼容性方法）
     */
    private void addFingerprintResult(IHttpRequestResponse requestResponse, List<String> identifiedCMS, String fullUrl) {
        try {
            String cmsInfo = String.join(", ", identifiedCMS);
            String method = burp.help.analyzeRequest(requestResponse).getMethod();
            String url = fullUrl;
            String statusCode = String.valueOf(burp.help.analyzeResponse(requestResponse.getResponse()).getStatusCode());
            
            // 提取更多信息
            IResponseInfo responseInfo = burp.help.analyzeResponse(requestResponse.getResponse());
            List<String> headers = responseInfo.getHeaders();
            String server = "";
            for (String header : headers) {
                if (header.toLowerCase().startsWith("server:")) {
                    server = header.substring(7).trim();
                    break;
                }
            }
            
            // 构建详细的备注信息
            StringBuilder notesBuilder = new StringBuilder();
            notesBuilder.append("识别到的CMS/框架: ").append(cmsInfo);
            if (!server.isEmpty()) {
                notesBuilder.append("\nServer: ").append(server);
            }
            String path = burp.help.analyzeRequest(requestResponse).getUrl().getPath();
            notesBuilder.append("\n识别位置: ").append(path.isEmpty() ? "根目录" : path);
            
            String details = notesBuilder.toString();
            String size = String.valueOf(requestResponse.getResponse().length);
            
            // 添加到指纹识别专用标签页
            if (burp.tags != null) {
                burp.tags.addFingerprintResult(
                    cmsInfo,        // 指纹名称
                    method,         // 请求方法
                    url,            // URL
                    statusCode,     // 状态码
                    details,        // 详细信息
                    size,           // 响应大小
                    requestResponse // 请求响应对象
                );
            }
            
        } catch (Exception e) {
            burp.call.printError("[Fingerprint] Failed to add fingerprint recognition result: " + e.getMessage());
        }
    }
    
    /**
     * 启用/禁用指纹识别
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        burp.call.printOutput("[Fingerprint] Fingerprint recognition " + (enabled ? "enabled" : "disabled"));
    }
    
    /**
     * 检查指纹识别是否启用
     */
    public boolean isEnabled() {
        return enabled;
    }
    
    /**
     * 获取指纹库大小
     */
    public int getFingerprintCount() {
        return matcher.getFingerprintCount();
    }
    
    /**
     * 清除指纹缓存
     */
    public void clearCache() {
        fingerprintCache.clear();
        burp.call.printOutput("[Fingerprint] Fingerprint recognition cache cleared");
    }
    
    /**
     * 获取已识别的主机数量
     */
    public int getIdentifiedHostCount() {
        return fingerprintCache.size();
    }
    
    /**
     * 获取指纹识别统计信息
     */
    public String getStatistics() {
        return String.format("指纹库大小: %d, 已识别主机: %d, 状态: %s", 
                           getFingerprintCount(), 
                           getIdentifiedHostCount(), 
                           enabled ? "启用" : "禁用");
    }

    /**
     * 获取所有指纹
     */
    public List<FingerPrint> getFingerprints() {
        return matcher != null ? matcher.getFingerprints() : new ArrayList<>();
    }
    
    /**
     * 添加单个指纹
     */
    public void addFingerprint(FingerPrint fingerprint) {
        matcher.addFingerprint(fingerprint);
    }
    
    /**
     * 删除指定指纹
     */
    public void deleteFingerprint(int index) {
        matcher.deleteFingerprint(index);
    }
    
    /**
     * 将当前指纹规则保存到指定文件
     * @param filePath 保存文件的路径，默认为 finger.json
     */
    public void saveFingerprintsToFile(String filePath) {
        try {
            if (filePath == null || filePath.trim().isEmpty()) {
                filePath = "finger.json";
            }
            
            List<FingerPrint> fingerprints = getFingerprints();
            loader.saveToJsonFile(fingerprints, filePath);
            burp.call.printOutput("[Fingerprint] Successfully saved " + fingerprints.size() + " fingerprint rules to " + filePath);
        } catch (IOException e) {
            burp.call.printError("[Fingerprint] Failed to save fingerprint rules: " + e.getMessage());
        }
    }

}