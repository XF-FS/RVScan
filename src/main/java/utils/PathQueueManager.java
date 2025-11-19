package utils;

import burp.BurpExtender;
import burp.IHttpService;
import func.ForceScan;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 路径队列管理器
 * 管理相同host的不同路径，将它们合并到一个队列中按目录层级进行扫描
 */
public class PathQueueManager {
    private BurpExtender burp;
    
    // 使用host:port作为key，存储每个host的路径队列
    private Map<String, HostPathQueue> hostQueues = new ConcurrentHashMap<>();
    
    // 用于同步的锁
    private final ReentrantLock lock = new ReentrantLock();
    
    public PathQueueManager(BurpExtender burp) {
        this.burp = burp;
    }
    
    /**
     * 添加路径到对应host的队列中
     * @param httpService HTTP服务信息
     * @param path 路径
     * @param requestResponse 请求响应对象
     */
    public void addPath(IHttpService httpService, String path, Object requestResponse) {
        String hostKey = getHostKey(httpService);
        
        lock.lock();
        try {
            HostPathQueue hostQueue = hostQueues.computeIfAbsent(hostKey, k -> 
                new HostPathQueue(httpService, burp));
            
            hostQueue.addPath(path, requestResponse);
            
            burp.call.printOutput("[PathQueueManager] Added path '" + path + 
                                 "' to queue for host: " + hostKey);
            
        } finally {
            lock.unlock();
        }
    }
    
    /**
     * 开始处理指定host的路径队列
     * @param httpService HTTP服务信息
     */
    public void processHostQueue(IHttpService httpService) {
        String hostKey = getHostKey(httpService);
        
        lock.lock();
        try {
            HostPathQueue hostQueue = hostQueues.get(hostKey);
            if (hostQueue != null) {
                burp.call.printOutput("[PathQueueManager] Starting to process queue for host: " + hostKey);
                hostQueue.processQueue();
                
                // 处理完成后移除队列
                hostQueues.remove(hostKey);
                burp.call.printOutput("[PathQueueManager] Completed processing queue for host: " + hostKey);
            } else {
                burp.call.printOutput("[PathQueueManager] No queue found for host: " + hostKey);
            }
        } finally {
            lock.unlock();
        }
    }
    
    /**
     * 获取所有待处理的host列表
     */
    public Set<String> getPendingHosts() {
        return new HashSet<>(hostQueues.keySet());
    }
    
    /**
     * 生成host的唯一标识
     */
    private String getHostKey(IHttpService httpService) {
        return httpService.getProtocol() + "://" + 
               httpService.getHost() + ":" + 
               httpService.getPort();
    }
    
    /**
     * 单个host的路径队列
     */
    private static class HostPathQueue {
        private IHttpService httpService;
        private BurpExtender burp;
        private Set<String> pathSet = new LinkedHashSet<>(); // 保持插入顺序，避免重复
        private List<PathInfo> pathInfos = new ArrayList<>();
        
        public HostPathQueue(IHttpService httpService, BurpExtender burp) {
            this.httpService = httpService;
            this.burp = burp;
        }
        
        /**
         * 添加路径到队列
         */
        public void addPath(String path, Object requestResponse) {
            if (!pathSet.contains(path)) {
                pathSet.add(path);
                pathInfos.add(new PathInfo(path, requestResponse));
            }
        }
        
        /**
         * 处理队列中的所有路径
         */
        public void processQueue() {
            if (pathInfos.isEmpty()) {
                return;
            }
            
            // 生成所有需要扫描的路径层级
            Set<String> allPaths = generateAllPathLevels();
            
            // 按路径层级排序
            List<String> sortedPaths = new ArrayList<>(allPaths);
            sortedPaths.sort(this::comparePathsByLevel);
            
            burp.call.printOutput("[HostPathQueue] Generated " + sortedPaths.size() + 
                                 " path levels for host: " + getHostKey());
            burp.call.printOutput("[HostPathQueue] Path scanning order:");
            for (int i = 0; i < sortedPaths.size(); i++) {
                burp.call.printOutput("[HostPathQueue] " + (i + 1) + ". " + sortedPaths.get(i));
            }
            
            // 使用第一个请求作为基础请求（所有路径使用相同的基础配置）
            PathInfo firstPathInfo = pathInfos.get(0);
            
            // 创建ForceScan实例，传入合并后的路径列表
            new ForceScan(burp, firstPathInfo.requestResponse, sortedPaths);
        }
        
        /**
         * 生成所有路径的层级结构
         */
        private Set<String> generateAllPathLevels() {
            Set<String> allPaths = new LinkedHashSet<>();
            
            // 总是添加根路径
            allPaths.add("/");
            
            // 处理每个原始路径
            for (PathInfo pathInfo : pathInfos) {
                String path = pathInfo.path;
                
                // 移除开头的斜杠进行处理
                if (path.startsWith("/")) {
                    path = path.substring(1);
                }
                
                // 如果路径为空（即原来就是"/"），跳过
                if (path.isEmpty()) {
                    continue;
                }
                
                // 分割路径并生成每一级
                String[] segments = path.split("/");
                StringBuilder currentPath = new StringBuilder();
                
                for (String segment : segments) {
                    if (segment.isEmpty()) continue;
                    
                    currentPath.append("/").append(segment);
                    allPaths.add(currentPath.toString());
                }
            }
            
            return allPaths;
        }
        
        /**
         * 按路径层级比较，用于排序
         */
        private int comparePathsByLevel(String path1, String path2) {
            // 根路径总是排在最前面
            if (path1.equals("/")) return -1;
            if (path2.equals("/")) return 1;
            
            // 计算路径层级（斜杠数量）
            int level1 = countSlashes(path1);
            int level2 = countSlashes(path2);
            
            if (level1 != level2) {
                return Integer.compare(level1, level2);
            }
            
            // 同层级按字典序排序
            return path1.compareTo(path2);
        }
        
        /**
         * 计算路径中斜杠的数量
         */
        private int countSlashes(String path) {
            int count = 0;
            for (char c : path.toCharArray()) {
                if (c == '/') count++;
            }
            return count;
        }
        
        private String getHostKey() {
            return httpService.getProtocol() + "://" + 
                   httpService.getHost() + ":" + 
                   httpService.getPort();
        }
    }
    
    /**
     * 路径信息类
     */
    private static class PathInfo {
        String path;
        Object requestResponse;
        
        public PathInfo(String path, Object requestResponse) {
            this.path = path;
            this.requestResponse = requestResponse;
        }
    }
} 