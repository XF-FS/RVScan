package utils;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * 路径处理工具类
 * 提供统一的路径规范化功能
 */
public class PathUtils {
    
    /**
     * 规范化路径，确保路径格式正确
     * @param basePath 基础路径
     * @param rulePath 规则路径
     * @return 规范化后的路径
     */
    public static String normalizePath(String basePath, String rulePath) {
        if (basePath == null) basePath = "";
        if (rulePath == null) rulePath = "";
        
        // 确保basePath以斜杠结尾（除非为空）
        String base = basePath;
        if (!base.isEmpty() && !base.endsWith("/")) {
            base = base + "/";
        }
        
        // 确保rulePath不以斜杠开头
        String rule = rulePath;
        if (rule.startsWith("/")) {
            rule = rule.substring(1);
        }
        
        // 合并路径
        String path = base + rule;
        
        // 确保路径以斜杠开头
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        
        // 替换连续的斜杠为单个斜杠
        return normalizeSlashes(path);
    }
    
    /**
     * 规范化单个路径，确保以斜杠开头且没有连续斜杠
     * @param path 原始路径
     * @return 规范化后的路径
     */
    public static String normalizePath(String path) {
        if (path == null || path.isEmpty()) {
            return "/";
        }
        
        // 确保以斜杠开头
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        
        // 替换连续的斜杠
        return normalizeSlashes(path);
    }
    
    /**
     * 替换连续的斜杠为单个斜杠
     * @param path 原始路径
     * @return 处理后的路径
     */
    public static String normalizeSlashes(String path) {
        if (path == null) return "/";
        
        // 使用正则表达式替换连续的斜杠
        return path.replaceAll("/+", "/");
    }
    
    /**
     * 构建完整的URL
     * @param protocol 协议
     * @param host 主机
     * @param port 端口
     * @param basePath 基础路径
     * @param rulePath 规则路径
     * @return URL对象
     * @throws MalformedURLException 如果URL格式不正确
     */
    public static URL buildURL(String protocol, String host, int port, String basePath, String rulePath) 
            throws MalformedURLException {
        String normalizedPath = normalizePath(basePath, rulePath);
        return new URL(protocol, host, port, normalizedPath);
    }
    
    /**
     * 从完整路径中提取各级路径
     * @param fullPath 完整路径
     * @return 各级路径列表
     */
    public static java.util.List<String> extractPathLevels(String fullPath) {
        java.util.List<String> pathLevels = new java.util.ArrayList<>();
        
        if (fullPath == null || fullPath.isEmpty()) {
            pathLevels.add("/");
            return pathLevels;
        }
        
        // 规范化路径
        String normalizedPath = normalizePath(fullPath);
        
        // 添加根路径
        pathLevels.add("/");
        
        // 分割路径并逐级构建
        String[] segments = normalizedPath.substring(1).split("/");
        StringBuilder currentPath = new StringBuilder();
        
        for (String segment : segments) {
            if (!segment.isEmpty()) {
                currentPath.append("/").append(segment);
                pathLevels.add(currentPath.toString());
            }
        }
        
        return pathLevels;
    }
    
    /**
     * 检查路径是否有效
     * @param path 路径
     * @return 是否有效
     */
    public static boolean isValidPath(String path) {
        if (path == null) return false;
        
        // 检查是否包含非法字符
        return !path.contains("\\") && !path.contains("..") || path.contains("../");
    }
}