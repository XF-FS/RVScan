package func;

import burp.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 强制扫描线程类
 * 用于执行不进行去重的扫描任务
 */
public class ForceScanThread implements Runnable {
    private Map<String, Object> rule;
    private ForceScan scanner;
    private IHttpRequestResponse requestResponse;
    private List<String> headers;
    private List<String> bypassList;
    private List<String> bypassFirstList;
    private List<String> bypassEndList;
    private String basePath;

    /**
     * 构造函数
     */
    public ForceScanThread(Map<String, Object> rule, ForceScan scanner, 
                          IHttpRequestResponse requestResponse, List<String> headers,
                          List<String> bypassList, List<String> bypassFirstList, 
                          List<String> bypassEndList, String basePath) {
        this.rule = rule;
        this.scanner = scanner;
        this.requestResponse = requestResponse;
        this.headers = headers;
        this.bypassList = bypassList;
        this.bypassFirstList = bypassFirstList;
        this.bypassEndList = bypassEndList;
        this.basePath = basePath;
    }

    @Override
    public void run() {
        try {
            executeScan();
        } catch (Exception e) {
            scanner.getCall().printError("[Force Scan] Error in scan thread: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 执行扫描
     */
    private void executeScan() {
        String rulePath = (String) rule.get("url");
        String name = (String) rule.get("name");
        String rePattern = (String) rule.get("re");
        String info = (String) rule.get("info");
        List<Integer> states = parseStatusCodes((String) rule.get("state"));
        
        try {
            // 构建完整URL，确保不会出现连续的斜杠
            String normalizedPath = normalizePath(basePath, rulePath);
            URL url = new URL(
                scanner.getHttpService().getProtocol(),
                scanner.getHttpService().getHost(),
                scanner.getHttpService().getPort(),
                normalizedPath
            );
            
            // 构建请求
            byte[] request = scanner.getHelp().buildHttpRequest(url);
            
            // 处理请求头
            if (scanner.getBurp().Carry_head) {
                List<String> requestHeaders = scanner.getHelp().analyzeRequest(request).getHeaders();
                headers.remove(0);
                headers.add(0, requestHeaders.get(0));
                request = scanner.getHelp().buildHttpMessage(headers, new byte[]{});
            }
            
            // 处理POST请求
            if ("POST".equals(rule.get("method"))) {
                String body = (String) rule.get("body");
                List<String> requestHeaders = scanner.getHelp().analyzeRequest(request).getHeaders();
                
                // 替换请求行为POST
                String firstLine = requestHeaders.get(0);
                if (!firstLine.startsWith("POST")) {
                    String[] parts = firstLine.split(" ", 3);
                    if (parts.length == 3) {
                        requestHeaders.set(0, "POST " + parts[1] + " " + parts[2]);
                    }
                }
                
                // 添加POST体
                if (body != null && !body.isEmpty()) {
                    request = scanner.getHelp().buildHttpMessage(requestHeaders, body.getBytes());
                } else {
                    request = scanner.getHelp().buildHttpMessage(requestHeaders, new byte[]{});
                }
            }
            
            // 发送请求
            IHttpRequestResponse response = scanner.getCall().makeHttpRequest(scanner.getHttpService(), request);
            
            // 检查响应
            checkResponse(response, name, rePattern, info, states);
            
            // 如果启用了绕过功能，尝试绕过
            if (scanner.getBurp().BypassFirst) {
                performBypassFirst(response, name, rePattern, info, states, rulePath);
            }
            
            if (scanner.getBurp().Bypass) {
                performBypass(response, name, rePattern, info, states, rulePath);
            }
            
            if (scanner.getBurp().BypassEnd) {
                performBypassEnd(response, name, rePattern, info, states);
            }
            
            // 打印扫描URL
            scanner.getCall().printOutput("[Force Scan] Scanned: " + url.toString());
            
        } catch (MalformedURLException e) {
            scanner.getCall().printError("[Force Scan] Invalid URL: " + e.getMessage());
        }
    }
    
    /**
     * 检查响应是否匹配规则
     */
    private void checkResponse(IHttpRequestResponse response, String name, String rePattern, 
                              String info, List<Integer> states) {
        if (response.getResponse() == null) {
            return;
        }
        
        int statusCode = scanner.getHelp().analyzeResponse(response.getResponse()).getStatusCode();
        
        if (states.contains(statusCode)) {
            byte[] resp = response.getResponse();
            Pattern pattern = Pattern.compile(rePattern, Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(scanner.getHelp().bytesToString(resp));
            String size = String.valueOf(scanner.getHelp().bytesToString(resp).length());
            
            if (matcher.find()) {
                // 添加结果
                vulscan.ir_add(
                    scanner.getBurp().tags,
                    name,
                    scanner.getHelp().analyzeRequest(response).getMethod(),
                    scanner.getHelp().analyzeRequest(response).getUrl().toString(),
                    String.valueOf(statusCode) + " ",
                    info,
                    size,
                    response
                );
            }
        }
    }
    
    /**
     * 执行前缀绕过
     */
    private void performBypassFirst(IHttpRequestResponse response, String name, String rePattern, 
                                   String info, List<Integer> states, String rulePath) {
        for (String bypass : bypassFirstList) {
            try {
                String normalizedPath = normalizePath(basePath, rulePath);
                byte[] request = scanner.getHelp().buildHttpRequest(new URL(
                    scanner.getHttpService().getProtocol(),
                    scanner.getHttpService().getHost(),
                    scanner.getHttpService().getPort(),
                    normalizedPath
                ));
                
                byte[] bypassRequest = editBypassRequestFirst(request, bypass, rulePath);
                IHttpRequestResponse bypassResponse = scanner.getCall().makeHttpRequest(
                    scanner.getHttpService(), bypassRequest
                );
                
                checkResponse(bypassResponse, name, rePattern, info, states);
                
            } catch (Exception e) {
                scanner.getCall().printError("[Force Scan] Bypass error: " + e.getMessage());
            }
        }
    }
    
    /**
     * 执行路径绕过
     */
    private void performBypass(IHttpRequestResponse response, String name, String rePattern, 
                              String info, List<Integer> states, String rulePath) {
        for (String bypass : bypassList) {
            try {
                String normalizedPath = normalizePath(basePath, rulePath);
                byte[] request = scanner.getHelp().buildHttpRequest(new URL(
                    scanner.getHttpService().getProtocol(),
                    scanner.getHttpService().getHost(),
                    scanner.getHttpService().getPort(),
                    normalizedPath
                ));
                
                byte[] bypassRequest = editBypassRequest(request, bypass, rulePath);
                IHttpRequestResponse bypassResponse = scanner.getCall().makeHttpRequest(
                    scanner.getHttpService(), bypassRequest
                );
                
                checkResponse(bypassResponse, name, rePattern, info, states);
                
            } catch (Exception e) {
                scanner.getCall().printError("[Force Scan] Bypass error: " + e.getMessage());
            }
        }
    }
    
    /**
     * 执行后缀绕过
     */
    private void performBypassEnd(IHttpRequestResponse response, String name, String rePattern, 
                                 String info, List<Integer> states) {
        for (String bypass : bypassEndList) {
            try {
                // 直接使用response的请求，而不是通过IRequestInfo获取
                byte[] request = response.getRequest();
                byte[] bypassRequest = editBypassRequestEnd(request, bypass);
                IHttpRequestResponse bypassResponse = scanner.getCall().makeHttpRequest(
                    scanner.getHttpService(), bypassRequest
                );
                
                checkResponse(bypassResponse, name, rePattern, info, states);
                
            } catch (Exception e) {
                scanner.getCall().printError("[Force Scan] Bypass error: " + e.getMessage());
            }
        }
    }
    
    /**
     * 编辑请求添加前缀绕过
     */
    private byte[] editBypassRequestFirst(byte[] request, String bypass, String payPath) {
        String requests = scanner.getHelp().bytesToString(request);
        String[] rows = requests.split("\r\n");
        String path = rows[0].split(" ")[1];
        String prefix = "";

        if (path.contains("http://")) {
            prefix = "http://";
            path = path.replace("http://", "");
        } else if (path.contains("https://")) {
            prefix = "https://";
            path = path.replace("https://", "");
        }

        String newPathSingle = path.replace(payPath, "") + payPath.replaceFirst("/", "/" + bypass + "/");
        if (path.endsWith("/")) {
            newPathSingle = newPathSingle.substring(0, newPathSingle.lastIndexOf(bypass + "/"));
        }
        newPathSingle = prefix + newPathSingle;
        String row1Single = rows[0].split(" ")[0] + " " + newPathSingle + " " + rows[0].split(" ")[2];
        String newRequestSingle = requests.replace(rows[0], row1Single);

        return scanner.getHelp().stringToBytes(newRequestSingle);
    }
    
    /**
     * 编辑请求添加路径绕过
     */
    private byte[] editBypassRequest(byte[] request, String bypass, String payPath) {
        String requests = scanner.getHelp().bytesToString(request);
        String[] rows = requests.split("\r\n");
        String path = rows[0].split(" ")[1];
        String prefix = "";
        
        if (path.contains("http://")) {
            prefix = "http://";
            path = path.replace("http://", "");
        } else if (path.contains("https://")) {
            prefix = "https://";
            path = path.replace("https://", "");
        }

        String newpath = path.replace(payPath,"") + payPath.replace("/", "/" + bypass + "/");
        if (path.endsWith("/")) {
            newpath = newpath.substring(0, newpath.lastIndexOf(bypass + "/"));
        }
        newpath = prefix + newpath;
        String row1 = rows[0].split(" ")[0] + " " + newpath + " " + rows[0].split(" ")[2];
        String newRequest = requests.replace(rows[0], row1);
        
        return scanner.getHelp().stringToBytes(newRequest);
    }
    
    /**
     * 编辑请求添加后缀绕过
     */
    private byte[] editBypassRequestEnd(byte[] request, String bypassEnd) {
        String requests = scanner.getHelp().bytesToString(request);
        String[] rows = requests.split("\r\n");
        String path = rows[0].split(" ")[1];
        String prefix = "";

        if (path.contains("http://")) {
            prefix = "http://";
            path = path.replace("http://", "");
        } else if (path.contains("https://")) {
            prefix = "https://";
            path = path.replace("https://", "");
        }

        String newPathEnd = prefix + path + bypassEnd;
        String row1End = rows[0].split(" ")[0] + " " + newPathEnd + " " + rows[0].split(" ")[2];
        String newRequestEnd = requests.replace(rows[0], row1End);

        return scanner.getHelp().stringToBytes(newRequestEnd);
    }
    
    /**
     * 规范化路径，确保不会出现连续的斜杠
     * @param basePath 基础路径
     * @param rulePath 规则路径
     * @return 规范化后的路径
     */
    private String normalizePath(String basePath, String rulePath) {
        // 确保basePath以斜杠结尾
        String base = basePath.endsWith("/") ? basePath : basePath + "/";
        
        // 确保rulePath不以斜杠开头
        String rule = rulePath.startsWith("/") ? rulePath.substring(1) : rulePath;
        
        // 合并路径
        String path = base + rule;
        
        // 替换连续的斜杠为单个斜杠
        while (path.contains("//")) {
            path = path.replace("//", "/");
        }
        
        return path;
    }
    
    /**
     * 解析状态码
     */
    private List<Integer> parseStatusCodes(String stateStr) {
        List<Integer> states = new ArrayList<>();
        
        if (stateStr == null || stateStr.isEmpty()) {
            states.add(200);
            return states;
        }
        
        String[] stateArray = stateStr.split(",");
        for (String state : stateArray) {
            state = state.trim();
            if (state.contains("-")) {
                String[] range = state.split("-");
                int start = Integer.parseInt(range[0].trim());
                int end = Integer.parseInt(range[1].trim());
                for (int i = start; i <= end; i++) {
                    states.add(i);
                }
            } else {
                states.add(Integer.parseInt(state));
            }
        }
        
        return states;
    }
}