package utils;

import burp.BurpExtender;
import burp.IResponseInfo;
import yaml.YamlUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * 结果过滤工具类
 * 用于过滤被动扫描结果中的误报和不需要的结果
 */
public class ResultFilter {
    private BurpExtender burp;
    private List<String> filterRules;
    
    public ResultFilter(BurpExtender burp) {
        this.burp = burp;
        loadFilterRules();
    }
    
    /**
     * 从配置文件加载过滤规则
     */
    private void loadFilterRules() {
        try {
            Map<String, Object> config = YamlUtil.readYaml(BurpExtender.Yaml_Path);
            filterRules = (List<String>) config.get("Result_Filter_List");
            
            if (filterRules == null) {
                filterRules = new ArrayList<>();
            }
            
            if (burp != null && burp.call != null) {
                burp.call.printOutput("[ResultFilter] Loaded " + filterRules.size() + " filter rules");
            }
        } catch (Exception e) {
            filterRules = new ArrayList<>();
            if (burp != null && burp.call != null) {
                burp.call.printError("[ResultFilter] Failed to load filter rules: " + e.getMessage());
            }
        }
    }
    
    /**
     * 检查响应内容是否应该被过滤（使用原始字节数据）
     * @param response 原始响应字节数组
     * @param responseInfo 响应信息
     * @return true表示应该过滤（不显示），false表示不过滤（正常显示）
     */
    public boolean shouldFilter(byte[] response, IResponseInfo responseInfo) {
        if (filterRules == null || filterRules.isEmpty()) {
            return false;
        }
        
        // 检查响应大小，如果超过2MB就跳过过滤检测
        final int MAX_RESPONSE_SIZE = 2 * 1024 * 1024; // 2MB
        if (response.length > MAX_RESPONSE_SIZE) {
            if (burp != null && burp.call != null) {
                burp.call.printOutput("[ResultFilter] 响应大小超过2MB (" + response.length + " bytes)，跳过过滤检测");
            }
            return false;
        }
        
        // 使用与指纹识别相同的编码检测逻辑
        String responseBody = getResponseBody(response, responseInfo);
        String responseHeaders = getResponseHeaders(responseInfo);
        
        // 合并响应体和响应头进行检查
        String fullResponse = responseBody + "\n" + responseHeaders;
        
        // 增加调试日志，打印完整响应内容
        if (burp != null && burp.call != null) {
            //burp.call.printOutput("[ResultFilter] 完整响应内容开始 ---");
            //burp.call.printOutput(fullResponse);
            //burp.call.printOutput("[ResultFilter] 完整响应内容结束 ---");
            //burp.call.printOutput("[ResultFilter] 过滤规则列表: " + String.join(", ", filterRules));
        }
        
        for (String rule : filterRules) {
            if (rule == null || rule.trim().isEmpty()) {
                continue;
            }
            
            try {
                // 增加详细的匹配日志
                if (burp != null && burp.call != null) {
                    //burp.call.printOutput("[ResultFilter] 正在检查规则: " + rule);
                }

                // 精确匹配
                if (fullResponse.contains(rule)) {
                    if (burp != null && burp.call != null) {
                        burp.call.printOutput("[ResultFilter] 精确匹配过滤规则: " + rule);
                    }
                    return true;
                }

                // 忽略大小写匹配
                if (fullResponse.toLowerCase().contains(rule.toLowerCase())) {
                    if (burp != null && burp.call != null) {
                        burp.call.printOutput("[ResultFilter] 忽略大小写匹配规则: " + rule);
                    }
                    return true;
                }

                // 正则匹配（支持中文和Unicode）
                Pattern pattern = Pattern.compile(rule, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
                Matcher matcher = pattern.matcher(fullResponse);
                
                if (matcher.find()) {
                    if (burp != null && burp.call != null) {
                        burp.call.printOutput("[ResultFilter] 正则匹配过滤规则: " + rule);
                    }
                    return true;
                }
            } catch (Exception e) {
                if (burp != null && burp.call != null) {
                    burp.call.printError("[ResultFilter] 规则匹配异常: " + e.getMessage());
                }
            }
        }
        
        return false;
    }

    /**
     * 兼容性方法：检查响应内容是否应该被过滤（使用字符串）
     * @param responseBody 响应体内容
     * @param responseHeaders 响应头内容
     * @return true表示应该过滤（不显示），false表示不过滤（正常显示）
     */
    public boolean shouldFilter(String responseBody, String responseHeaders) {
        if (filterRules == null || filterRules.isEmpty()) {
            return false;
        }
        
        // 合并响应体和响应头进行检查
        String fullResponse = responseBody + "\n" + responseHeaders;
        
        // 检查响应大小，如果超过2MB就跳过过滤检测
        final int MAX_RESPONSE_SIZE = 2 * 1024 * 1024; // 2MB
        if (fullResponse.getBytes().length > MAX_RESPONSE_SIZE) {
            if (burp != null && burp.call != null) {
                burp.call.printOutput("[ResultFilter] 响应大小超过2MB (" + fullResponse.getBytes().length + " bytes)，跳过过滤检测");
            }
            return false;
        }
        
        for (String rule : filterRules) {
            if (rule == null || rule.trim().isEmpty()) {
                continue;
            }
            
            try {
                // 精确匹配
                if (fullResponse.contains(rule)) {
                    return true;
                }

                // 忽略大小写匹配
                if (fullResponse.toLowerCase().contains(rule.toLowerCase())) {
                    return true;
                }

                // 正则匹配
                Pattern pattern = Pattern.compile(rule, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
                Matcher matcher = pattern.matcher(fullResponse);
                
                if (matcher.find()) {
                    return true;
                }
            } catch (Exception e) {
                // 忽略异常
            }
        }
        
        return false;
    }

    /**
     * 获取响应体内容（复制自指纹识别的编码检测逻辑）
     */
    private String getResponseBody(byte[] response, IResponseInfo responseInfo) {
        try {
            int bodyOffset = responseInfo.getBodyOffset();
            
            // 提取响应体字节数组
            byte[] bodyBytes = new byte[response.length - bodyOffset];
            System.arraycopy(response, bodyOffset, bodyBytes, 0, bodyBytes.length);
            
            // 尝试检测编码并正确转换
            String responseBody = detectEncodingAndDecode(bodyBytes, responseInfo);
            
            return responseBody;
        } catch (Exception e) {
            return "";
        }
    }
    
    /**
     * 检测编码并解码响应体（复制自指纹识别的逻辑）
     */
    private String detectEncodingAndDecode(byte[] bodyBytes, IResponseInfo responseInfo) {
        // 1. 首先尝试从Content-Type头中获取编码
        String charset = extractCharsetFromHeaders(responseInfo);
        
        if (charset != null) {
            try {
                String decoded = new String(bodyBytes, charset);
                if (burp != null && burp.call != null) {
                    //burp.call.printOutput("[ResultFilter] 使用头部指定编码 " + charset + " 解码成功");
                }
                return decoded;
            } catch (Exception e) {
                if (burp != null && burp.call != null) {
                    burp.call.printOutput("[ResultFilter] 使用头部指定编码 " + charset + " 解码失败，尝试其他编码");
                }
            }
        }
        
        // 2. 尝试从HTML meta标签中获取编码
        String htmlCharset = extractCharsetFromHtml(bodyBytes);
        if (htmlCharset != null) {
            try {
                String decoded = new String(bodyBytes, htmlCharset);
                if (burp != null && burp.call != null) {
                    //burp.call.printOutput("[ResultFilter] 使用HTML指定编码 " + htmlCharset + " 解码成功");
                }
                return decoded;
            } catch (Exception e) {
                if (burp != null && burp.call != null) {
                    burp.call.printOutput("[ResultFilter] 使用HTML指定编码 " + htmlCharset + " 解码失败");
                }
            }
        }
        
        // 3. 尝试常见编码
        String[] commonCharsets = {"UTF-8", "GBK", "GB2312", "ISO-8859-1"};
        for (String testCharset : commonCharsets) {
            try {
                String decoded = new String(bodyBytes, testCharset);
                // 简单检查是否包含中文字符，如果包含且不是乱码，则可能是正确的编码
                if (testCharset.equals("UTF-8") || testCharset.equals("GBK") || testCharset.equals("GB2312")) {
                    if (containsChineseCharacters(decoded)) {
                        if (burp != null && burp.call != null) {
                            burp.call.printOutput("[ResultFilter] 使用编码 " + testCharset + " 成功解码中文内容");
                        }
                        return decoded;
                    }
                }
                // 对于其他编码，直接返回
                if (testCharset.equals("UTF-8")) {
                    if (burp != null && burp.call != null) {
                        burp.call.printOutput("[ResultFilter] 使用UTF-8编码解码");
                    }
                    return decoded; // UTF-8作为默认首选
                }
            } catch (Exception e) {
                continue;
            }
        }
        
        // 4. 最后使用默认编码
        try {
            String decoded = new String(bodyBytes);
            if (burp != null && burp.call != null) {
                burp.call.printOutput("[ResultFilter] 使用默认编码解码");
            }
            return decoded;
        } catch (Exception e) {
            return ""; // 返回空字符串
        }
    }
    
    /**
     * 从HTTP头中提取字符集
     */
    private String extractCharsetFromHeaders(IResponseInfo responseInfo) {
        try {
            List<String> headers = responseInfo.getHeaders();
            for (String header : headers) {
                if (header.toLowerCase().startsWith("content-type:")) {
                    Pattern charsetPattern = Pattern.compile("charset=([^;\\s]+)", Pattern.CASE_INSENSITIVE);
                    java.util.regex.Matcher matcher = charsetPattern.matcher(header);
                    if (matcher.find()) {
                        return matcher.group(1).trim();
                    }
                }
            }
        } catch (Exception e) {
            // 忽略异常
        }
        return null;
    }
    
    /**
     * 从HTML meta标签中提取字符集
     */
    private String extractCharsetFromHtml(byte[] bodyBytes) {
        try {
            // 先用UTF-8尝试解码前1024字节来查找meta标签
            String htmlStart = new String(bodyBytes, 0, Math.min(1024, bodyBytes.length), "UTF-8");
            
            // 查找charset meta标签
            Pattern metaPattern = Pattern.compile("<meta[^>]+charset=[\"']?([^\"'>\\s]+)", Pattern.CASE_INSENSITIVE);
            java.util.regex.Matcher matcher = metaPattern.matcher(htmlStart);
            if (matcher.find()) {
                String detectedCharset = matcher.group(1).trim();
                return detectedCharset;
            }
        } catch (Exception e) {
            // 忽略异常
        }
        return null;
    }
    
    /**
     * 检查字符串是否包含中文字符
     */
    private boolean containsChineseCharacters(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }
        
        for (char c : text.toCharArray()) {
            if (c >= 0x4E00 && c <= 0x9FFF) { // 中文字符Unicode范围
                return true;
            }
        }
        return false;
    }
    
    /**
     * 获取响应头内容
     */
    private String getResponseHeaders(IResponseInfo responseInfo) {
        try {
            List<String> headers = responseInfo.getHeaders();
            return String.join(" ", headers).toLowerCase();
        } catch (Exception e) {
            return "";
        }
    }
    
    /**
     * 重新加载过滤规则
     */
    public void reloadFilterRules() {
        loadFilterRules();
    }
    
    /**
     * 获取当前过滤规则数量
     */
    public int getFilterRulesCount() {
        return filterRules != null ? filterRules.size() : 0;
    }
}