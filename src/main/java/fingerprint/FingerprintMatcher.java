package fingerprint;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IHttpService;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.security.MessageDigest;
import java.util.Base64;
import java.net.URL;
import java.nio.ByteBuffer;

/**
 * 指纹匹配器
 * 基于EHole项目的指纹识别逻辑
 */
public class FingerprintMatcher {
    private IExtensionHelpers helpers;
    private List<FingerPrint> fingerprints;
    private burp.BurpExtender burp;
    
    /**
     * 指纹匹配结果详情
     */
    public static class MatchResult {
        private String cms;
        private String matchType;
        private String matchDetail;
        
        public MatchResult(String cms, String matchType, String matchDetail) {
            this.cms = cms;
            this.matchType = matchType;
            this.matchDetail = matchDetail;
        }
        
        public String getCms() { return cms; }
        public String getMatchType() { return matchType; }
        public String getMatchDetail() { return matchDetail; }
        
        @Override
        public String toString() {
            return "【" + matchType + "】" + cms;
        }
    }
    
    public FingerprintMatcher(IExtensionHelpers helpers) {
        this.helpers = helpers;
        this.fingerprints = new ArrayList<>();
        this.burp = null;
    }
    
    public FingerprintMatcher(burp.BurpExtender burp) {
        this.burp = burp;
        this.helpers = burp.help;
        this.fingerprints = new ArrayList<>();
    }
    
    /**
     * 加载指纹库
     */
    public void loadFingerprints(List<FingerPrint> fingerprints) {
        this.fingerprints = fingerprints;
    }
    
    /**
     * 对根目录进行指纹识别
     * @param requestResponse HTTP请求响应对
     * @return 识别到的CMS列表
     */
    public List<String> identifyFingerprint(IHttpRequestResponse requestResponse) {
        List<MatchResult> matchResults = identifyFingerprintWithDetails(requestResponse);
        List<String> identifiedCMS = new ArrayList<>();
        for (MatchResult result : matchResults) {
            identifiedCMS.add(result.getCms());
        }
        return identifiedCMS;
    }
    
    /**
     * 对根目录进行指纹识别（带详细匹配信息）
     * @param requestResponse HTTP请求响应对
     * @return 识别到的指纹详情列表
     */
    public List<MatchResult> identifyFingerprintWithDetails(IHttpRequestResponse requestResponse) {
        List<MatchResult> identifiedCMS = new ArrayList<>();
        
        if (requestResponse.getResponse() == null) {
            return identifiedCMS;
        }
        
        // 获取路径信息用于调试
        IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
        String path = requestInfo.getUrl().getPath();
        
        IResponseInfo responseInfo = helpers.analyzeResponse(requestResponse.getResponse());
        int statusCode = responseInfo.getStatusCode();
        
        // 获取响应内容
        String responseBody = getResponseBody(requestResponse.getResponse(), responseInfo);
        String responseHeaders = getResponseHeaders(responseInfo);
        String title = extractTitle(responseBody);
        
        // 调试信息 - 使用Burp输出而不是System.out
        // if (burp != null) {
        //     burp.call.printOutput("[Debug] 开始指纹识别 - 路径: " + path + ", 状态码: " + statusCode);
        //     burp.call.printOutput("[Debug] 标题: " + title);
        //     burp.call.printOutput("[Debug] 响应体长度: " + responseBody.length());
        // }
        
        // 检查并处理favicon（如果响应是HTML）
        String faviconHash = null;
        try {
            if (isHtmlResponse(responseInfo, responseBody)) {
                faviconHash = processFaviconFromHtml(requestResponse, responseBody);
            } else if (isFaviconRequest(path)) {
                // 如果直接请求的是favicon文件
                faviconHash = calculateFaviconHash(requestResponse.getResponse(), responseInfo);
            }
        } catch (Exception e) {
            // if (burp != null) {
            //     burp.call.printOutput("[Debug] Favicon处理出错: " + e.getMessage());
            // }
        }
        
        // 遍历所有指纹进行匹配
        int matchCount = 0;
        for (FingerPrint fingerprint : fingerprints) {
            MatchResult matchResult = matchFingerprintWithDetails(fingerprint, statusCode, responseBody, responseHeaders, title, faviconHash);
            if (matchResult != null) {
                // 检查是否已经存在相同的CMS
                boolean alreadyExists = false;
                for (MatchResult existing : identifiedCMS) {
                    if (existing.getCms().equals(matchResult.getCms())) {
                        alreadyExists = true;
                        break;
                    }
                }
                
                if (!alreadyExists) {
                    identifiedCMS.add(matchResult);
                    matchCount++;
                    if (burp != null) {
                        burp.call.printOutput("[Fingerprint] 匹配到指纹: " + matchResult.toString());
                    }
                }
            }
        }
        
        // if (burp != null) {
        //     burp.call.printOutput("[Debug] 总共匹配到 " + matchCount + " 个指纹");
        // }
        return identifiedCMS;
    }
    
    /**
     * 检查是否为根目录路径
     * 根据EHole的规则，只对根目录进行指纹识别
     */
    private boolean isRootPath(String path) {
        // 基本根目录路径
        if (path == null || path.equals("/") || path.equals("") || 
            path.equals("/index.html") || path.equals("/index.php") || 
            path.equals("/index.jsp") || path.equals("/default.html") ||
            path.equals("/index.htm") || path.equals("/default.htm")) {
            return true;
        }
        
        // 检查是否为根目录下的常见文件
        String[] rootFiles = {
            "/favicon.ico", "/robots.txt", "/sitemap.xml", 
            "/crossdomain.xml", "/apple-touch-icon.png",
            "/index", "/admin", "/login", "/home"
        };
        
        for (String rootFile : rootFiles) {
            if (path.equals(rootFile)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 匹配单个指纹（带详细信息）
     */
    private MatchResult matchFingerprintWithDetails(FingerPrint fingerprint, int statusCode, 
                                   String responseBody, String responseHeaders, String title, String faviconHash) {
        // 检查状态码 - 如果指纹没有指定状态码(为0)，则接受任何状态码
        if (fingerprint.getStatus() != 0 && fingerprint.getStatus() != statusCode) {
            return null;
        }
        
        // 检查是否为faviconhash匹配
        if ("faviconhash".equals(fingerprint.getMethod())) {
            if (matchFaviconHash(fingerprint.getKeyword(), faviconHash)) {
                return new MatchResult(fingerprint.getCms(), "faviconhash", "Favicon哈希匹配: " + faviconHash);
            }
            return null;
        }
        
        // 根据匹配位置进行关键词匹配
        String targetContent = "";
        String matchType = "";
        switch (fingerprint.getLocation().toLowerCase()) {
            case "body":
                targetContent = responseBody;
                matchType = "body";
                break;
            case "header":
                targetContent = responseHeaders;
                matchType = "header";
                break;
            case "title":
                targetContent = title;
                matchType = "title";
                break;
            default:
                // 如果位置不明确，在所有内容中搜索
                targetContent = responseBody + " " + responseHeaders + " " + title;
                matchType = "all";
                break;
        }
        
        // 检查关键词匹配
        if (matchKeywords(fingerprint.getKeyword(), targetContent)) {
            String matchDetail = "关键词匹配: " + String.join(", ", fingerprint.getKeyword());
            return new MatchResult(fingerprint.getCms(), matchType, matchDetail);
        }
        
        return null;
    }
    
    /**
     * 匹配单个指纹（兼容性方法）
     */
    private boolean matchFingerprint(FingerPrint fingerprint, int statusCode, 
                                   String responseBody, String responseHeaders, String title, String faviconHash) {
        MatchResult result = matchFingerprintWithDetails(fingerprint, statusCode, responseBody, responseHeaders, title, faviconHash);
        return result != null;
    }
    
    /**
     * 关键词匹配逻辑
     * 支持多关键字匹配：所有关键字都必须匹配上才能识别成功
     */
    private boolean matchKeywords(List<String> keywords, String content) {
        if (keywords == null || keywords.isEmpty()) {
            return false;
        }
        
        content = content.toLowerCase();
        
        // 遍历所有关键字，所有关键字都必须匹配
        for (String keyword : keywords) {
            if (!matchSingleKeyword(keyword.toLowerCase().trim(), content)) {
                // 如果任何一个关键字不匹配，则整体匹配失败
                // if (burp != null) {
                //     burp.call.printOutput("[Debug] 关键字匹配失败: " + keyword);
                // }
                return false;
            }
        }
        
        // 所有关键字都匹配成功
        // if (burp != null) {
        //     burp.call.printOutput("[Debug] 所有关键字匹配成功，共 " + keywords.size() + " 个关键字");
        // }
        return true;
    }
    
    /**
     * 单个关键词匹配
     * 支持正则表达式、否定匹配和普通字符串匹配
     */
    private boolean matchSingleKeyword(String keyword, String content) {
        if (keyword == null || keyword.isEmpty()) {
            return false;
        }
        
        keyword = keyword.trim();
        
        // 处理否定匹配
        if (keyword.startsWith("!")) {
            String negativeKeyword = keyword.substring(1);
            boolean result = !content.contains(negativeKeyword);
            // if (burp != null) {
            //     burp.call.printOutput("[Debug] 否定匹配 '" + negativeKeyword + "': " + result);
            // }
            return result;
        }
        
        // 处理正则表达式匹配
        if (keyword.startsWith("regex:")) {
            try {
                String regex = keyword.substring(6);
                Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
                boolean result = pattern.matcher(content).find();
                // if (burp != null) {
                //     burp.call.printOutput("[Debug] 正则匹配 '" + regex + "': " + result);
                // }
                return result;
            } catch (Exception e) {
                // if (burp != null) {
                //     burp.call.printOutput("[Debug] 正则表达式错误: " + keyword + " - " + e.getMessage());
                // }
                return false;
            }
        }
        
        // 处理AND逻辑（在单个关键字内部）
        if (keyword.contains("&&")) {
            String[] andKeywords = keyword.split("&&");
            for (String andKeyword : andKeywords) {
                if (!content.contains(andKeyword.trim())) {
                    // if (burp != null) {
                    //     burp.call.printOutput("[Debug] AND逻辑匹配失败: " + andKeyword.trim());
                    // }
                    return false;
                }
            }
            // if (burp != null) {
            //     burp.call.printOutput("[Debug] AND逻辑匹配成功: " + keyword);
            // }
            return true;
        }
        
        // 处理OR逻辑（在单个关键字内部）
        if (keyword.contains("||")) {
            String[] orKeywords = keyword.split("\\|\\|");
            for (String orKeyword : orKeywords) {
                if (content.contains(orKeyword.trim())) {
                    // if (burp != null) {
                    //     burp.call.printOutput("[Debug] OR逻辑匹配成功: " + orKeyword.trim());
                    // }
                    return true;
                }
            }
            // if (burp != null) {
            //     burp.call.printOutput("[Debug] OR逻辑匹配失败: " + keyword);
            // }
            return false;
        }
        
        // 普通字符串匹配
        boolean result = content.contains(keyword);
        // if (burp != null) {
        //     burp.call.printOutput("[Debug] 普通匹配 '" + keyword + "': " + result);
        // }
        return result;
    }
    
    /**
     * 获取响应体内容
     */
    private String getResponseBody(byte[] response, IResponseInfo responseInfo) {
        try {
            int bodyOffset = responseInfo.getBodyOffset();
            
            // 提取响应体字节数组
            byte[] bodyBytes = new byte[response.length - bodyOffset];
            System.arraycopy(response, bodyOffset, bodyBytes, 0, bodyBytes.length);
            
            // 尝试检测编码并正确转换
            String responseBody = detectEncodingAndDecode(bodyBytes, responseInfo);
            
            // if (burp != null) {
            //     burp.call.printOutput("[Debug] 响应体编码检测结果，长度: " + responseBody.length());
            // }
            
            return responseBody;
        } catch (Exception e) {
            // if (burp != null) {
            //     burp.call.printError("[Debug] 响应体解码失败: " + e.getMessage());
            // }
            return "";
        }
    }
    
    /**
     * 检测编码并解码响应体
     */
    private String detectEncodingAndDecode(byte[] bodyBytes, IResponseInfo responseInfo) {
        // 1. 首先尝试从Content-Type头中获取编码
        String charset = extractCharsetFromHeaders(responseInfo);
        
        if (charset != null) {
            try {
                return new String(bodyBytes, charset);
            } catch (Exception e) {
                // if (burp != null) {
                //     burp.call.printOutput("[Debug] 使用头部指定编码 " + charset + " 解码失败，尝试其他编码");
                // }
            }
        }
        
        // 2. 尝试从HTML meta标签中获取编码
        String htmlCharset = extractCharsetFromHtml(bodyBytes);
        if (htmlCharset != null) {
            try {
                return new String(bodyBytes, htmlCharset);
            } catch (Exception e) {
                // if (burp != null) {
                //     burp.call.printOutput("[Debug] 使用HTML指定编码 " + htmlCharset + " 解码失败");
                // }
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
                        // if (burp != null) {
                        //     burp.call.printOutput("[Debug] 使用编码 " + testCharset + " 成功解码中文内容");
                        // }
                        return decoded;
                    }
                }
                // 对于其他编码，直接返回
                if (testCharset.equals("UTF-8")) {
                    return decoded; // UTF-8作为默认首选
                }
            } catch (Exception e) {
                continue;
            }
        }
        
        // 4. 最后使用默认编码
        return new String(bodyBytes);
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
                return matcher.group(1).trim();
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
     * 提取HTML标题
     */
    private String extractTitle(String html) {
        try {
            Pattern titlePattern = Pattern.compile("<title[^>]*>(.*?)</title>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
            java.util.regex.Matcher matcher = titlePattern.matcher(html);
            if (matcher.find()) {
                return matcher.group(1).trim();
            }
        } catch (Exception e) {
            // 忽略异常
        }
        return "";
    }
    
    /**
     * 添加单个指纹
     */
    public void addFingerprint(FingerPrint fingerprint) {
        this.fingerprints.add(fingerprint);
    }
    
    /**
     * 获取指纹数量
     */
    public int getFingerprintCount() {
        return fingerprints.size();
    }
    
    /**
     * 获取所有指纹
     */
    public List<FingerPrint> getFingerprints() {
        return new ArrayList<>(fingerprints);
    }
    
    /**
     * 删除指定指纹
     */
    public void deleteFingerprint(int index) {
        if (index >= 0 && index < fingerprints.size()) {
            fingerprints.remove(index);
        }
    }
    
    /**
     * 检查响应是否为HTML
     */
    private boolean isHtmlResponse(IResponseInfo responseInfo, String responseBody) {
        try {
            // 检查Content-Type
            List<String> headers = responseInfo.getHeaders();
            for (String header : headers) {
                if (header.toLowerCase().startsWith("content-type:") && 
                    header.toLowerCase().contains("text/html")) {
                    return true;
                }
            }
            
            // 检查响应体是否包含HTML标签
            if (responseBody.toLowerCase().contains("<html") || 
                responseBody.toLowerCase().contains("<!doctype")) {
                return true;
            }
        } catch (Exception e) {
            // 忽略异常
        }
        return false;
    }
    
    /**
     * 检查请求路径是否为favicon文件
     */
    private boolean isFaviconRequest(String path) {
        if (path == null) return false;
        String lowerPath = path.toLowerCase();
        return lowerPath.endsWith("favicon.ico") || 
               lowerPath.endsWith("favicon.png") || 
               lowerPath.endsWith("favicon.gif") ||
               lowerPath.contains("favicon");
    }
    
    /**
     * 从HTML中提取favicon并计算hash
     */
    private String processFaviconFromHtml(IHttpRequestResponse requestResponse, String responseBody) {
        try {
            // 提取favicon URL
            String faviconUrl = extractFaviconUrl(responseBody);
            if (faviconUrl == null || faviconUrl.isEmpty()) {
                // 尝试默认的favicon.ico
                faviconUrl = "/favicon.ico";
            }
            
            // if (burp != null) {
            //     burp.call.printOutput("[Debug] 检测到favicon URL: " + faviconUrl);
            // }
            
            // 访问favicon并计算hash
            return fetchAndCalculateFaviconHash(requestResponse.getHttpService(), faviconUrl);
            
        } catch (Exception e) {
            // if (burp != null) {
            //     burp.call.printOutput("[Debug] 从HTML处理favicon失败: " + e.getMessage());
            // }
            return null;
        }
    }
    
    /**
     * 从HTML中提取favicon URL
     */
    private String extractFaviconUrl(String html) {
        try {
            // 使用更灵活的正则表达式来匹配favicon链接
            // 这个模式可以匹配rel和href属性的任意顺序
            Pattern faviconPattern = Pattern.compile(
                "<link\\s+[^>]*(?:rel=[\"'](?:icon|shortcut\\s+icon)[\"'][^>]*href=[\"']([^\"']+)[\"']|href=[\"']([^\"']+)[\"'][^>]*rel=[\"'](?:icon|shortcut\\s+icon)[\"'])[^>]*>",
                Pattern.CASE_INSENSITIVE
            );
            
            java.util.regex.Matcher matcher = faviconPattern.matcher(html);
            if (matcher.find()) {
                // 返回匹配到的href值（group(1)或group(2)其中一个会有值）
                String href = matcher.group(1) != null ? matcher.group(1) : matcher.group(2);
                if (burp != null) {
                    burp.call.printOutput("[Debug] 从HTML提取到favicon URL: " + href);
                }
                return href;
            }
            
            // 如果上面的复杂正则没匹配到，尝试简单的分步匹配
            Pattern linkPattern = Pattern.compile("<link[^>]*>", Pattern.CASE_INSENSITIVE);
            java.util.regex.Matcher linkMatcher = linkPattern.matcher(html);
            
            while (linkMatcher.find()) {
                String linkTag = linkMatcher.group();
                
                // 检查是否包含favicon相关的rel属性
                if (linkTag.toLowerCase().contains("rel=\"icon\"") || 
                    linkTag.toLowerCase().contains("rel='icon'") ||
                    linkTag.toLowerCase().contains("rel=\"shortcut icon\"") ||
                    linkTag.toLowerCase().contains("rel='shortcut icon'")) {
                    
                    // 提取href属性
                    Pattern hrefPattern = Pattern.compile("href=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
                    java.util.regex.Matcher hrefMatcher = hrefPattern.matcher(linkTag);
                    if (hrefMatcher.find()) {
                        String href = hrefMatcher.group(1);
                        if (burp != null) {
                            burp.call.printOutput("[Debug] 通过分步匹配提取到favicon URL: " + href);
                        }
                        return href;
                    }
                }
            }
            
        } catch (Exception e) {
            if (burp != null) {
                burp.call.printOutput("[Debug] favicon URL提取失败: " + e.getMessage());
            }
        }
        return null;
    }
    
    /**
     * 访问favicon并计算hash
     */
    private String fetchAndCalculateFaviconHash(IHttpService httpService, String faviconUrl) {
        try {
            // 构建favicon的完整URL
            String fullUrl;
            if (faviconUrl.startsWith("http://") || faviconUrl.startsWith("https://")) {
                fullUrl = faviconUrl;
            } else {
                fullUrl = httpService.getProtocol() + "://" + httpService.getHost() + ":" + httpService.getPort() + faviconUrl;
            }
            
            // if (burp != null) {
            //     burp.call.printOutput("[Debug] 访问favicon: " + fullUrl);
            // }
            
            // 发送请求获取favicon
            URL url = new URL(fullUrl);
            byte[] request = helpers.buildHttpRequest(url);
            IHttpRequestResponse faviconResponse = burp.call.makeHttpRequest(httpService, request);
            
            if (faviconResponse.getResponse() != null) {
                IResponseInfo responseInfo = helpers.analyzeResponse(faviconResponse.getResponse());
                return calculateFaviconHash(faviconResponse.getResponse(), responseInfo);
            }
            
        } catch (Exception e) {
            // if (burp != null) {
            //     burp.call.printOutput("[Debug] 访问favicon失败: " + e.getMessage());
            // }
        }
        return null;
    }
    
    /**
     * 计算favicon hash (EHole标准算法)
     * 1. 获取favicon二进制数据
     * 2. Base64编码并格式化（每76字符换行）
     * 3. 计算MurmurHash3
     * 4. 返回32位有符号整数
     */
    private String calculateFaviconHash(byte[] response, IResponseInfo responseInfo) {
        try {
            // 提取favicon的二进制数据
            int bodyOffset = responseInfo.getBodyOffset();
            byte[] faviconData = new byte[response.length - bodyOffset];
            System.arraycopy(response, bodyOffset, faviconData, 0, faviconData.length);
            
            // if (burp != null) {
            //     burp.call.printOutput("[Debug] Favicon数据大小: " + faviconData.length + " 字节");
            // }
            
            // 1. 进行标准Base64编码
            String base64Encoded = Base64.getEncoder().encodeToString(faviconData);
            
            // 2. 格式化Base64字符串（每76字符换行，最后添加换行）
            String formattedBase64 = formatBase64(base64Encoded);
            
            // if (burp != null) {
            //     burp.call.printOutput("[Debug] Base64编码长度: " + formattedBase64.length());
            // }
            
            // 3. 计算MurmurHash3 (使用Java实现的简化版本)
            int hash = murmurHash3_32(formattedBase64.getBytes(), 0);
            String hashString = String.valueOf(hash);
            
            // if (burp != null) {
            //     burp.call.printOutput("[Debug] 计算得到favicon hash: " + hashString);
            // }
            
            return hashString;
            
        } catch (Exception e) {
            // if (burp != null) {
            //     burp.call.printError("[Debug] 计算favicon hash失败: " + e.getMessage());
            // }
            return null;
        }
    }
    
    /**
     * 格式化Base64字符串（EHole标准格式）
     * 每76字符添加一个换行符，最后添加换行符
     */
    private String formatBase64(String base64) {
        StringBuilder buffer = new StringBuilder();
        for (int i = 0; i < base64.length(); i++) {
            buffer.append(base64.charAt(i));
            if ((i + 1) % 76 == 0) {
                buffer.append('\n');
            }
        }
        buffer.append('\n');
        return buffer.toString();
    }
    
    /**
     * MurmurHash3 32位实现（Java版本）
     * 基于Austin Appleby的MurmurHash3算法
     */
    private int murmurHash3_32(byte[] data, int seed) {
        final int c1 = 0xcc9e2d51;
        final int c2 = 0x1b873593;
        final int r1 = 15;
        final int r2 = 13;
        final int m = 5;
        final int n = 0xe6546b64;
        
        int hash = seed;
        int len = data.length;
        int roundedEnd = (len & 0xfffffffc); // round down to 4 byte block
        
        for (int i = 0; i < roundedEnd; i += 4) {
            // little endian load order
            int k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) |
                     ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24);
            k1 *= c1;
            k1 = (k1 << r1) | (k1 >>> (32 - r1));
            k1 *= c2;
            
            hash ^= k1;
            hash = (hash << r2) | (hash >>> (32 - r2));
            hash = hash * m + n;
        }
        
        // tail
        int k1 = 0;
        switch (len & 0x03) {
            case 3:
                k1 = (data[roundedEnd + 2] & 0xff) << 16;
            case 2:
                k1 |= (data[roundedEnd + 1] & 0xff) << 8;
            case 1:
                k1 |= (data[roundedEnd] & 0xff);
                k1 *= c1;
                k1 = (k1 << r1) | (k1 >>> (32 - r1));
                k1 *= c2;
                hash ^= k1;
        }
        
        // finalization
        hash ^= len;
        hash ^= (hash >>> 16);
        hash *= 0x85ebca6b;
        hash ^= (hash >>> 13);
        hash *= 0xc2b2ae35;
        hash ^= (hash >>> 16);
        
        return hash;
    }
    
    /**
     * 匹配favicon hash
     */
    private boolean matchFaviconHash(List<String> expectedHashes, String actualHash) {
        if (expectedHashes == null || expectedHashes.isEmpty() || actualHash == null) {
            // if (burp != null) {
            //     burp.call.printOutput("[Debug] Favicon hash匹配失败: 数据为空");
            // }
            return false;
        }
        
        for (String expectedHash : expectedHashes) {
            if (expectedHash.trim().equals(actualHash.trim())) {
                // 保留匹配成功的日志
                if (burp != null) {
                    burp.call.printOutput("[Fingerprint] Favicon hash匹配成功: " + actualHash);
                }
                return true;
            }
        }
        
        // if (burp != null) {
        //     burp.call.printOutput("[Debug] Favicon hash匹配失败: 期望" + expectedHashes + ", 实际" + actualHash);
        // }
        return false;
    }
}