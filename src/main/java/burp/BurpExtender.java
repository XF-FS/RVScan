package burp;

import UI.Tags;
import func.vulscan;
import func.ForceScan;
import utils.BurpAnalyzedRequest;
import utils.DomainNameRepeat;
import utils.ThreadPoolManager;
import utils.UrlRepeat;
import yaml.YamlUtil;
import fingerprint.FingerprintScanner;
import fingerprint.FingerprintConfig;
import APIKit.ApiKitPassiveScanner;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class BurpExtender implements IBurpExtender, IScannerCheck, IContextMenuFactory {

    public static String Yaml_Path = System.getProperty("user.dir") + "/" + "Config_yaml.yaml";
    public IBurpExtenderCallbacks call;
    private DomainNameRepeat DomainName;
    public IExtensionHelpers help;
    public Tags tags;
    private UrlRepeat urlC;
    // 使用并发集合替代手动同步的集合，提高多线程性能
public Set<String> history_url = ConcurrentHashMap.newKeySet();
    public static String EXPAND_NAME = "RVScan_Ehole";
    public Config Config_l;
    public ThreadPoolManager threadPoolManager;  // 使用新的线程池管理器
    public utils.PathQueueManager pathQueueManager;  // 路径队列管理器
    public boolean Carry_head = false;
    public boolean on_off = false;
    public boolean Bypass = false;
    public boolean DomainScan = false;
    public boolean BypassFirst = false;
    public boolean BypassEnd = false;
    public FingerprintScanner fingerprintScanner;  // 指纹扫描器
    public FingerprintConfig fingerprintConfig;    // 指纹识别配置界面
    public utils.ResultFilter resultFilter;        // 结果过滤器
    public ApiKitPassiveScanner apiKitPassiveScanner;  // APIKit被动扫描器
    public static String Download_Yaml_protocol = "https";

    public static String VERSION = "2.4";
    public static String Download_Yaml_host = "raw.githubusercontent.com";
    public static int Download_Yaml_port = 443;
    public static String Download_Yaml_file = "/XF-FS/RVScan/refs/heads/main/Config_yaml.yaml";
    public Map<String, View> views;
    public JTextField Host_txtfield;




    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 确保配置文件存在，如果不存在则创建默认配置
        if (!new File(Yaml_Path).exists()) {
            try {
                // 创建目录（如果不存在）
                File yamlFile = new File(Yaml_Path);
                File parentDir = yamlFile.getParentFile();
                if (parentDir != null && !parentDir.exists()) {
                    parentDir.mkdirs();
                }
                
                // 使用默认配置创建文件
                Map<String, Object> defaultConfig = new HashMap<>();
                Collection<Object> list1 = new ArrayList<>();
                defaultConfig.put("Load_List", list1);
                YamlUtil.writeYaml(defaultConfig, Yaml_Path);
            } catch (Exception e) {
                System.err.println("创建默认配置文件时发生错误: " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        this.call = callbacks;
        this.help = call.getHelpers();
        this.DomainName = new DomainNameRepeat();
        this.urlC = new UrlRepeat();
        
        // 初始化线程池管理器
        this.threadPoolManager = new ThreadPoolManager();
        
        // 初始化路径队列管理器
        this.pathQueueManager = new utils.PathQueueManager(this);
        
        // 初始化指纹识别模块
        this.fingerprintScanner = new FingerprintScanner(this);
        this.fingerprintConfig = new FingerprintConfig(this, fingerprintScanner);
        
        // 初始化结果过滤器
        this.resultFilter = new utils.ResultFilter(this);
        
        // 初始化配置界面（必须在指纹识别模块之后）
        this.Config_l = new Config(this);
        this.tags = new Tags(callbacks, Config_l);
        
        // 初始化APIKit被动扫描器
        this.apiKitPassiveScanner = new ApiKitPassiveScanner(callbacks);
        // 将APIKit面板关联到扫描器
        if (this.tags.apiKitPanel != null) {
            this.apiKitPassiveScanner.setApiKitPanel(this.tags.apiKitPanel);
            // 设置ConfigPanel到适配器
            APIKit.BurpExtenderAdapter.setConfigPanel(this.tags.apiKitPanel.getConfigPanel());
        }
        
        call.printOutput("@Info: Loading  RVScan success");
        call.printOutput("@Info: Fingerprint recognition enabled, supports EHole fingerprint library");
        call.printOutput("@Info : Enhance the bypass function by replacing the first/with a bypass statement, and adding a bypass statement after the path with a bypass statement");
        call.printOutput("@Version:  RVScan " + VERSION);
        call.printOutput("@From: Code by XFF");
        call.printOutput("@Github: https://github.com/XF-FS/RVScan/");
        call.printOutput("");
        call.setExtensionName(EXPAND_NAME);
        call.registerScannerCheck(this);
        call.registerContextMenuFactory(this);
    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        ArrayList<IScanIssue> IssueList = new ArrayList();
        
        // 获取基础信息（指纹识别和主扫描都需要）
        String re = Host_txtfield.getText().replace(".", "\\.").replace("*", ".*?");
        Pattern pattern = Pattern.compile(re);
        Matcher matcher = pattern.matcher(baseRequestResponse.getHttpService().getHost());
        
        if (matcher.find()) {
            IHttpService Http_Service = baseRequestResponse.getHttpService();
            String Root_Url = Http_Service.getProtocol() + "://" + Http_Service.getHost() + ":" + String.valueOf(Http_Service.getPort());
            
            // EHole指纹识别独立运行，不受主扫描开关影响
            if (fingerprintScanner != null && fingerprintScanner.isEnabled()) {
                String currentPath = this.help.analyzeRequest(baseRequestResponse).getUrl().getPath();
                performDomainFingerprintScan(baseRequestResponse, Root_Url, currentPath);
            }
            
            // APIKit API文档扫描，独立运行，不受主扫描开关影响
            if (apiKitPassiveScanner != null && tags != null && tags.apiKitPanel != null) {
                try {
                    List<IScanIssue> apiIssues = apiKitPassiveScanner.doPassiveScan(baseRequestResponse);
                    if (apiIssues != null && !apiIssues.isEmpty()) {
                        IssueList.addAll(apiIssues);
                    }
                } catch (Exception e) {
                    this.call.printError("[APIKit] Error during API scan: " + e.getMessage());
                }
            }
            
            // 主扫描功能（敏感目录扫描），受主扫描开关控制
            if (on_off) {
                // 检查当前请求路径是否应该被敏感信息扫描过滤
                String currentPath = this.help.analyzeRequest(baseRequestResponse).getUrl().getPath();
                if (shouldSkipSensitiveScan(currentPath)) {
                    this.call.printOutput("[Filter] Skip sensitive information scan: " + currentPath + " (static resource or favicon)");
                    return IssueList;
                }
                
                // 使用新的线程池管理器
                int threadCount = (Integer) Config_l.spinner1.getValue();
                threadPoolManager.createThreadPool(threadCount, threadCount * 2);
                
                try {
                    URL url = new URL(Root_Url + currentPath);
                    BurpAnalyzedRequest Root_Request = new BurpAnalyzedRequest(this.call, baseRequestResponse);
                    String Root_Method = this.help.analyzeRequest(baseRequestResponse.getRequest()).getMethod();
                    String New_Url = this.urlC.RemoveUrlParameterValue(url.toString());
                    if (this.urlC.check(Root_Method, New_Url)) {
                        return null;
                    }
                    
                    // 执行敏感目录扫描
                    new vulscan(this, Root_Request,null);
                    
                    this.urlC.addMethodAndUrl(Root_Method, New_Url);
                    try {
                        this.DomainName.add(Root_Url);
                        return IssueList;
                    } catch (Throwable th) {
                        return IssueList;
                    }
                } catch (MalformedURLException e3) {
                    throw new RuntimeException(e3);
                }
            }
        }
        
        return IssueList;
    }
    
    /**
     * 检查是否应该跳过敏感信息扫描（比isStaticResource更严格）
     */
    private boolean shouldSkipSensitiveScan(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        
        // 转换为小写进行比较
        String lowerPath = path.toLowerCase();
        
        // 明确排除 /favicon.ico
        if (lowerPath.equals("/favicon.ico")) {
            return true;
        }
        
        // 定义需要跳过敏感信息扫描的静态资源扩展名
        String[] staticExtensions = {
            ".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",  // 字体文件
            ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",  // 媒体文件
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",  // 文档文件
            ".zip", ".rar", ".7z", ".tar", ".gz",  // 压缩文件
            ".swf", ".fla",  // Flash文件
            ".map"  // source map文件
        };
        
        // 检查文件扩展名（敏感信息扫描中，所有静态资源都跳过，包括favicon）
        for (String ext : staticExtensions) {
            if (lowerPath.endsWith(ext)) {
                return true;
            }
        }
        
        // 检查常见静态资源路径模式
        String[] staticPathPatterns = {
            "/static/", "/assets/", "/public/", "/resources/", "/img/", "/images/", 
            "/css/", "/js/", "/fonts/", "/media/", "/uploads/", "/files/",
            "/themes/", "/template/", "/skin/", "/style/", "/libs/", "/lib/",
            "/node_modules/", "/bower_components/", "/vendor/"
        };
        
        for (String pattern : staticPathPatterns) {
            if (lowerPath.contains(pattern)) {
                return true;
            }
        }
        
        // 检查常见的静态文件名模式
        String[] staticFilePatterns = {
            "jquery", "bootstrap", "angular", "react", "vue", "lodash", 
            "moment", "chart", "d3.js", "three.js", "axios", "zepto"
        };
        
        for (String pattern : staticFilePatterns) {
            if (lowerPath.contains(pattern) && (lowerPath.endsWith(".js") || lowerPath.endsWith(".css"))) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 检查是否为根目录路径
     */
    private boolean isRootPath(String path) {
        if (path == null || path.equals("/") || path.equals("") || 
            path.equals("/index.html") || path.equals("/index.php") || 
            path.equals("/index.jsp") || path.equals("/default.html") ||
            path.equals("/index.htm") || path.equals("/default.htm")) {
            return true;
        }
        
        String[] rootFiles = {
            "/favicon.ico", "/robots.txt", "/sitemap.xml", 
            "/crossdomain.xml", "/apple-touch-icon.png"
        };
        
        for (String rootFile : rootFiles) {
            if (path.equals(rootFile)) {
                return true;
            }
        }
        
        return false;
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menu = new ArrayList<JMenuItem>();
        JMenuItem one_menu = new JMenuItem("Send To  RVScan");
        JMenuItem two_menu = new JMenuItem("Send To  RVScan and Head");
        JMenuItem force_scan_menu = new JMenuItem("Force Scan All Paths (No Deduplication)");
        
        one_menu.addActionListener(new Right_click_monitor(invocation, this));
        two_menu.addActionListener(new Right_click_monitor(invocation, this, true));
        force_scan_menu.addActionListener(new Force_Scan_Monitor(invocation, this));
        
        menu.add(one_menu);
        menu.add(two_menu);
        menu.add(force_scan_menu);

        return menu;
    }

    public void prompt(Component component,String message){
        if (component == null){
            component = this.tags.getUiComponent();
        }
        JOptionPane.showMessageDialog(component, message);
    }

    /**
     * 对域名进行指纹识别（对当前路径、根目录和配置列表中的路径进行识别）
     */
    private void performDomainFingerprintScan(IHttpRequestResponse originalRequest, String baseUrl, String currentPath) {
        try {
            // 检查当前路径是否为静态资源，如果是则跳过指纹识别
            if (isStaticResource(currentPath)) {
                // this.call.printOutput("[Debug] 当前路径 " + currentPath + " 是静态资源，跳过指纹识别");
                return;
            }
            
            IHttpService httpService = originalRequest.getHttpService();
            
            // 1. 首先对当前访问路径进行指纹识别
            performSinglePathFingerprint(httpService, baseUrl, currentPath, "当前访问路径");
            
            // 2. 从配置文件读取指纹识别路径列表
            List<String> fingerprintPaths = getFingerprintPathsFromConfig();
            
            // 3. 对配置列表中的每个路径进行指纹识别
            for (String path : fingerprintPaths) {
                // 跳过已经识别过的当前路径
                if (path.equals(currentPath)) {
                    continue;
                }
                
                // 跳过静态资源路径
                if (isStaticResource(path)) {
                    // this.call.printOutput("[Debug] 配置路径 " + path + " 是静态资源，跳过指纹识别");
                    continue;
                }
                
                performSinglePathFingerprint(httpService, baseUrl, path, "配置路径");
            }
            
        } catch (Exception e) {
            this.call.printError("[Fingerprint] Error occurred during fingerprint recognition: " + e.getMessage());
        }
    }
    
    /**
     * 对单个路径进行指纹识别
     */
    private void performSinglePathFingerprint(IHttpService httpService, String baseUrl, String path, String pathType) {
        try {
            // 构建完整的URL作为缓存键
            String fullUrl = baseUrl + path;
            
            // 检查是否已经对该URL进行过指纹识别
            if (fingerprintScanner.isHostAlreadyScanned(fullUrl)) {
                // this.call.printOutput("[Debug] " + pathType + " " + fullUrl + " 已进行过指纹识别，跳过");
                return;
            }
            
            // this.call.printOutput("[Debug] 开始对" + pathType + " " + path + " 进行指纹识别");
            
            try {
                URL url = new URL(fullUrl);
                byte[] request = this.help.buildHttpRequest(url);
                
                // 发送请求
                IHttpRequestResponse response = this.call.makeHttpRequest(httpService, request);
                
                if (response.getResponse() != null) {
                    // 检查是否有重定向
                    IResponseInfo responseInfo = this.help.analyzeResponse(response.getResponse());
                    int statusCode = responseInfo.getStatusCode();
                    
                    // this.call.printOutput("[Debug] " + pathType + " " + path + " 返回状态码: " + statusCode);
                    
                    if (statusCode >= 300 && statusCode < 400) {
                        // 处理重定向
                        String redirectLocation = getRedirectLocation(responseInfo);
                        if (redirectLocation != null && !redirectLocation.isEmpty()) {
                            // this.call.printOutput("[Debug] 检测到重定向到: " + redirectLocation);
                            response = handleRedirect(httpService, redirectLocation);
                        }
                    }
                    
                    // 对响应进行指纹识别
                    if (response != null && response.getResponse() != null) {
                        fingerprintScanner.performFingerprintScan(response);
                        // this.call.printOutput("[Debug] 已完成" + pathType + " " + path + " 指纹识别");
                    }
                } else {
                    this.call.printError("[Fingerprint] " + pathType + " " + path + " request failed, no response");
                }
                
            } catch (Exception e) {
                this.call.printError("[Fingerprint] Failed to initiate " + pathType + " " + path + " request: " + e.getMessage());
            }
            
        } catch (Exception e) {
            this.call.printError("[Fingerprint] Error occurred during " + pathType + " " + path + " fingerprint recognition: " + e.getMessage());
        }
    }
    
    /**
     * 从配置文件读取指纹识别路径列表
     */
    private List<String> getFingerprintPathsFromConfig() {
        try {
            Map<String, Object> yamlMap = yaml.YamlUtil.readYaml(Config_l.yaml_path);
            List<String> fingerprintPaths = (List<String>) yamlMap.get("Fingerprint_Paths");
            
            if (fingerprintPaths != null && !fingerprintPaths.isEmpty()) {
                // this.call.printOutput("[Debug] 从配置文件加载了 " + fingerprintPaths.size() + " 个指纹识别路径: " + fingerprintPaths);
                return fingerprintPaths;
            } else {
                // this.call.printOutput("[Debug] 配置文件中未找到 Fingerprint_Paths，使用默认路径");
                // 返回默认的指纹识别路径
                return java.util.Arrays.asList("/");
            }
        } catch (Exception e) {
            this.call.printError("[Fingerprint] Failed to read fingerprint recognition path configuration: " + e.getMessage());
            // 返回默认的指纹识别路径
            return java.util.Arrays.asList("/");
        }
    }
    
    /**
     * 检查是否为静态资源
     */
    private boolean isStaticResource(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        
        // 转换为小写进行比较
        String lowerPath = path.toLowerCase();
        
        // 定义静态资源扩展名
        String[] staticExtensions = {
            ".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",  // 字体文件
            ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",  // 媒体文件
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",  // 文档文件
            ".zip", ".rar", ".7z", ".tar", ".gz",  // 压缩文件
            ".xml", ".json", ".txt", ".log",  // 数据文件（可选择性过滤）
            ".swf", ".fla"  // Flash文件
        };
        
        // 检查文件扩展名（favicon文件需要特殊处理，不过滤）
        for (String ext : staticExtensions) {
            if (lowerPath.endsWith(ext)) {
                // favicon文件需要进行指纹识别，不过滤
                if (lowerPath.contains("favicon")) {
                    return false;
                }
                return true;
            }
        }
        
        // 检查常见静态资源路径模式
        String[] staticPathPatterns = {
            "/static/", "/assets/", "/public/", "/resources/", "/img/", "/images/", 
            "/css/", "/js/", "/fonts/", "/media/", "/uploads/", "/files/",
            "/themes/", "/template/", "/skin/", "/style/"
        };
        
        for (String pattern : staticPathPatterns) {
            if (lowerPath.contains(pattern)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 获取重定向位置
     */
    private String getRedirectLocation(IResponseInfo responseInfo) {
        List<String> headers = responseInfo.getHeaders();
        for (String header : headers) {
            if (header.toLowerCase().startsWith("location:")) {
                return header.substring(9).trim();
            }
        }
        return null;
    }
    
    /**
     * 处理重定向
     */
    private IHttpRequestResponse handleRedirect(IHttpService httpService, String location) {
        try {
            // 如果是相对路径，补全为绝对路径
            if (location.startsWith("/")) {
                location = httpService.getProtocol() + "://" + httpService.getHost() + ":" + httpService.getPort() + location;
            }
            
            URL redirectUrl = new URL(location);
            byte[] redirectRequest = this.help.buildHttpRequest(redirectUrl);
            
            this.call.printOutput("[Debug] Following redirect to: " + location);
            IHttpRequestResponse redirectResponse = this.call.makeHttpRequest(httpService, redirectRequest);
            
            // 检查是否还有进一步的重定向（最多跟随3次）
            if (redirectResponse.getResponse() != null) {
                IResponseInfo responseInfo = this.help.analyzeResponse(redirectResponse.getResponse());
                int statusCode = responseInfo.getStatusCode();
                
                if (statusCode >= 300 && statusCode < 400) {
                    String nextLocation = getRedirectLocation(responseInfo);
                    if (nextLocation != null && !nextLocation.equals(location)) {
                        this.call.printOutput("[Debug] Detected further redirect to: " + nextLocation);
                        // 只跟随一次重定向，避免无限循环
                        if (nextLocation.startsWith("/")) {
                            nextLocation = httpService.getProtocol() + "://" + httpService.getHost() + ":" + httpService.getPort() + nextLocation;
                        }
                        URL finalUrl = new URL(nextLocation);
                        byte[] finalRequest = this.help.buildHttpRequest(finalUrl);
                        return this.call.makeHttpRequest(httpService, finalRequest);
                    }
                }
            }
            
            return redirectResponse;
            
        } catch (Exception e) {
            this.call.printError("[Fingerprint] Failed to handle redirect: " + e.getMessage());
            return null;
        }
    }
}


class Right_click_monitor implements ActionListener {
    private IContextMenuInvocation invocation;
    private BurpExtender burp;

    private Boolean head;

    public Right_click_monitor(IContextMenuInvocation invocation, BurpExtender burp) {
        this.invocation = invocation;
        this.burp = burp;
        this.head = false;
    }

    public Right_click_monitor(IContextMenuInvocation invocation, BurpExtender burp, Boolean head) {
        this.invocation = invocation;
        this.burp = burp;
        this.head = head;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        burp.threadPoolManager.createThreadPool((Integer) burp.Config_l.spinner1.getValue(), (Integer) burp.Config_l.spinner1.getValue() * 2);
        IHttpRequestResponse[] RequestResponses = invocation.getSelectedMessages();
        if (head) {
            JTextArea jTextArea = new JTextArea(1, 1);
            jTextArea.setLineWrap(false);
            List<String> headers = this.getHeaders(RequestResponses[0]);
            headers.remove(0);
            String headerText = "";
            for (String head : headers){
                headerText += head + "\n";
            }
            jTextArea.setText(headerText);

            JSplitPane jSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            jSplitPane.setResizeWeight(0.95);
            jSplitPane.add(new JScrollPane(jTextArea));


            JSplitPane jSplitPane2 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            jSplitPane2.setResizeWeight(0.5);
            JButton ok = new JButton("OK");
            JButton cancel = new JButton("Cancel");

            jSplitPane2.add(ok);
            jSplitPane2.add(cancel);

            jSplitPane.add(jSplitPane2);

//            SwingUtilities.invokeLater(new Runnable() {
//                @Override
//                public void run() {
//
//                }
//            });
            JFrame frame = new JFrame("Custom Request Header");
            frame.add(jSplitPane);
            frame.setSize(600, 400);
            frame.setLocationRelativeTo(null); // 让窗口在屏幕中央显示
            frame.setVisible(true);

            cancel.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    frame.dispose();
                }
            });
            ok.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    List<String> headersText = parseHead(jTextArea.getText());
                    if (headersText == null){
                        burp.prompt(frame,"Wrong header!");
                        return;
                    }
                    frame.dispose();
                    for (IHttpRequestResponse i : RequestResponses) {
                        try {
                            IHttpService Http_Service = i.getHttpService();
                            IRequestInfo RequestInfo = burp.help.analyzeRequest(Http_Service, i.getRequest());
                            String host_url = RequestInfo.getUrl().getProtocol() + "://" + RequestInfo.getUrl().getHost();
                            IHttpRequestResponse[] aaaa = burp.call.getSiteMap(host_url);
                            for (IHttpRequestResponse oo : aaaa) {
//                                String Root_Url = Http_Service.getProtocol() + "://" + Http_Service.getHost() + ":" + String.valueOf(Http_Service.getPort());
//                                URL url = new URL(Root_Url + burp.help.analyzeRequest(xxx).getUrl().getPath());
                                byte[] xxx = replaceHeader(oo, headersText);
                                BurpAnalyzedRequest Root_Request = new BurpAnalyzedRequest(burp.call, oo);
                                start_send send = new start_send(burp, Root_Request,xxx);
                                send.start();
                            }

                        } catch (Exception exception) {
                            exception.printStackTrace();
                        }

                    }
                }
            });

        }else {
            for (IHttpRequestResponse i : RequestResponses) {
                try {
                    IHttpService Http_Service = i.getHttpService();
                    IRequestInfo RequestInfo = burp.help.analyzeRequest(Http_Service, i.getRequest());
                    String host_url = RequestInfo.getUrl().getProtocol() + "://" + RequestInfo.getUrl().getHost();
                    IHttpRequestResponse[] aaaa = burp.call.getSiteMap(host_url);
                    for (IHttpRequestResponse xxx : aaaa) {
//                        String Root_Url = Http_Service.getProtocol() + "://" + Http_Service.getHost() + ":" + String.valueOf(Http_Service.getPort());
//                        URL url = new URL(Root_Url + burp.help.analyzeRequest(xxx).getUrl().getPath());
                        BurpAnalyzedRequest Root_Request = new BurpAnalyzedRequest(burp.call, xxx);
                        start_send send = new start_send(burp, Root_Request,null);
                        send.start();
                    }

                } catch (Exception exception) {
                    exception.printStackTrace();
                }

            }
        }


    }

    public byte[] replaceHeader(IHttpRequestResponse i, List<String> header) {
        List<String> headers = new ArrayList<>(header);

        IRequestInfo iRequestInfo = burp.help.analyzeRequest(i);
        iRequestInfo.getHeaders();
        headers.add(0, burp.help.analyzeRequest(i).getHeaders().get(0));

        return burp.help.buildHttpMessage(headers, new byte[]{});
    }

    public List<String> getHeaders(IHttpRequestResponse iHttpRequestResponse) {
        return this.burp.help.analyzeRequest(iHttpRequestResponse).getHeaders();
    }

    public static List<String> parseHead(String headerText) {
        if (headerText.equals("")) {
            return null;
        }
        List<String> rows = new ArrayList<>();
        for (String row : headerText.split("\n")) {
            if (!row.equals("")) {
                rows.add(row);
            }
        }
        if (rows.size() == 0) {
            return null;
        }
        return rows;
    }

}



class start_send extends Thread {
    private BurpExtender burp;
    private BurpAnalyzedRequest Root_Request;
    private byte[] request;

    public start_send(BurpExtender burp, BurpAnalyzedRequest Root_Request,byte[] request) {
        this.burp = burp;
        this.Root_Request = Root_Request;
        this.request = request;
    }

    public void run() {
        new vulscan(this.burp, this.Root_Request,this.request);
    }

}

