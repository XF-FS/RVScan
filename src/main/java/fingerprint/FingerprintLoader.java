package fingerprint;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import org.yaml.snakeyaml.Yaml;
import burp.BurpExtender;

import java.io.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * 指纹库加载器
 * 支持从JSON和YAML文件加载EHole格式的指纹
 */
public class FingerprintLoader {
    private BurpExtender burp;
    // EHole官方指纹库URL（作为备用）
    private static final String DEFAULT_FINGERPRINT_URL = "https://raw.githubusercontent.com/XF-FS/RVScan/refs/heads/main/finger.json";
    // 备用指纹库URL（国内访问更快）
    private static final String BACKUP_FINGERPRINT_URL = "https://gitee.com/EdgeSecurityTeam/EHole/raw/main/finger.json";
    // 本地指纹库路径
    private static final String DEFAULT_LOCAL_FINGERPRINT_PATH = "finger.json";
    // 本地缓存指纹库路径
    private static final String LOCAL_CACHE_PATH = System.getProperty("user.dir") + "/finger.json";
    
    private ObjectMapper objectMapper;
    private Yaml yaml;
    
    public FingerprintLoader(BurpExtender burp) {
        this.burp = burp;
        this.objectMapper = new ObjectMapper();
        this.yaml = new Yaml();
    }
    
    /**
     * 加载指纹库
     * 优先从本地finger.json加载
     */
    public List<FingerPrint> loadFingerprints() throws IOException {
        List<FingerPrint> fingerprints = null;
        
        // 1. 尝试从项目根目录的finger.json加载
        try {
            File defaultFile = new File(DEFAULT_LOCAL_FINGERPRINT_PATH);
            if (defaultFile.exists()) {
                fingerprints = loadFromJsonFile(defaultFile.getAbsolutePath());
                if (fingerprints != null && !fingerprints.isEmpty()) {
                    burp.call.printOutput("[Fingerprint] Loaded " + fingerprints.size() + " fingerprints from " + DEFAULT_LOCAL_FINGERPRINT_PATH);
                    return validateAndFilterFingerprints(fingerprints);
                }
            }
        } catch (Exception e) {
            burp.call.printError("[Fingerprint] Failed to load fingerprints from " + DEFAULT_LOCAL_FINGERPRINT_PATH + ": " + e.getMessage());
        }
        
        // 2. 加载内置的默认指纹
        fingerprints = loadDefaultFingerprints();
        if (fingerprints != null && !fingerprints.isEmpty()) {
            burp.call.printOutput("[Fingerprint] Using built-in fingerprint library with " + fingerprints.size() + " fingerprints");
            return fingerprints;
        }
        
        // 3. 最后尝试从在线源加载
        try {
            fingerprints = loadFromUrl(null);
            if (fingerprints != null && !fingerprints.isEmpty()) {
                burp.call.printOutput("[Fingerprint] Loaded " + fingerprints.size() + " fingerprints from online source");
                return fingerprints;
            }
        } catch (Exception e) {
            burp.call.printError("[Fingerprint] Failed to load fingerprints online: " + e.getMessage());
        }
        
        throw new IOException("无法从任何来源加载指纹库");
    }
    
    /**
     * 从本地JSON文件加载指纹
     */
    public List<FingerPrint> loadFromJsonFile(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new FileNotFoundException("指纹文件不存在: " + filePath);
        }
        
        // 读取EHole格式的指纹文件
        JsonNode rootNode = objectMapper.readTree(file);
        JsonNode fingerprintArray = rootNode.get("fingerprint");
        List<FingerPrint> fingerprints;
        
        if (fingerprintArray != null && fingerprintArray.isArray()) {
            fingerprints = objectMapper.convertValue(fingerprintArray, new TypeReference<List<FingerPrint>>() {});
        } else {
            // 尝试直接读取为指纹数组
            fingerprints = objectMapper.readValue(file, new TypeReference<List<FingerPrint>>() {});
        }
        
        // 处理没有status字段的指纹，设置默认值（简化日志输出）
        int noStatusCount = 0;
        for (FingerPrint fingerprint : fingerprints) {
            if (fingerprint.getStatus() == 0) {
                noStatusCount++;
            }
        }
        if (noStatusCount > 0) {
                            burp.call.printOutput("[Fingerprint] " + noStatusCount + " fingerprints have no specified status code, will accept any status code");
        }
        
        return fingerprints;
    }
    
    /**
     * 从本地YAML文件加载指纹
     */
    public List<FingerPrint> loadFromYamlFile(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new FileNotFoundException("指纹文件不存在: " + filePath);
        }
        
        try (FileInputStream fis = new FileInputStream(file)) {
            List<Map<String, Object>> yamlData = yaml.load(fis);
            return convertMapListToFingerprints(yamlData);
        }
    }
    
    /**
     * 从在线URL加载指纹（EHole官方指纹库）
     */
    public List<FingerPrint> loadFromUrl(String url) throws IOException {
        if (url == null || url.isEmpty()) {
            url = DEFAULT_FINGERPRINT_URL;
        }
        
        // 尝试主URL，失败则尝试备用URL
        IOException lastException = null;
        String[] urls = {url, BACKUP_FINGERPRINT_URL};
        
        for (String tryUrl : urls) {
            try {
                URL fingerprintUrl = new URL(tryUrl);
                try (InputStream inputStream = fingerprintUrl.openStream()) {
                    List<FingerPrint> fingerprints = objectMapper.readValue(inputStream, new TypeReference<List<FingerPrint>>() {});
                    // 验证加载的指纹格式
                    List<FingerPrint> validFingerprints = validateAndFilterFingerprints(fingerprints);
                    
                    // 保存到本地缓存
                    try {
                        saveToJsonFile(validFingerprints, LOCAL_CACHE_PATH);
                    } catch (Exception e) {
                        // 忽略保存失败的异常
                    }
                    
                    return validFingerprints;
                }
            } catch (IOException e) {
                lastException = e;
                continue; // 尝试下一个URL
            }
        }
        
        // 如果在线加载失败，尝试从本地缓存加载
        try {
            File localFile = new File(LOCAL_CACHE_PATH);
            if (localFile.exists()) {
                return loadFromJsonFile(LOCAL_CACHE_PATH);
            }
        } catch (Exception e) {
            // 忽略本地加载失败的异常
        }
        
        throw new IOException("无法从任何URL或本地缓存加载指纹库", lastException);
    }
    
    /**
     * 验证并过滤指纹
     */
    private List<FingerPrint> validateAndFilterFingerprints(List<FingerPrint> fingerprints) {
        List<FingerPrint> validFingerprints = new ArrayList<>();
        
        for (FingerPrint fingerprint : fingerprints) {
            if (validateFingerprint(fingerprint)) {
                validFingerprints.add(fingerprint);
            }
        }
        
        return validFingerprints;
    }
    
    /**
     * 从字符串加载指纹（JSON格式）
     */
    public List<FingerPrint> loadFromJsonString(String jsonString) throws IOException {
        return objectMapper.readValue(jsonString, new TypeReference<List<FingerPrint>>() {});
    }
    
    /**
     * 加载默认指纹库（内置常用指纹）
     */
    public List<FingerPrint> loadDefaultFingerprints() {
        List<FingerPrint> fingerprints = new ArrayList<>();
        
        // 添加一些常用的指纹识别规则
        fingerprints.add(new FingerPrint("Apache", "GET", "header", 
            Arrays.asList("server: apache"), 200));
        
        fingerprints.add(new FingerPrint("Nginx", "GET", "header", 
            Arrays.asList("server: nginx"), 200));
        
        fingerprints.add(new FingerPrint("IIS", "GET", "header", 
            Arrays.asList("server: microsoft-iis"), 200));
        
        fingerprints.add(new FingerPrint("Tomcat", "GET", "body", 
            Arrays.asList("apache tomcat"), 200));
        
        fingerprints.add(new FingerPrint("WordPress", "GET", "body", 
            Arrays.asList("wp-content", "wordpress"), 200));
        
        fingerprints.add(new FingerPrint("Drupal", "GET", "body", 
            Arrays.asList("drupal", "sites/default/files"), 200));
        
        fingerprints.add(new FingerPrint("Joomla", "GET", "body", 
            Arrays.asList("joomla", "administrator/index.php"), 200));
        
        fingerprints.add(new FingerPrint("ThinkPHP", "GET", "body", 
            Arrays.asList("thinkphp", "think\\app"), 200));
        
        fingerprints.add(new FingerPrint("Laravel", "GET", "body", 
            Arrays.asList("laravel", "laravel_session"), 200));
        
        fingerprints.add(new FingerPrint("Spring Boot", "GET", "header", 
            Arrays.asList("x-application-context"), 200));
        
        fingerprints.add(new FingerPrint("Django", "GET", "header", 
            Arrays.asList("csrftoken", "django"), 200));
        
        fingerprints.add(new FingerPrint("Flask", "GET", "header", 
            Arrays.asList("werkzeug"), 200));
        
        fingerprints.add(new FingerPrint("Struts2", "GET", "body", 
            Arrays.asList("struts", "action"), 200));
        
        fingerprints.add(new FingerPrint("Shiro", "GET", "header", 
            Arrays.asList("rememberme=deleteme"), 200));
        
        fingerprints.add(new FingerPrint("Discuz", "GET", "body", 
            Arrays.asList("discuz", "powered by discuz"), 200));
        
        return fingerprints;
    }
    
    /**
     * 将Map列表转换为FingerPrint对象列表
     */
    private List<FingerPrint> convertMapListToFingerprints(List<Map<String, Object>> mapList) {
        List<FingerPrint> fingerprints = new ArrayList<>();
        
        for (Map<String, Object> map : mapList) {
            FingerPrint fingerprint = new FingerPrint();
            fingerprint.setCms((String) map.get("cms"));
            fingerprint.setMethod((String) map.get("method"));
            fingerprint.setLocation((String) map.get("location"));
            fingerprint.setStatus(((Number) map.getOrDefault("status", 200)).intValue());
            
            // 处理关键词列表
            Object keywordObj = map.get("keyword");
            if (keywordObj instanceof List) {
                fingerprint.setKeyword((List<String>) keywordObj);
            } else if (keywordObj instanceof String) {
                fingerprint.setKeyword(Arrays.asList((String) keywordObj));
            }
            
            fingerprints.add(fingerprint);
        }
        
        return fingerprints;
    }
    
    /**
     * 保存指纹到JSON文件
     */
    public void saveToJsonFile(List<FingerPrint> fingerprints, String filePath) throws IOException {
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(new File(filePath), fingerprints);
    }
    
    /**
     * 验证指纹格式
     */
    public boolean validateFingerprint(FingerPrint fingerprint) {
        return fingerprint.getCms() != null && !fingerprint.getCms().isEmpty() &&
               fingerprint.getMethod() != null && !fingerprint.getMethod().isEmpty() &&
               fingerprint.getLocation() != null && !fingerprint.getLocation().isEmpty() &&
               fingerprint.getKeyword() != null && !fingerprint.getKeyword().isEmpty();
    }
}